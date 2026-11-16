"""Bounded, credential-free transport for fixed Explorer public API paths."""

import asyncio
import json
import re
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Literal, cast
from urllib.error import HTTPError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from ..contracts import HederaNetwork

MAX_EXPLORER_RESPONSE_BYTES = 512 * 1024
DEFAULT_EXPLORER_TIMEOUT_MS = 15_000

_PATH_RE = re.compile(r"^/v1/[a-zA-Z0-9/._:%-]+$", re.ASCII)
_RESULT_ID_RE = re.compile(
    r"^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$",
    re.IGNORECASE | re.ASCII,
)

type ExplorerPublicHttpStatusV1 = Literal["ok", "not_found", "unavailable", "invalid"]
type ExplorerHttpMethodV1 = Literal["GET", "POST"]


@dataclass(frozen=True, slots=True)
class ExplorerFetchResponseV1:
    status: int
    headers: Mapping[str, str]
    body: bytes | None


type ExplorerFetchImplV1 = Callable[
    [str, ExplorerHttpMethodV1, Mapping[str, str], bytes | None, int, int],
    Awaitable[ExplorerFetchResponseV1],
]


@dataclass(frozen=True, slots=True)
class ExplorerPublicTransportV1:
    base_url: str
    fetch_impl: ExplorerFetchImplV1 | None = None
    timeout_ms: int = DEFAULT_EXPLORER_TIMEOUT_MS
    max_response_bytes: int = MAX_EXPLORER_RESPONSE_BYTES


@dataclass(frozen=True, slots=True)
class ExplorerPublicHttpResultV1:
    status: ExplorerPublicHttpStatusV1
    reason_code: str | None
    body: dict[str, object] | None


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(
        self,
        req: Request,
        fp: object,
        code: int,
        msg: str,
        headers: object,
        newurl: str,
    ) -> None:
        return None


def _safe_bound(value: object, *, field: str, minimum: int, maximum: int) -> int:
    if (
        isinstance(value, bool) or not isinstance(value, int) or value < minimum
        or value > maximum
    ):
        raise TypeError(f"Invalid Explorer {field}")
    return value


def _origin(value: object) -> str:
    if not isinstance(value, str):
        raise TypeError("Explorer base_url must be an absolute URL")

    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise TypeError("Explorer base_url must be an absolute URL") from exc

    hostname = parsed.hostname

    if (
        parsed.scheme not in {"http", "https"} or hostname is None
        or parsed.username is not None or parsed.password is not None or parsed.query
        or parsed.fragment or parsed.path not in {"", "/", "/v1", "/v1/"}
    ):
        raise TypeError(
            "Explorer base_url must identify a fixed HTTPS origin "
            "(HTTP loopback permitted)"
        )

    local = hostname in {"localhost", "127.0.0.1", "::1"}

    if parsed.scheme != "https" and not (parsed.scheme == "http" and local):
        raise TypeError(
            "Explorer base_url must identify a fixed HTTPS origin "
            "(HTTP loopback permitted)"
        )

    rendered_host = f"[{hostname}]" if ":" in hostname else hostname
    authority = f"{rendered_host}:{port}" if port is not None else rendered_host

    return f"{parsed.scheme}://{authority}"


def _headers(value: Mapping[str, str]) -> dict[str, str]:
    return {str(key).lower(): str(item) for key, item in value.items()}


def _read_bounded(response: object, maximum: int) -> bytes:
    chunks: list[bytes] = []
    total = 0

    while total <= maximum:
        remaining = maximum + 1 - total
        size = min(64 * 1024, remaining)

        chunk = response.read(size)  # type: ignore[attr-defined]

        if not chunk:
            break
        if not isinstance(chunk, bytes):
            raise OSError("Invalid HTTP response body")

        chunks.append(chunk)
        total += len(chunk)

    return b"".join(chunks)


def _default_fetch_sync(
    url: str,
    method: ExplorerHttpMethodV1,
    headers: Mapping[str, str],
    body: bytes | None,
    timeout_ms: int,
    max_response_bytes: int,
) -> ExplorerFetchResponseV1:
    request_headers = dict(headers)
    request_headers["User-Agent"] = "vera-anchor-verifier-py"

    request = Request(
        url,
        data=body,
        headers=request_headers,
        method=method,
    )
    opener = build_opener(_NoRedirect())

    try:
        with opener.open(
            request,
            timeout=timeout_ms / 1000,
        ) as response:
            status = int(response.getcode())
            response_headers = {
                key.lower(): value
                for key, value in response.headers.items()
            }

            declared = response_headers.get("content-length")

            if declared is not None:
                try:
                    if int(declared) > max_response_bytes:
                        return ExplorerFetchResponseV1(
                            status=status,
                            headers=response_headers,
                            body=b"x" * (max_response_bytes + 1),
                        )
                except ValueError:
                    pass

            response_body = _read_bounded(
                response,
                max_response_bytes,
            )

            return ExplorerFetchResponseV1(
                status=status,
                headers=response_headers,
                body=response_body,
            )

    except HTTPError as exc:
        return ExplorerFetchResponseV1(
            status=exc.code,
            headers={
                key.lower(): value
                for key, value in exc.headers.items()
            },
            body=b"",
        )


async def _default_fetch(
    url: str,
    method: ExplorerHttpMethodV1,
    headers: Mapping[str, str],
    body: bytes | None,
    timeout_ms: int,
    max_response_bytes: int,
) -> ExplorerFetchResponseV1:
    return await asyncio.to_thread(
        _default_fetch_sync,
        url,
        method,
        headers,
        body,
        timeout_ms,
        max_response_bytes,
    )


def _invalid_json_constant(value: str) -> None:
    raise ValueError(f"Invalid JSON constant: {value}")


async def read_explorer_public_v1(
    config: ExplorerPublicTransportV1,
    path: str,
    network: HederaNetwork,
    post_body: Mapping[str, object] | None = None,
    query: Mapping[str, str | None] | None = None,
) -> ExplorerPublicHttpResultV1:
    """Read only a code-defined Explorer public API path."""
    base = _origin(config.base_url)

    if (
        not isinstance(path, str) or _PATH_RE.fullmatch(path) is None or ".." in path
        or network not in ("mainnet", "testnet")
    ):
        raise TypeError("Invalid fixed Explorer API path or network")

    timeout = _safe_bound(
        config.timeout_ms,
        field="timeout bound",
        minimum=100,
        maximum=60_000,
    )
    budget = _safe_bound(
        config.max_response_bytes,
        field="response bound",
        minimum=1024,
        maximum=MAX_EXPLORER_RESPONSE_BYTES,
    )

    if query is not None and any(key != "resultId" for key in query):
        raise TypeError("Invalid Explorer query")

    if query is not None and post_body is not None:
        raise TypeError("Explorer GET query cannot accompany POST body")

    parameters: list[tuple[str, str]] = []

    if query is not None:
        result_id = query.get("resultId")

        if result_id is not None:
            if _RESULT_ID_RE.fullmatch(result_id) is None:
                raise TypeError("Invalid Explorer resultId query")

            parameters.append(("resultId", result_id.lower()))

    method: ExplorerHttpMethodV1
    request_body: bytes | None

    if post_body is None:
        method = "GET"
        request_body = None
        parameters.append(("network", network))
    else:
        method = "POST"

        if any(not isinstance(key, str) for key in post_body):
            raise TypeError("Invalid Explorer POST body")

        try:
            request_body = json.dumps(
                dict(post_body),
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
            ).encode()
        except (TypeError, ValueError) as exc:
            raise TypeError("Invalid Explorer POST body") from exc

    endpoint = f"{base}{path}"

    if parameters:
        endpoint = f"{endpoint}?{urlencode(parameters)}"

    headers = {"Accept": "application/json"}

    if request_body is not None:
        headers["Content-Type"] = "application/json"

    fetch = config.fetch_impl or _default_fetch

    try:
        response = await fetch(
            endpoint,
            method,
            headers,
            request_body,
            timeout,
            budget,
        )
    except Exception:
        return ExplorerPublicHttpResultV1(
            status="unavailable",
            reason_code="EXPLORER_REQUEST_UNAVAILABLE",
            body=None,
        )

    if response.status == 404:
        return ExplorerPublicHttpResultV1(
            status="not_found",
            reason_code="EXPLORER_NOT_FOUND",
            body=None,
        )

    if not 200 <= response.status < 300:
        return ExplorerPublicHttpResultV1(
            status="unavailable",
            reason_code="EXPLORER_HTTP_UNAVAILABLE",
            body=None,
        )

    response_headers = _headers(response.headers)

    declared_network = response_headers.get("x-hedera-network")

    if declared_network is not None and declared_network != network:
        return ExplorerPublicHttpResultV1(
            status="invalid",
            reason_code="EXPLORER_NETWORK_MISMATCH",
            body=None,
        )

    declared_size = response_headers.get("content-length")

    if declared_size is not None:
        try:
            if int(declared_size) > budget:
                return ExplorerPublicHttpResultV1(
                    status="invalid",
                    reason_code="EXPLORER_RESPONSE_TOO_LARGE",
                    body=None,
                )
        except ValueError:
            pass

    if response.body is None:
        return ExplorerPublicHttpResultV1(
            status="invalid",
            reason_code="EXPLORER_EMPTY_RESPONSE",
            body=None,
        )

    if len(response.body) > budget:
        return ExplorerPublicHttpResultV1(
            status="invalid",
            reason_code="EXPLORER_RESPONSE_TOO_LARGE",
            body=None,
        )

    try:
        text = response.body.decode("utf-8", errors="strict")
        parsed = json.loads(text, parse_constant=_invalid_json_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        return ExplorerPublicHttpResultV1(
            status="invalid",
            reason_code="EXPLORER_RESPONSE_INVALID",
            body=None,
        )

    if type(parsed) is not dict:
        return ExplorerPublicHttpResultV1(
            status="invalid",
            reason_code="EXPLORER_RESPONSE_INVALID",
            body=None,
        )

    return ExplorerPublicHttpResultV1(
        status="ok",
        reason_code=None,
        body=cast(dict[str, object], parsed),
    )