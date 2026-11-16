"""Independent Hedera Mirror HCS-1 resolution."""

import asyncio
import base64
import binascii
import json
import math
import re
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal, cast
from urllib.parse import parse_qsl, urljoin, urlsplit

from ..contracts import HederaNetwork
from ..standards.hcs.hcs1_v1 import (
    MAX_HCS1_V1_CHUNKS,
    Hcs1V1ContentInput,
    Hcs1V1ContentOptions,
    Hcs1V1ContentResult,
    parse_hcs1_reference_v1,
    verify_hcs1_content_v1,
)
from .hedera_mirror_v1 import HederaMirrorV1Config, _default_fetch

_DEFAULT_BASE: dict[HederaNetwork, str] = {
    "mainnet": "https://mainnet-public.mirrornode.hedera.com/api/v1",
    "testnet": "https://testnet.mirrornode.hedera.com/api/v1",
}
_MAX_RESPONSE_BYTES = 4 * 1024 * 1024
_MAX_PAGES = math.ceil(MAX_HCS1_V1_CHUNKS / 100) + 1
_MAX_SAFE_INTEGER = (1 << 53) - 1

_BASE64_RE = re.compile(
    r"^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$",
    re.ASCII,
)
_MEMO_RE = re.compile(r"^[0-9a-f]{64}:zstd:base64$", re.ASCII)
_ALLOWED_PAGE_KEYS = frozenset({"limit", "order", "timestamp", "sequencenumber"})

type Hcs1MirrorStatusV1 = Literal[
    "resolved",
    "conflict",
    "invalid",
    "unavailable",
    "unsupported",
]


@dataclass(frozen=True, slots=True)
class Hcs1MirrorV1Config(HederaMirrorV1Config):
    total_timeout_ms: int = 30_000


@dataclass(frozen=True, slots=True)
class Hcs1MirrorV1Request:
    reference: str
    network: HederaNetwork
    expected_sha256: str | None = None


@dataclass(frozen=True, slots=True)
class Hcs1MirrorV1Result:
    status: Hcs1MirrorStatusV1
    reason_code: str | None
    reference: str
    hedera_network: HederaNetwork
    resolver_id: Literal["hedera.mirror-rest.hcs1.v1"]
    verification: Hcs1V1ContentResult | None


@dataclass(frozen=True, slots=True)
class _ReadLimits:
    timeout_ms: int
    max_response_bytes: int
    deadline: float


class _MirrorFailure(Exception):
    def __init__(self, code: str, *, invalid: bool = False) -> None:
        super().__init__(code)
        self.code = code
        self.invalid = invalid


def _safe_integer(
    value: object,
    *,
    minimum: int,
    maximum: int,
    code: str,
) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < minimum
        or value > maximum
    ):
        raise TypeError(code)
    return value


def _network(value: object) -> HederaNetwork:
    if value == "mainnet":
        return "mainnet"
    if value == "testnet":
        return "testnet"
    raise TypeError("HCS1_NETWORK_INVALID")


def _effective_port(scheme: str, port: int | None) -> int | None:
    if port is not None:
        return port
    if scheme == "https":
        return 443
    if scheme == "http":
        return 80
    return None


def _same_origin(left: str, right: str) -> bool:
    try:
        lhs = urlsplit(left)
        rhs = urlsplit(right)
        return (
            lhs.scheme.lower() == rhs.scheme.lower()
            and lhs.hostname == rhs.hostname
            and _effective_port(lhs.scheme.lower(), lhs.port)
            == _effective_port(rhs.scheme.lower(), rhs.port)
        )
    except ValueError:
        return False


def _base_url(config: Hcs1MirrorV1Config, network: HederaNetwork) -> str:
    raw_value: object = None

    if config.base_urls is not None:
        raw_value = config.base_urls.get(network)
    if raw_value is None:
        raw_value = _DEFAULT_BASE[network]
    if not isinstance(raw_value, str):
        raise TypeError("Invalid HCS-1 Mirror base URL")

    try:
        parsed = urlsplit(raw_value)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise TypeError("Invalid HCS-1 Mirror base URL") from exc

    if hostname is None:
        raise TypeError("Invalid HCS-1 Mirror base URL")

    loopback = hostname in {"localhost", "127.0.0.1", "::1"}
    valid_scheme = parsed.scheme == "https" or (
        parsed.scheme == "http" and loopback
    )

    if (
        not valid_scheme
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or not parsed.path.endswith("/api/v1")
    ):
        raise TypeError(
            "HCS-1 Mirror requires a fixed HTTPS /api/v1 endpoint "
            "(or HTTP loopback)"
        )

    host = f"[{hostname}]" if ":" in hostname else hostname
    authority = host
    default_port = 443 if parsed.scheme == "https" else 80

    if port is not None and port != default_port:
        authority = f"{authority}:{port}"

    return f"{parsed.scheme}://{authority}{parsed.path.rstrip('/')}"


def _bounds(config: Hcs1MirrorV1Config) -> _ReadLimits:
    timeout = _safe_integer(
        config.timeout_ms,
        minimum=250,
        maximum=15_000,
        code="Invalid HCS-1 Mirror read limits",
    )
    maximum = _safe_integer(
        config.max_response_bytes,
        minimum=1024,
        maximum=_MAX_RESPONSE_BYTES,
        code="Invalid HCS-1 Mirror read limits",
    )
    total = _safe_integer(
        config.total_timeout_ms,
        minimum=250,
        maximum=60_000,
        code="Invalid HCS-1 Mirror read limits",
    )
    return _ReadLimits(
        timeout_ms=timeout,
        max_response_bytes=maximum,
        deadline=time.monotonic() + total / 1000,
    )


def _record(value: object) -> dict[str, object]:
    if type(value) is not dict:
        raise _MirrorFailure("HCS1_MIRROR_RESPONSE_INVALID", invalid=True)
    return cast(dict[str, object], value)


def _invalid_json_constant(value: str) -> None:
    raise ValueError(f"Invalid JSON constant: {value}")


def _headers(value: Mapping[str, str]) -> dict[str, str]:
    return {str(key).lower(): str(item) for key, item in value.items()}


async def _read_json(
    config: Hcs1MirrorV1Config,
    url: str,
    base: str,
    topic: str,
    limits: _ReadLimits,
) -> dict[str, object] | None:
    try:
        parsed = urlsplit(url)
        base_parsed = urlsplit(base)
    except ValueError as exc:
        raise _MirrorFailure(
            "HCS1_MIRROR_ENDPOINT_INVALID",
            invalid=True,
        ) from exc

    topic_path = f"{base_parsed.path}/topics/{topic}"
    messages_path = f"{topic_path}/messages"

    if (
        not _same_origin(url, base)
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or parsed.path not in (topic_path, messages_path)
    ):
        raise _MirrorFailure(
            "HCS1_MIRROR_ENDPOINT_INVALID",
            invalid=True,
        )

    remaining = limits.deadline - time.monotonic()
    if remaining <= 0:
        raise _MirrorFailure("HCS1_MIRROR_TIMEOUT")

    request_timeout_ms = min(
        limits.timeout_ms,
        max(1, math.ceil(remaining * 1000)),
    )
    fetch = config.fetch_impl or _default_fetch

    try:
        response = await asyncio.wait_for(
            fetch(
                url,
                {"Accept": "application/json"},
                request_timeout_ms,
                limits.max_response_bytes,
            ),
            timeout=request_timeout_ms / 1000,
        )
    except Exception:
        raise _MirrorFailure("HCS1_MIRROR_UNAVAILABLE") from None

    if response.status == 404:
        return None
    if response.status == 429:
        raise _MirrorFailure("HCS1_MIRROR_RATE_LIMITED")
    if not 200 <= response.status < 300:
        raise _MirrorFailure("HCS1_MIRROR_UNAVAILABLE")

    response_headers = _headers(response.headers)
    advertised = response_headers.get("content-length")

    if advertised is not None:
        try:
            if int(advertised) > limits.max_response_bytes:
                raise _MirrorFailure("HCS1_MIRROR_RESPONSE_TOO_LARGE")
        except ValueError:
            pass

    body = response.body
    if body is None:
        raise _MirrorFailure("HCS1_MIRROR_RESPONSE_INVALID", invalid=True)
    if len(body) > limits.max_response_bytes:
        raise _MirrorFailure("HCS1_MIRROR_RESPONSE_TOO_LARGE")

    try:
        parsed_json = json.loads(
            body.decode("utf-8", errors="strict"),
            parse_constant=_invalid_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise _MirrorFailure(
            "HCS1_MIRROR_RESPONSE_INVALID",
            invalid=True,
        ) from exc

    return _record(parsed_json)


def _is_canonical_base64(value: object) -> bool:
    if not isinstance(value, str) or _BASE64_RE.fullmatch(value) is None:
        return False

    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return False

    return base64.b64encode(decoded).decode("ascii") == value


def _normalize_memo(value: object) -> str:
    if not isinstance(value, str) or len(value) > 256:
        raise _MirrorFailure("HCS1_TOPIC_MEMO_INVALID", invalid=True)
    if _MEMO_RE.fullmatch(value) is not None:
        return value
    if not _is_canonical_base64(value):
        raise _MirrorFailure("HCS1_TOPIC_MEMO_INVALID", invalid=True)

    try:
        memo = base64.b64decode(value, validate=True).decode(
            "utf-8",
            errors="strict",
        )
    except (binascii.Error, UnicodeDecodeError, ValueError) as exc:
        raise _MirrorFailure(
            "HCS1_TOPIC_MEMO_INVALID",
            invalid=True,
        ) from exc

    if _MEMO_RE.fullmatch(memo) is None:
        raise _MirrorFailure("HCS1_TOPIC_MEMO_INVALID", invalid=True)

    return memo


def _json_safe_integer(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        integer = value
    elif isinstance(value, float) and math.isfinite(value) and value.is_integer():
        integer = int(value)
    else:
        return None

    if integer < 0 or integer > _MAX_SAFE_INTEGER:
        return None
    return integer


def _message_bytes(
    value: object,
    topic: str,
    previous_sequence: int,
) -> tuple[bytes, int]:
    row = _record(value)
    sequence = _json_safe_integer(row.get("sequence_number"))
    encoded = row.get("message")

    if (
        row.get("topic_id") != topic
        or sequence is None
        or sequence <= previous_sequence
        or not _is_canonical_base64(encoded)
    ):
        raise _MirrorFailure(
            "HCS1_MIRROR_MESSAGE_INVALID",
            invalid=True,
        )

    assert isinstance(encoded, str)

    try:
        message = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise _MirrorFailure(
            "HCS1_MIRROR_MESSAGE_INVALID",
            invalid=True,
        ) from exc

    if not message or len(message) > 1024:
        raise _MirrorFailure(
            "HCS1_MIRROR_MESSAGE_INVALID",
            invalid=True,
        )

    return message, sequence


def _js_truthy(value: object) -> bool:
    if value is None or value is False:
        return False

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if value == 0:
            return False
        if isinstance(value, float) and math.isnan(value):
            return False

    return value != ""


def _first_query_value(
    pairs: list[tuple[str, str]],
    key: str,
) -> str | None:
    for name, value in pairs:
        if name == key:
            return value
    return None


def _query_safe_integer(value: str) -> int | None:
    try:
        number = float(value)
    except ValueError:
        return None

    if (
        not math.isfinite(number)
        or not number.is_integer()
        or abs(number) > _MAX_SAFE_INTEGER
    ):
        return None

    return int(number)


def _next_url(
    link: str,
    *,
    base: str,
    topic: str,
) -> str:
    candidate = urljoin(f"{base}/", link)

    try:
        parsed = urlsplit(candidate)
        base_parsed = urlsplit(base)
    except ValueError as exc:
        raise _MirrorFailure(
            "HCS1_MIRROR_PAGINATION_INVALID",
            invalid=True,
        ) from exc

    expected_path = f"{base_parsed.path}/topics/{topic}/messages"

    if (
        not _same_origin(candidate, base)
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or parsed.path != expected_path
    ):
        raise _MirrorFailure(
            "HCS1_MIRROR_PAGINATION_INVALID",
            invalid=True,
        )

    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    if any(key not in _ALLOWED_PAGE_KEYS for key, _ in pairs):
        raise _MirrorFailure(
            "HCS1_MIRROR_PAGINATION_INVALID",
            invalid=True,
        )

    if _first_query_value(pairs, "order") != "asc":
        raise _MirrorFailure(
            "HCS1_MIRROR_PAGINATION_INVALID",
            invalid=True,
        )

    raw_limit = _first_query_value(pairs, "limit")
    limit = 100 if raw_limit is None else _query_safe_integer(raw_limit)

    if limit is None or limit < 1 or limit > 100:
        raise _MirrorFailure(
            "HCS1_MIRROR_PAGINATION_INVALID",
            invalid=True,
        )

    return candidate


def _result(
    request: Hcs1MirrorV1Request,
    status: Hcs1MirrorStatusV1,
    reason_code: str | None,
    verification: Hcs1V1ContentResult | None,
) -> Hcs1MirrorV1Result:
    return Hcs1MirrorV1Result(
        status=status,
        reason_code=reason_code,
        reference=request.reference,
        hedera_network=request.network,
        resolver_id="hedera.mirror-rest.hcs1.v1",
        verification=verification,
    )


async def resolve_hcs1_file_v1(
    config: Hcs1MirrorV1Config,
    request: Hcs1MirrorV1Request,
    decode_options: Hcs1V1ContentOptions | None = None,
) -> Hcs1MirrorV1Result:
    """Resolve a pinned HCS-1 file through independently observed Mirror data."""
    reference = parse_hcs1_reference_v1(request.reference)
    network = _network(request.network)
    base = _base_url(config, network)
    limits = _bounds(config)
    topic = reference.topic_id

    try:
        topic_row = await _read_json(
            config,
            f"{base}/topics/{topic}",
            base,
            topic,
            limits,
        )
        if topic_row is None:
            return _result(
                request,
                "unavailable",
                "HCS1_TOPIC_NOT_FOUND",
                None,
            )

        if (
            topic_row.get("topic_id") != topic
            or not _js_truthy(topic_row.get("submit_key"))
            or _js_truthy(topic_row.get("admin_key"))
        ):
            raise _MirrorFailure(
                "HCS1_TOPIC_METADATA_INVALID",
                invalid=True,
            )

        memo = _normalize_memo(topic_row.get("memo"))
        url: str | None = f"{base}/topics/{topic}/messages?limit=100&order=asc"
        messages: list[bytes] = []
        previous_sequence = 0
        pages = 0
        visited: set[str] = set()

        while url is not None:
            pages += 1
            if pages > _MAX_PAGES or url in visited:
                raise _MirrorFailure(
                    "HCS1_MIRROR_PAGINATION_INVALID",
                    invalid=True,
                )

            visited.add(url)
            page = await _read_json(
                config,
                url,
                base,
                topic,
                limits,
            )
            if page is None:
                raise _MirrorFailure(
                    "HCS1_MIRROR_RESPONSE_INVALID",
                    invalid=True,
                )

            raw_messages = page.get("messages")
            if type(raw_messages) is not list or len(raw_messages) > 100:
                raise _MirrorFailure(
                    "HCS1_MIRROR_RESPONSE_INVALID",
                    invalid=True,
                )

            for raw_message in cast(list[object], raw_messages):
                message, previous_sequence = _message_bytes(
                    raw_message,
                    topic,
                    previous_sequence,
                )
                messages.append(message)

                if len(messages) > MAX_HCS1_V1_CHUNKS:
                    raise _MirrorFailure(
                        "HCS1_TOO_MANY_CHUNKS",
                        invalid=True,
                    )

            raw_links = page.get("links")
            if type(raw_links) is not dict or "next" not in raw_links:
                raise _MirrorFailure(
                    "HCS1_MIRROR_PAGINATION_INVALID",
                    invalid=True,
                )

            next_link = cast(dict[str, object], raw_links).get("next")
            if next_link is None:
                url = None
                continue

            if not isinstance(next_link, str) or not next_link:
                raise _MirrorFailure(
                    "HCS1_MIRROR_PAGINATION_INVALID",
                    invalid=True,
                )

            url = _next_url(
                next_link,
                base=base,
                topic=topic,
            )

        verification = await verify_hcs1_content_v1(
            Hcs1V1ContentInput(
                memo=memo,
                messages=tuple(messages),
                expected_sha256=request.expected_sha256,
            ),
            decode_options,
        )

        if verification.status == "pass":
            status: Hcs1MirrorStatusV1 = "resolved"
        elif verification.status == "unsupported":
            status = "unsupported"
        elif verification.reason_code in {
            "HCS1_CHECKSUM_MISMATCH",
            "HCS1_EXPECTED_CHECKSUM_MISMATCH",
        }:
            status = "conflict"
        else:
            status = "invalid"

        return _result(
            request,
            status,
            verification.reason_code,
            verification,
        )

    except _MirrorFailure as exc:
        return _result(
            request,
            "invalid" if exc.invalid else "unavailable",
            exc.code,
            None,
        )