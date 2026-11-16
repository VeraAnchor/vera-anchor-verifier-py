"""Bounded actor-authorized HCS evidence acquisition from Vera Anchor Core."""

import asyncio
import json
import math
import re
import socket
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Literal, cast
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from ..auth.auth_provider_v1 import (
    AuthProviderContractErrorV1,
    AuthProviderV1,
    CoreAuthorizationRequestV1,
    resolve_core_authorization_v1,
)
from ..contracts import HederaNetwork

_CORE_PATH = "/v1/hcs/verify-decrypt"
_DEFAULT_TIMEOUT_MS = 12_000
_DEFAULT_RESPONSE_BYTES = 1024 * 1024
_MAX_RESPONSE_BYTES = 2 * 1024 * 1024
_MAX_IDENTIFIER_BYTES = 256
_MAX_TEXT = 4096
_MAX_SAFE_INTEGER = (1 << 53) - 1
_MAX_MESSAGE_BYTES = 256 * 1024

_HASH_RE = re.compile(r"^[0-9a-f]{128}$", re.IGNORECASE | re.ASCII)
_TOPIC_RE = re.compile(r"^0\.0\.\d+$", re.ASCII)
_CONSENSUS_RE = re.compile(r"^\d{1,12}\.\d{1,9}$", re.ASCII)
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")

_ECMASCRIPT_TRIM = (
    "\u0009\u000b\u000c\u0020\u00a0\u1680"
    "\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a"
    "\u2028\u2029\u202f\u205f\u3000\ufeff\u000a\u000d"
)

type AuthorizedHcsEvidenceStatusV1 = Literal[
    "resolved",
    "unauthorized",
    "forbidden",
    "not_found",
    "rate_limited",
    "unavailable",
    "invalid",
]

type DecryptionMethodV1 = Literal["service_assisted", "not_requested"]


@dataclass(frozen=True, slots=True)
class CoreAuthorizedFetchResponseV1:
    status: int
    headers: Mapping[str, str]
    body: bytes | None


type CoreAuthorizedFetchImplV1 = Callable[
    [str, Mapping[str, str], bytes, int, int],
    Awaitable[CoreAuthorizedFetchResponseV1],
]


@dataclass(frozen=True, slots=True)
class CoreAuthorizedV1Config:
    base_url: str
    auth_provider: AuthProviderV1
    fetch_impl: CoreAuthorizedFetchImplV1 | None = None
    timeout_ms: int = _DEFAULT_TIMEOUT_MS
    max_response_bytes: int = _DEFAULT_RESPONSE_BYTES


@dataclass(frozen=True, slots=True)
class AuthorizedHcsEvidenceV1Request:
    network: HederaNetwork
    message_id: str | None = None
    transaction_id: str | None = None
    include_decrypted: bool = False


@dataclass(frozen=True, slots=True)
class AuthorizedHcsAcquisitionV1:
    resolver_id: Literal["core.authorized-hcs.v1"]
    access_context: Literal["authorized"]
    retrieval_provider: Literal["vera_anchor_core"]
    decryption_method: DecryptionMethodV1
    recoverability: Literal["service_dependent"]


@dataclass(frozen=True, slots=True)
class AuthorizedHcsTopicV1:
    name: str
    topic_id: str | None
    key_version: int | None


@dataclass(frozen=True, slots=True)
class AuthorizedHcsEncryptionV1:
    topic_key_version: int | None
    user_key_version: int | None


@dataclass(frozen=True, slots=True)
class AuthorizedHcsTransactionV1:
    id: str
    message_id: str | None
    transaction_id: str | None
    sequence_number: int | None
    consensus_timestamp: str | None
    status: str | None
    mirror_verified: bool
    mirror_verified_at: str | None


@dataclass(frozen=True, slots=True)
class AuthorizedHcsCoreHashObservationV1:
    expected: str | None
    computed: str | None


@dataclass(frozen=True, slots=True)
class AuthorizedHcsMessageBindingV1:
    schema_version: Literal["vera.hcs-message-binding.v1"]
    algorithm: Literal["sha3-512"]
    message_sha3_512: str
    message_bytes: int


@dataclass(frozen=True, slots=True)
class AuthorizedHcsEvidenceV1:
    acquisition: AuthorizedHcsAcquisitionV1
    hedera_network: HederaNetwork
    topic: AuthorizedHcsTopicV1
    encryption: AuthorizedHcsEncryptionV1
    tx: AuthorizedHcsTransactionV1
    core_hash_observation: AuthorizedHcsCoreHashObservationV1
    message_binding: AuthorizedHcsMessageBindingV1
    payload_included: bool
    payload: object | None


@dataclass(frozen=True, slots=True)
class AuthorizedHcsEvidenceV1Result:
    status: AuthorizedHcsEvidenceStatusV1
    reason_code: str | None
    evidence: AuthorizedHcsEvidenceV1 | None


class _AuthorizedCoreReadFailure(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class _AuthorizedRequestTimeout(Exception):
    pass


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


def _js_length(value: str) -> int:
    return len(value.encode("utf-16-le", "surrogatepass")) // 2


def _trim(value: str) -> str:
    return value.strip(_ECMASCRIPT_TRIM)


def _utf8_bytes(value: str) -> int:
    return len(value.encode("utf-8", "surrogatepass"))


def _core_origin(value: object) -> str:
    if not isinstance(value, str):
        raise TypeError("Core base_url must be an absolute URL")

    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise TypeError("Core base_url must be an absolute URL") from exc

    hostname = parsed.hostname

    if hostname is None:
        raise TypeError("Core base_url must be an absolute URL")

    local = hostname in {"localhost", "127.0.0.1", "::1"}

    if (
        parsed.scheme not in {"http", "https"}
        or (parsed.scheme != "https" and not (parsed.scheme == "http" and local))
        or parsed.username is not None or parsed.password is not None or parsed.query
        or parsed.fragment or parsed.path not in {"", "/"}
    ):
        raise TypeError(
            "Core base_url must identify a fixed HTTPS origin "
            "(HTTP loopback permitted)"
        )

    rendered_host = f"[{hostname}]" if ":" in hostname else hostname
    authority = f"{rendered_host}:{port}" if port is not None else rendered_host

    return f"{parsed.scheme}://{authority}"


def _safe_bound(value: object, *, minimum: int, maximum: int) -> int:
    if (
        isinstance(value, bool) or not isinstance(value, int) or value < minimum
        or value > maximum
    ):
        raise TypeError("Invalid authorized Core transport bounds")

    return value


def _bounds(config: CoreAuthorizedV1Config) -> tuple[int, int]:
    return (
        _safe_bound(config.timeout_ms, minimum=250, maximum=60_000),
        _safe_bound(
            config.max_response_bytes,
            minimum=1024,
            maximum=_MAX_RESPONSE_BYTES,
        ),
    )


def _identifier(value: object, name: str) -> str | None:
    if value is None or value == "":
        return None

    if (
        not isinstance(value, str) or not value or _trim(value) != value
        or _utf8_bytes(value) > _MAX_IDENTIFIER_BYTES
        or _CONTROL_RE.search(value) is not None
    ):
        raise TypeError(f"Invalid {name}")

    return value


def _request_body(request: AuthorizedHcsEvidenceV1Request) -> dict[str, object]:
    if request.network not in ("mainnet", "testnet"):
        raise TypeError("Authorized HCS evidence requires an explicit Hedera network")

    message_id = _identifier(request.message_id, "message_id")
    transaction_id = _identifier(request.transaction_id, "transaction_id")

    if (message_id is None) == (transaction_id is None):
        raise TypeError("Exactly one of message_id or transaction_id is required")

    body: dict[str, object] = {"hedera_network": request.network}

    if message_id is not None:
        body["message_id"] = message_id
    else:
        body["transaction_id"] = transaction_id

    body["mode"] = "decrypt_only"
    body["include_decrypted"] = request.include_decrypted is True

    return body


def _object(value: object) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise _AuthorizedCoreReadFailure("CORE_AUTHORIZED_RESPONSE_INVALID")

    return cast(Mapping[str, object], value)


def _text(value: object, maximum: int = _MAX_TEXT) -> str:
    if (
        not isinstance(value, str) or not value or _js_length(value) > maximum
        or _trim(value) != value or _CONTROL_RE.search(value) is not None
    ):
        raise _AuthorizedCoreReadFailure("CORE_AUTHORIZED_RESPONSE_INVALID")

    return value


def _nullable_text(value: object, maximum: int = _MAX_TEXT) -> str | None:
    if value is None:
        return None

    return _text(value, maximum)


def _nullable_positive_int(value: object) -> int | None:
    if value is None:
        return None

    if isinstance(value, bool):
        raise _AuthorizedCoreReadFailure("CORE_AUTHORIZED_RESPONSE_INVALID")

    if isinstance(value, int):
        number = value
    elif isinstance(value, float) and math.isfinite(value) and value.is_integer():
        number = int(value)
    else:
        raise _AuthorizedCoreReadFailure("CORE_AUTHORIZED_RESPONSE_INVALID")

    if number < 1 or number > _MAX_SAFE_INTEGER:
        raise _AuthorizedCoreReadFailure("CORE_AUTHORIZED_RESPONSE_INVALID")

    return number


def _nullable_hash(value: object) -> str | None:
    if value is None or value == "":
        return None

    digest = _text(value, 128)

    if _HASH_RE.fullmatch(digest) is None:
        raise _AuthorizedCoreReadFailure("CORE_AUTHORIZED_RESPONSE_INVALID")

    return digest.lower()


def _validate_success(
    body: object,
    request: AuthorizedHcsEvidenceV1Request,
) -> AuthorizedHcsEvidenceV1:
    row = _object(body)

    if (
        row.get("ok") is not True or row.get("hedera_network") != request.network
        or row.get("mode") != "decrypt_only" or "verified" not in row
        or row.get("verified") is not None
    ):
        raise _AuthorizedCoreReadFailure("CORE_AUTHORIZED_RESPONSE_INVALID")

    topic = _object(row.get("topic"))
    encryption = _object(row.get("encryption"))
    tx = _object(row.get("tx"))
    core_hash = _object(row.get("hash"))
    binding = _object(row.get("message_binding"))

    if (
        "match" not in core_hash or core_hash.get("match") is not None
        or not isinstance(tx.get("mirror_verified"), bool)
        or binding.get("schema_version") != "vera.hcs-message-binding.v1"
        or binding.get("algorithm") != "sha3-512"
    ):
        raise _AuthorizedCoreReadFailure("CORE_AUTHORIZED_RESPONSE_INVALID")

    topic_id = _nullable_text(topic.get("topic_id"), 64)

    if topic_id is not None and _TOPIC_RE.fullmatch(topic_id) is None:
        raise _AuthorizedCoreReadFailure("CORE_AUTHORIZED_RESPONSE_INVALID")

    consensus_timestamp = _nullable_text(tx.get("consensus_timestamp"), 64)

    if (
        consensus_timestamp is not None and _CONSENSUS_RE.fullmatch(consensus_timestamp)
        is None
    ):
        raise _AuthorizedCoreReadFailure("CORE_AUTHORIZED_RESPONSE_INVALID")

    message_id = _nullable_text(tx.get("message_id"), _MAX_IDENTIFIER_BYTES)
    transaction_id = _nullable_text(tx.get("transaction_id"), _MAX_IDENTIFIER_BYTES)

    if request.message_id is not None and message_id != request.message_id:
        raise _AuthorizedCoreReadFailure("CORE_AUTHORIZED_LOCATOR_MISMATCH")

    if (
        request.transaction_id is not None and transaction_id != request.transaction_id
    ):
        raise _AuthorizedCoreReadFailure("CORE_AUTHORIZED_LOCATOR_MISMATCH")

    message_digest = _text(binding.get("message_sha3_512"), 128)
    message_bytes = _nullable_positive_int(binding.get("message_bytes"))

    if (
        _HASH_RE.fullmatch(message_digest) is None or message_bytes is None
        or message_bytes > _MAX_MESSAGE_BYTES
    ):
        raise _AuthorizedCoreReadFailure("CORE_AUTHORIZED_RESPONSE_INVALID")

    include_payload = request.include_decrypted is True
    has_payload = "payload" in row

    if include_payload != has_payload:
        raise _AuthorizedCoreReadFailure("CORE_AUTHORIZED_DISCLOSURE_MISMATCH")

    mirror_verified = tx.get("mirror_verified")
    assert isinstance(mirror_verified, bool)

    return AuthorizedHcsEvidenceV1(
        acquisition=AuthorizedHcsAcquisitionV1(
            resolver_id="core.authorized-hcs.v1",
            access_context="authorized",
            retrieval_provider="vera_anchor_core",
            decryption_method=(
                "service_assisted"
                if include_payload
                else "not_requested"
            ),
            recoverability="service_dependent",
        ),
        hedera_network=request.network,
        topic=AuthorizedHcsTopicV1(
            name=_text(topic.get("name"), 256),
            topic_id=topic_id,
            key_version=_nullable_positive_int(topic.get("key_version")),
        ),
        encryption=AuthorizedHcsEncryptionV1(
            topic_key_version=_nullable_positive_int(
                encryption.get("topic_key_version")
            ),
            user_key_version=_nullable_positive_int(encryption.get("user_key_version")),
        ),
        tx=AuthorizedHcsTransactionV1(
            id=_text(tx.get("id"), 128),
            message_id=message_id,
            transaction_id=transaction_id,
            sequence_number=_nullable_positive_int(tx.get("sequence_number")),
            consensus_timestamp=consensus_timestamp,
            status=_nullable_text(tx.get("status"), 64),
            mirror_verified=mirror_verified,
            mirror_verified_at=_nullable_text(tx.get("mirror_verified_at"), 64),
        ),
        core_hash_observation=AuthorizedHcsCoreHashObservationV1(
            expected=_nullable_hash(core_hash.get("expected")),
            computed=_nullable_hash(core_hash.get("computed")),
        ),
        message_binding=AuthorizedHcsMessageBindingV1(
            schema_version="vera.hcs-message-binding.v1",
            algorithm="sha3-512",
            message_sha3_512=message_digest.lower(),
            message_bytes=message_bytes,
        ),
        payload_included=include_payload,
        payload=row.get("payload") if include_payload else None,
    )


def _headers(value: Mapping[str, str]) -> dict[str, str]:
    return {str(key).lower(): str(item) for key, item in value.items()}


def _read_bounded(response: object, maximum: int) -> bytes:
    chunks: list[bytes] = []
    total = 0

    while total <= maximum:
        remaining = maximum + 1 - total
        chunk = response.read(  # type: ignore[attr-defined]
            min(64 * 1024, remaining)
        )

        if not chunk:
            break

        if not isinstance(chunk, bytes):
            raise OSError("Invalid Core response body")

        chunks.append(chunk)
        total += len(chunk)

    return b"".join(chunks)


def _default_fetch_sync(
    url: str,
    headers: Mapping[str, str],
    body: bytes,
    timeout_ms: int,
    max_response_bytes: int,
) -> CoreAuthorizedFetchResponseV1:
    request = Request(url, data=body, headers=dict(headers), method="POST")
    opener = build_opener(_NoRedirect())

    try:
        with opener.open(request, timeout=timeout_ms / 1000) as response:
            return CoreAuthorizedFetchResponseV1(
                status=int(response.getcode()),
                headers={key.lower(): value for key, value in response.headers.items()},
                body=_read_bounded(response, max_response_bytes),
            )

    except HTTPError as exc:
        if 300 <= exc.code < 400:
            raise OSError("Core redirect rejected") from exc

        response_headers = (
            {}
            if exc.headers is None
            else {key.lower(): value for key, value in exc.headers.items()}
        )

        return CoreAuthorizedFetchResponseV1(
            status=exc.code,
            headers=response_headers,
            body=b"",
        )

    except TimeoutError as exc:
        raise _AuthorizedRequestTimeout() from exc

    except URLError as exc:
        if isinstance(exc.reason, (TimeoutError, socket.timeout)):
            raise _AuthorizedRequestTimeout() from exc

        raise


async def _default_fetch(
    url: str,
    headers: Mapping[str, str],
    body: bytes,
    timeout_ms: int,
    max_response_bytes: int,
) -> CoreAuthorizedFetchResponseV1:
    return await asyncio.to_thread(
        _default_fetch_sync,
        url,
        headers,
        body,
        timeout_ms,
        max_response_bytes,
    )


def _invalid_json_constant(value: str) -> None:
    raise ValueError(f"Invalid JSON constant: {value}")


def _read_json_bounded(response: CoreAuthorizedFetchResponseV1, budget: int) -> object:
    headers = _headers(response.headers)
    content_type = headers.get("content-type", "").lower()

    if "application/json" not in content_type:
        raise _AuthorizedCoreReadFailure("CORE_AUTHORIZED_RESPONSE_INVALID")

    declared = headers.get("content-length")

    if declared is not None:
        try:
            number = float(declared)
        except ValueError:
            number = math.nan

        if not math.isfinite(number) or number < 0 or number > budget:
            raise _AuthorizedCoreReadFailure("CORE_AUTHORIZED_RESPONSE_TOO_LARGE")

    if response.body is None:
        raise _AuthorizedCoreReadFailure("CORE_AUTHORIZED_RESPONSE_INVALID")

    if len(response.body) > budget:
        raise _AuthorizedCoreReadFailure("CORE_AUTHORIZED_RESPONSE_TOO_LARGE")

    try:
        text = response.body.decode("utf-8", errors="strict")
        return json.loads(text, parse_constant=_invalid_json_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise _AuthorizedCoreReadFailure("CORE_AUTHORIZED_RESPONSE_INVALID") from None


def _failure(
    status: AuthorizedHcsEvidenceStatusV1,
    reason: str,
) -> AuthorizedHcsEvidenceV1Result:
    return AuthorizedHcsEvidenceV1Result(
        status=status,
        reason_code=reason,
        evidence=None,
    )


def _http_failure(status: int) -> AuthorizedHcsEvidenceV1Result:
    if status == 401:
        return _failure("unauthorized", "CORE_AUTH_REQUIRED")

    if status == 403:
        return _failure("forbidden", "CORE_AUTH_FORBIDDEN")

    if status == 404:
        return _failure("not_found", "CORE_AUTHORIZED_EVIDENCE_NOT_FOUND")

    if status == 429:
        return _failure("rate_limited", "CORE_RATE_LIMITED")

    if 400 <= status < 500:
        return _failure("invalid", "CORE_AUTHORIZED_REQUEST_REJECTED")

    return _failure("unavailable", "CORE_AUTHORIZED_HTTP_UNAVAILABLE")


async def resolve_authorized_hcs_evidence_v1(
    config: CoreAuthorizedV1Config,
    request: AuthorizedHcsEvidenceV1Request,
) -> AuthorizedHcsEvidenceV1Result:
    """
    Retrieve actor-authorized HCS evidence without trusting Core's verdict.

    Core remains the authentication/decryption provider. Verification meaning
    is established later by local recomputation and independent corroboration.
    """
    if config is None or config.auth_provider is None:
        raise TypeError("Authorized Core resolver requires auth_provider")

    origin = _core_origin(config.base_url)
    timeout, budget = _bounds(config)
    body = _request_body(request)

    auth_request = CoreAuthorizationRequestV1(
        origin=origin,
        path="/v1/hcs/verify-decrypt",
        method="POST",
        network=request.network,
    )

    try:
        authorization = (
            await resolve_core_authorization_v1(config.auth_provider, auth_request)
        ).authorization
    except AuthProviderContractErrorV1:
        raise
    except Exception:
        return _failure("unavailable", "AUTH_PROVIDER_UNAVAILABLE")

    try:
        encoded_body = json.dumps(
            body,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise TypeError("Invalid authorized Core request") from exc

    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": authorization,
    }
    fetch = config.fetch_impl or _default_fetch

    try:
        response = await fetch(
            f"{origin}{_CORE_PATH}",
            headers,
            encoded_body,
            timeout,
            budget,
        )
    except (TimeoutError, _AuthorizedRequestTimeout):
        return _failure("unavailable", "CORE_AUTHORIZED_REQUEST_TIMEOUT")
    except Exception:
        return _failure("unavailable", "CORE_AUTHORIZED_REQUEST_UNAVAILABLE")

    if not 200 <= response.status < 300:
        return _http_failure(response.status)

    try:
        parsed = _read_json_bounded(response, budget)
        evidence = _validate_success(parsed, request)
    except _AuthorizedCoreReadFailure as exc:
        return _failure("invalid", exc.code)
    except Exception:
        return _failure("invalid", "CORE_AUTHORIZED_RESPONSE_INVALID")

    return AuthorizedHcsEvidenceV1Result(
        status="resolved",
        reason_code=None,
        evidence=evidence,
    )