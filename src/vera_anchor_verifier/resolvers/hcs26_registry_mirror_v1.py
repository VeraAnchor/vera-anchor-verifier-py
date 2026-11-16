"""Bounded exact historical HCS-26 registry message observation."""

import asyncio
import base64
import binascii
import json
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal, cast
from urllib.parse import urlsplit

from ..contracts import HederaNetwork
from ..standards.hcs.hcs26_v1 import Hcs26MemoV1, Hcs26V1Error, parse_hcs26_memo_v1
from .hedera_mirror_v1 import HederaMirrorV1Config, _default_fetch

_DEFAULT_BASE: dict[HederaNetwork, str] = {
    "mainnet": "https://mainnet-public.mirrornode.hedera.com/api/v1",
    "testnet": "https://testnet.mirrornode.hedera.com/api/v1",
}
_TOPIC_RE = re.compile(r"^0\.0\.[0-9]+$", re.ASCII)
_BASE64_RE = re.compile(
    r"^(?:[A-Za-z0-9+/]{4})*"
    r"(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$",
    re.ASCII,
)
_TIMESTAMP_RE = re.compile(r"^[0-9]{1,20}\.[0-9]{1,9}$", re.ASCII)
_MAX_RESPONSE_BYTES = 256 * 1024
_SHARED_MIRROR_DEFAULT_BYTES = 2 * 1024 * 1024
_MAX_SAFE_INTEGER = (1 << 53) - 1

type Hcs26RegistryStatusV1 = Literal["resolved", "unavailable", "invalid"]


@dataclass(frozen=True, slots=True)
class Hcs26RegistryRequestV1:
    hedera_network: HederaNetwork
    topic_id: str
    sequence_number: int
    registry_type: Literal["discovery", "version"]


@dataclass(frozen=True, slots=True)
class Hcs26RegistryMessageV1:
    topic_id: str
    sequence_number: int
    consensus_timestamp: str
    memo: Hcs26MemoV1
    message: bytes


@dataclass(frozen=True, slots=True)
class Hcs26RegistryReadV1:
    status: Hcs26RegistryStatusV1
    reason_code: str | None
    evidence: Hcs26RegistryMessageV1 | None


@dataclass(frozen=True, slots=True)
class _ReadBounds:
    timeout_ms: int
    max_response_bytes: int


class _ReadError(Exception):
    def __init__(self, code: str, *, invalid: bool = False) -> None:
        super().__init__(code)
        self.code = code
        self.invalid = invalid


def _js_length(value: str) -> int:
    return len(value.encode("utf-16-le", "surrogatepass")) // 2


def _record(value: object) -> dict[str, object]:
    if type(value) is not dict:
        raise _ReadError("HCS26_MIRROR_RESPONSE_INVALID", invalid=True)
    return cast(dict[str, object], value)


def _safe_bound(value: object, minimum: int, maximum: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < minimum
        or (value > maximum)
        or (value > _MAX_SAFE_INTEGER)
    ):
        raise TypeError("HCS26_MIRROR_BOUNDS_INVALID")
    return value


def _base_url(config: HederaMirrorV1Config, network: HederaNetwork) -> str:
    raw: object = None
    if config.base_urls is not None:
        raw = config.base_urls.get(network)
    if raw is None:
        raw = _DEFAULT_BASE[network]
    if not isinstance(raw, str):
        raise TypeError("HCS26_MIRROR_BASE_URL_INVALID")

    try:
        parsed = urlsplit(raw)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise TypeError("HCS26_MIRROR_BASE_URL_INVALID") from exc

    if hostname is None:
        raise TypeError("HCS26_MIRROR_BASE_URL_INVALID")

    loopback = hostname in {"localhost", "127.0.0.1", "::1"}

    if (
        parsed.scheme != "https" and (not (parsed.scheme == "http" and loopback))
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or (not parsed.path.endswith("/api/v1"))
    ):
        raise TypeError("HCS26_MIRROR_BASE_URL_INVALID")

    host = f"[{hostname}]" if ":" in hostname else hostname
    authority = host
    default_port = 443 if parsed.scheme == "https" else 80

    if port is not None and port != default_port:
        authority = f"{authority}:{port}"

    return f"{parsed.scheme}://{authority}{parsed.path.rstrip('/')}"


def _limits(config: HederaMirrorV1Config) -> _ReadBounds:
    timeout = _safe_bound(config.timeout_ms, 250, 15_000)
    raw_max = config.max_response_bytes

    # The shared Python Mirror config defaults to 2 MiB. The pinned HCS-26
    # registry reader retains its own 256 KiB response ceiling.
    if raw_max == _SHARED_MIRROR_DEFAULT_BYTES:
        maximum = _MAX_RESPONSE_BYTES
    else:
        maximum = _safe_bound(raw_max, 1024, _MAX_RESPONSE_BYTES)

    return _ReadBounds(timeout_ms=timeout, max_response_bytes=maximum)


def _header_value(headers: Mapping[str, str], name: str) -> str | None:
    lowered = name.lower()

    for key, value in headers.items():
        if str(key).lower() == lowered:
            return str(value)

    return None


def _valid_content_length(value: str) -> int | None:
    text = value.strip()

    if not text:
        number = 0.0
    else:
        try:
            number = float(text)
        except ValueError:
            return None

    if not math.isfinite(number) or not number.is_integer() or abs(number) > _MAX_SAFE_INTEGER:
        return None

    return int(number)


def _invalid_json_constant(_value: str) -> None:
    raise ValueError("Invalid JSON constant")


async def _read_json(
    config: HederaMirrorV1Config,
    url: str,
    bounds: _ReadBounds,
) -> dict[str, object] | None:
    fetch = config.fetch_impl or _default_fetch

    try:
        response = await asyncio.wait_for(
            fetch(
                url,
                {"Accept": "application/json"},
                bounds.timeout_ms,
                bounds.max_response_bytes,
            ),
            timeout=bounds.timeout_ms / 1000,
        )
    except Exception:
        raise _ReadError("HCS26_MIRROR_UNAVAILABLE") from None

    if response.status == 404:
        return None
    if response.status == 429:
        raise _ReadError("HCS26_MIRROR_RATE_LIMITED")
    if not 200 <= response.status < 300:
        raise _ReadError("HCS26_MIRROR_UNAVAILABLE")

    advertised = _header_value(response.headers, "content-length")

    if advertised is not None:
        length = _valid_content_length(advertised)
        if length is None or length > bounds.max_response_bytes:
            raise _ReadError("HCS26_MIRROR_RESPONSE_TOO_LARGE")

    body = response.body

    if body is None:
        raise _ReadError("HCS26_MIRROR_RESPONSE_INVALID", invalid=True)
    if len(body) > bounds.max_response_bytes:
        raise _ReadError("HCS26_MIRROR_RESPONSE_TOO_LARGE")

    try:
        parsed = json.loads(
            body.decode("utf-8", errors="strict"),
            parse_constant=_invalid_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError) as exc:
        raise _ReadError("HCS26_MIRROR_RESPONSE_INVALID", invalid=True) from exc

    return _record(parsed)


def _canonical_base64(value: str) -> bytes:
    if _BASE64_RE.fullmatch(value) is None:
        raise _ReadError("HCS26_MIRROR_MESSAGE_INVALID", invalid=True)

    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise _ReadError("HCS26_MIRROR_MESSAGE_INVALID", invalid=True) from exc

    if base64.b64encode(decoded).decode("ascii") != value:
        raise _ReadError("HCS26_MIRROR_MESSAGE_INVALID", invalid=True)

    return decoded


def _normalized_memo(value: object) -> Hcs26MemoV1:
    if not isinstance(value, str) or _js_length(value) > 256:
        raise _ReadError("HCS26_TOPIC_MEMO_INVALID", invalid=True)

    text = value

    if not value.startswith("hcs-26:"):
        if _BASE64_RE.fullmatch(value) is None:
            raise _ReadError("HCS26_TOPIC_MEMO_INVALID", invalid=True)

        try:
            decoded = base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise _ReadError("HCS26_TOPIC_MEMO_INVALID", invalid=True) from exc

        if base64.b64encode(decoded).decode("ascii") != value:
            raise _ReadError("HCS26_TOPIC_MEMO_INVALID", invalid=True)

        try:
            text = decoded.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise _ReadError("HCS26_TOPIC_MEMO_INVALID", invalid=True) from exc

    try:
        return parse_hcs26_memo_v1(text)
    except Hcs26V1Error as exc:
        raise _ReadError(exc.code, invalid=True) from exc


def _decode_message(value: object) -> bytes:
    if not isinstance(value, str) or not value:
        raise _ReadError("HCS26_MIRROR_MESSAGE_INVALID", invalid=True)

    decoded = _canonical_base64(value)

    if not decoded or len(decoded) > 1024:
        raise _ReadError("HCS26_MIRROR_MESSAGE_INVALID", invalid=True)

    return decoded


def _json_sequence_matches(value: object, expected: int) -> bool:
    if isinstance(value, bool):
        return False
    if not isinstance(value, (int, float)):
        return False

    try:
        number = float(value)
    except OverflowError:
        return False

    return (
        math.isfinite(number)
        and number.is_integer()
        and 1 <= number <= _MAX_SAFE_INTEGER
        and int(number) == expected
    )


def _result(
    status: Hcs26RegistryStatusV1,
    reason_code: str | None,
    evidence: Hcs26RegistryMessageV1 | None = None,
) -> Hcs26RegistryReadV1:
    return Hcs26RegistryReadV1(
        status=status,
        reason_code=reason_code,
        evidence=evidence,
    )


def _validate_request(request: Hcs26RegistryRequestV1) -> None:
    network: object = request.hedera_network
    topic: object = request.topic_id
    sequence: object = request.sequence_number
    registry_type: object = request.registry_type

    if (
        network not in {"mainnet", "testnet"}
        or not isinstance(topic, str)
        or _TOPIC_RE.fullmatch(topic) is None
        or isinstance(sequence, bool)
        or not isinstance(sequence, int)
        or sequence < 1
        or sequence > _MAX_SAFE_INTEGER
        or registry_type not in {"discovery", "version"}
    ):
        raise TypeError("HCS26_REGISTRY_LOCATOR_INVALID")


async def read_hcs26_registry_message_v1(
    config: HederaMirrorV1Config,
    request: Hcs26RegistryRequestV1,
) -> Hcs26RegistryReadV1:
    """
    Observe one exact historical HCS-26 registry message through Mirror REST.

    The returned material is Mirror corroboration only. Callers must apply the
    pinned HCS-26 operation parser separately.
    """
    _validate_request(request)

    base = _base_url(config, request.hedera_network)
    bounds = _limits(config)
    topic_url = f"{base}/topics/{request.topic_id}"
    message_url = f"{topic_url}/messages/{request.sequence_number}"

    try:
        topic = await _read_json(config, topic_url, bounds)

        if topic is None:
            return _result("unavailable", "HCS26_REGISTRY_NOT_FOUND")
        if topic.get("topic_id") != request.topic_id:
            raise _ReadError("HCS26_REGISTRY_SCOPE_MISMATCH", invalid=True)

        memo = _normalized_memo(topic.get("memo"))

        if memo.type != request.registry_type:
            return _result("invalid", "HCS26_REGISTRY_TYPE_MISMATCH")

        row = await _read_json(config, message_url, bounds)

        if row is None:
            return _result("unavailable", "HCS26_REGISTRY_ENTRY_NOT_FOUND")

        if (
            row.get("topic_id") != request.topic_id
            or not _json_sequence_matches(row.get("sequence_number"), request.sequence_number)
            or row.get("chunk_info") is not None
        ):
            raise _ReadError("HCS26_REGISTRY_MESSAGE_SCOPE_MISMATCH", invalid=True)

        timestamp = row.get("consensus_timestamp")

        if not isinstance(timestamp, str) or _TIMESTAMP_RE.fullmatch(timestamp) is None:
            raise _ReadError("HCS26_REGISTRY_TIMESTAMP_INVALID", invalid=True)

        message = _decode_message(row.get("message"))

        return _result(
            "resolved",
            None,
            Hcs26RegistryMessageV1(
                topic_id=request.topic_id,
                sequence_number=request.sequence_number,
                consensus_timestamp=timestamp,
                memo=memo,
                message=message,
            ),
        )

    except _ReadError as exc:
        return _result("invalid" if exc.invalid else "unavailable", exc.code)