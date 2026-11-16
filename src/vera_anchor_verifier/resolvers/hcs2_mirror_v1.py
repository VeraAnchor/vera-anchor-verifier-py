"""Read-only HCS-2 historical register observation through Hedera Mirror."""

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
from ..standards.hcs.hcs2_v1 import (
    Hcs2V1VerificationInput,
    Hcs2V1VerificationResult,
    verify_hcs2_register_v1,
)
from .hedera_mirror_v1 import HederaMirrorV1Config, _default_fetch

_DEFAULT_MIRROR: dict[HederaNetwork, str] = {
    "mainnet": "https://mainnet-public.mirrornode.hedera.com/api/v1",
    "testnet": "https://testnet.mirrornode.hedera.com/api/v1",
}
_TOPIC_RE = re.compile(r"^0\.0\.[0-9]+$", re.ASCII)
_BASE64_RE = re.compile(
    r"^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$",
    re.ASCII,
)
_MEMO_RE = re.compile(r"^hcs-2:[01]:[0-9]+$", re.ASCII)
_TIMESTAMP_RE = re.compile(r"^[0-9]{1,20}\.[0-9]{1,9}$", re.ASCII)

_MAX_RESPONSE_BYTES = 256 * 1024
_SHARED_MIRROR_DEFAULT_BYTES = 2 * 1024 * 1024
_MAX_SAFE_INTEGER = (1 << 53) - 1

type Hcs2MirrorStatusV1 = Literal[
    "resolved",
    "conflict",
    "invalid",
    "unavailable",
]


@dataclass(frozen=True, slots=True)
class Hcs2MirrorV1Request:
    hedera_network: HederaNetwork
    registry_topic_id: str
    sequence_number: int
    expected_t_id: str | None = None


@dataclass(frozen=True, slots=True)
class Hcs2MirrorV1Result:
    status: Hcs2MirrorStatusV1
    reason_code: str | None
    hedera_network: HederaNetwork
    registry_topic_id: str
    sequence_number: int
    consensus_timestamp: str | None
    resolver_id: Literal["hedera.mirror-rest.hcs2.v1"]
    verification: Hcs2V1VerificationResult | None


@dataclass(frozen=True, slots=True)
class _RequestBounds:
    timeout_ms: int
    max_response_bytes: int


class _ReadFailure(Exception):
    def __init__(self, code: str, *, invalid: bool = False) -> None:
        super().__init__(code)
        self.code = code
        self.invalid = invalid


def _record(value: object) -> dict[str, object]:
    if type(value) is not dict:
        raise _ReadFailure(
            "HCS2_MIRROR_RESPONSE_INVALID",
            invalid=True,
        )
    return cast(dict[str, object], value)


def _base_url(
    config: HederaMirrorV1Config,
    network: HederaNetwork,
) -> str:
    raw: object = None

    if config.base_urls is not None:
        raw = config.base_urls.get(network)
    if raw is None:
        raw = _DEFAULT_MIRROR[network]
    if not isinstance(raw, str):
        raise TypeError("HCS2_MIRROR_BASE_URL_INVALID")

    try:
        parsed = urlsplit(raw)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise TypeError("HCS2_MIRROR_BASE_URL_INVALID") from exc

    if hostname is None:
        raise TypeError("HCS2_MIRROR_BASE_URL_INVALID")

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
        raise TypeError("HCS2_MIRROR_BASE_URL_INVALID")

    host = f"[{hostname}]" if ":" in hostname else hostname
    authority = host
    default_port = 443 if parsed.scheme == "https" else 80

    if port is not None and port != default_port:
        authority = f"{authority}:{port}"

    return f"{parsed.scheme}://{authority}{parsed.path.rstrip('/')}"


def _safe_bound(
    value: object,
    minimum: int,
    maximum: int,
) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < minimum
        or value > maximum
        or value > _MAX_SAFE_INTEGER
    ):
        raise TypeError("HCS2_MIRROR_BOUNDS_INVALID")
    return value


def _request_bounds(config: HederaMirrorV1Config) -> _RequestBounds:
    timeout = _safe_bound(
        config.timeout_ms,
        250,
        15_000,
    )
    raw_max = config.max_response_bytes

    # The shared Python Mirror config defaults to 2 MiB.
    # HCS-2 keeps its pinned 256 KiB response ceiling.
    if raw_max == _SHARED_MIRROR_DEFAULT_BYTES:
        maximum = _MAX_RESPONSE_BYTES
    else:
        maximum = _safe_bound(
            raw_max,
            1024,
            _MAX_RESPONSE_BYTES,
        )

    return _RequestBounds(
        timeout_ms=timeout,
        max_response_bytes=maximum,
    )


def _invalid_json_constant(value: str) -> None:
    raise ValueError(f"Invalid JSON constant: {value}")


def _header_value(
    headers: Mapping[str, str],
    name: str,
) -> str | None:
    lowered = name.lower()
    for key, value in headers.items():
        if str(key).lower() == lowered:
            return str(value)
    return None


async def _read_json(
    config: HederaMirrorV1Config,
    url: str,
    bounds: _RequestBounds,
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
        raise _ReadFailure("HCS2_MIRROR_UNAVAILABLE") from None

    if response.status == 404:
        return None
    if response.status == 429:
        raise _ReadFailure("HCS2_MIRROR_RATE_LIMITED")
    if not 200 <= response.status < 300:
        raise _ReadFailure("HCS2_MIRROR_UNAVAILABLE")

    advertised = _header_value(
        response.headers,
        "content-length",
    )

    if advertised:
        try:
            size = float(advertised)
        except ValueError:
            raise _ReadFailure(
                "HCS2_MIRROR_RESPONSE_TOO_LARGE"
            ) from None

        if not math.isfinite(size) or size > bounds.max_response_bytes:
            raise _ReadFailure("HCS2_MIRROR_RESPONSE_TOO_LARGE")

    body = response.body
    if body is None:
        raise _ReadFailure(
            "HCS2_MIRROR_RESPONSE_INVALID",
            invalid=True,
        )
    if len(body) > bounds.max_response_bytes:
        raise _ReadFailure("HCS2_MIRROR_RESPONSE_TOO_LARGE")

    try:
        value = json.loads(
            body.decode("utf-8", errors="strict"),
            parse_constant=_invalid_json_constant,
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValueError,
    ) as exc:
        raise _ReadFailure(
            "HCS2_MIRROR_RESPONSE_INVALID",
            invalid=True,
        ) from exc

    return _record(value)


def _canonical_base64(value: object) -> str | None:
    if not isinstance(value, str) or _BASE64_RE.fullmatch(value) is None:
        return None

    try:
        decoded = base64.b64decode(
            value,
            validate=True,
        )
    except (binascii.Error, ValueError):
        return None

    if base64.b64encode(decoded).decode("ascii") != value:
        return None

    return value


def _normalized_memo(value: object) -> str:
    if not isinstance(value, str) or len(value) > 256:
        raise _ReadFailure(
            "HCS2_TOPIC_MEMO_INVALID",
            invalid=True,
        )

    if _MEMO_RE.fullmatch(value) is not None:
        return value

    encoded = _canonical_base64(value)
    if encoded is None:
        raise _ReadFailure(
            "HCS2_TOPIC_MEMO_INVALID",
            invalid=True,
        )

    try:
        decoded = base64.b64decode(
            encoded,
            validate=True,
        ).decode(
            "utf-8",
            errors="strict",
        )
    except (
        binascii.Error,
        UnicodeDecodeError,
        ValueError,
    ) as exc:
        raise _ReadFailure(
            "HCS2_TOPIC_MEMO_INVALID",
            invalid=True,
        ) from exc

    if _MEMO_RE.fullmatch(decoded) is None:
        raise _ReadFailure(
            "HCS2_TOPIC_MEMO_INVALID",
            invalid=True,
        )

    return decoded


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


def _valid_locator(request: Hcs2MirrorV1Request) -> bool:
    network: object = request.hedera_network
    topic: object = request.registry_topic_id
    sequence: object = request.sequence_number

    return (
        network in {"mainnet", "testnet"}
        and isinstance(topic, str)
        and _TOPIC_RE.fullmatch(topic) is not None
        and not isinstance(sequence, bool)
        and isinstance(sequence, int)
        and 1 <= sequence <= _MAX_SAFE_INTEGER
    )


def _output(
    request: Hcs2MirrorV1Request,
    status: Hcs2MirrorStatusV1,
    reason_code: str | None,
    verification: Hcs2V1VerificationResult | None,
    consensus_timestamp: str | None = None,
) -> Hcs2MirrorV1Result:
    return Hcs2MirrorV1Result(
        status=status,
        reason_code=reason_code,
        hedera_network=request.hedera_network,
        registry_topic_id=request.registry_topic_id,
        sequence_number=request.sequence_number,
        consensus_timestamp=consensus_timestamp,
        resolver_id="hedera.mirror-rest.hcs2.v1",
        verification=verification,
    )


async def resolve_hcs2_register_v1(
    config: HederaMirrorV1Config,
    request: Hcs2MirrorV1Request,
) -> Hcs2MirrorV1Result:
    """
    Verify one exact historical HCS-2 register observed through Mirror.

    This does not reconstruct mutable current registry state and does not
    authenticate Hedera consensus signatures.
    """
    if not _valid_locator(request):
        raise TypeError("HCS2_REGISTRY_LOCATOR_INVALID")

    network = request.hedera_network
    base = _base_url(config, network)
    bounds = _request_bounds(config)
    topic = request.registry_topic_id

    try:
        topic_row = await _read_json(
            config,
            f"{base}/topics/{topic}",
            bounds,
        )
        if topic_row is None:
            return _output(
                request,
                "unavailable",
                "HCS2_REGISTRY_NOT_FOUND",
                None,
            )

        if topic_row.get("topic_id") != topic:
            raise _ReadFailure(
                "HCS2_REGISTRY_SCOPE_MISMATCH",
                invalid=True,
            )

        memo = _normalized_memo(topic_row.get("memo"))
        row = await _read_json(
            config,
            f"{base}/topics/{topic}/messages/{request.sequence_number}",
            bounds,
        )
        if row is None:
            return _output(
                request,
                "unavailable",
                "HCS2_REGISTER_NOT_FOUND",
                None,
            )

        encoded = row.get("message")
        row_sequence = _json_safe_integer(row.get("sequence_number"))

        if (
            row.get("topic_id") != topic
            or row_sequence != request.sequence_number
            or row.get("chunk_info") is not None
            or _canonical_base64(encoded) is None
        ):
            raise _ReadFailure(
                "HCS2_MESSAGE_SCOPE_INVALID",
                invalid=True,
            )

        timestamp = row.get("consensus_timestamp")
        if (
            not isinstance(timestamp, str)
            or _TIMESTAMP_RE.fullmatch(timestamp) is None
        ):
            raise _ReadFailure(
                "HCS2_MESSAGE_TIMESTAMP_INVALID",
                invalid=True,
            )

        assert isinstance(encoded, str)

        try:
            message = base64.b64decode(
                encoded,
                validate=True,
            )
        except (binascii.Error, ValueError) as exc:
            raise _ReadFailure(
                "HCS2_MIRROR_MESSAGE_INVALID",
                invalid=True,
            ) from exc

        if not message or len(message) > 1024:
            raise _ReadFailure(
                "HCS2_MIRROR_MESSAGE_INVALID",
                invalid=True,
            )

        verification = verify_hcs2_register_v1(
            Hcs2V1VerificationInput(
                memo=memo,
                message=message,
                expected_t_id=request.expected_t_id,
            )
        )

        status: Hcs2MirrorStatusV1
        if verification.status == "pass":
            status = "resolved"
        elif verification.reason_code == "HCS2_TARGET_MISMATCH":
            status = "conflict"
        else:
            status = "invalid"

        return _output(
            request,
            status,
            verification.reason_code,
            verification,
            timestamp,
        )

    except _ReadFailure as exc:
        return _output(
            request,
            "invalid" if exc.invalid else "unavailable",
            exc.code,
            None,
        )