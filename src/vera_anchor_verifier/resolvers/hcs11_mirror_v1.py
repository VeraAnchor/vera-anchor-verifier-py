"""Bounded public HCS-11 account/profile resolution."""

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
from ..standards.hcs.hcs1_v1 import Hcs1V1ContentOptions, parse_hcs1_reference_v1
from ..standards.hcs.hcs11_v1 import (
    Hcs11V1Input,
    Hcs11V1Memo,
    Hcs11V1Profile,
    parse_hcs11_account_memo_v1,
    verify_hcs11_ai_agent_profile_v1,
)
from ..standards.hcs.hcs14_v1 import parse_hcs14_did_uaid_v1
from .hcs1_mirror_v1 import Hcs1MirrorV1Config, Hcs1MirrorV1Request, resolve_hcs1_file_v1
from .hcs2_mirror_v1 import Hcs2MirrorV1Request, resolve_hcs2_register_v1
from .hedera_mirror_v1 import _default_fetch

_DEFAULT_BASE: dict[HederaNetwork, str] = {
    "mainnet": "https://mainnet-public.mirrornode.hedera.com/api/v1",
    "testnet": "https://testnet.mirrornode.hedera.com/api/v1",
}
_ACCOUNT_RE = re.compile(r"^0\.0\.[0-9]+$", re.ASCII)
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_BASE64_RE = re.compile(
    r"^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$",
    re.ASCII,
)
_NATIVE_HEDERA_RE = re.compile(
    r"^hedera:(mainnet|testnet):0\.0\.[0-9]+$",
    re.ASCII,
)

_MAX_RESPONSE_BYTES = 256 * 1024
_SHARED_MIRROR_DEFAULT_BYTES = 2 * 1024 * 1024
_MAX_SAFE_INTEGER = (1 << 53) - 1

type Hcs11MirrorStatusV1 = Literal[
    "resolved",
    "conflict",
    "invalid",
    "unavailable",
    "unsupported",
]


@dataclass(frozen=True, slots=True)
class Hcs11MirrorV1Request:
    hedera_network: HederaNetwork
    account_id: str
    hcs2_sequence_number: int | None = None
    expected_profile_reference: str | None = None
    expected_hcs1_reference: str | None = None
    expected_hcs1_sha256: str | None = None
    expected_profile_sha256: str | None = None
    expected_uaid: str | None = None
    expected_base_did: str | None = None


@dataclass(frozen=True, slots=True)
class Hcs11RegistryEntryV1:
    topic_id: str
    sequence_number: int
    consensus_timestamp: str


@dataclass(frozen=True, slots=True)
class Hcs11MirrorV1Result:
    status: Hcs11MirrorStatusV1
    reason_code: str | None
    hedera_network: HederaNetwork
    account_id: str
    resolver_id: Literal["hedera.mirror-rest.hcs11.v1"]
    account_memo_temporal_scope: Literal["current_observation"]
    account_memo: Hcs11V1Memo | None
    registry_entry: Hcs11RegistryEntryV1 | None
    profile_reference: str | None
    content_sha256: str | None
    canonical_profile_sha256: str | None
    profile: Hcs11V1Profile | None
    did_binding: Literal["match", "not_checked"]


@dataclass(frozen=True, slots=True)
class _ReadBounds:
    timeout_ms: int
    max_response_bytes: int


class _AccountReadError(Exception):
    def __init__(self, code: str, *, invalid: bool = False) -> None:
        super().__init__(code)
        self.code = code
        self.invalid = invalid


def _record(value: object) -> dict[str, object]:
    if type(value) is not dict:
        raise _AccountReadError(
            "HCS11_ACCOUNT_RESPONSE_INVALID",
            invalid=True,
        )
    return cast(dict[str, object], value)


def _base_url(
    config: Hcs1MirrorV1Config,
    network: HederaNetwork,
) -> str:
    raw: object = None

    if config.base_urls is not None:
        raw = config.base_urls.get(network)
    if raw is None:
        raw = _DEFAULT_BASE[network]
    if not isinstance(raw, str):
        raise TypeError("HCS11_MIRROR_BASE_URL_INVALID")

    try:
        parsed = urlsplit(raw)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise TypeError("HCS11_MIRROR_BASE_URL_INVALID") from exc

    if hostname is None:
        raise TypeError("HCS11_MIRROR_BASE_URL_INVALID")

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
        raise TypeError("HCS11_MIRROR_BASE_URL_INVALID")

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
        raise TypeError("HCS11_MIRROR_BOUNDS_INVALID")
    return value


def _validated_limits(config: Hcs1MirrorV1Config) -> _ReadBounds:
    timeout = _safe_bound(
        config.timeout_ms,
        250,
        15_000,
    )
    raw_max = config.max_response_bytes

    # The shared Mirror config defaults to 2 MiB. HCS-11 account
    # acquisition retains its pinned 256 KiB response ceiling.
    if raw_max == _SHARED_MIRROR_DEFAULT_BYTES:
        maximum = _MAX_RESPONSE_BYTES
    else:
        maximum = _safe_bound(
            raw_max,
            1024,
            _MAX_RESPONSE_BYTES,
        )

    return _ReadBounds(
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


async def _read_account(
    config: Hcs1MirrorV1Config,
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
        raise _AccountReadError("HCS11_ACCOUNT_UNAVAILABLE") from None

    if response.status == 404:
        return None
    if response.status == 429:
        raise _AccountReadError("HCS11_ACCOUNT_RATE_LIMITED")
    if not 200 <= response.status < 300:
        raise _AccountReadError("HCS11_ACCOUNT_UNAVAILABLE")

    advertised = _header_value(
        response.headers,
        "content-length",
    )

    if advertised:
        try:
            length = float(advertised)
        except ValueError:
            raise _AccountReadError(
                "HCS11_ACCOUNT_RESPONSE_TOO_LARGE"
            ) from None

        if not math.isfinite(length) or length > bounds.max_response_bytes:
            raise _AccountReadError("HCS11_ACCOUNT_RESPONSE_TOO_LARGE")

    body = response.body
    if body is None:
        raise _AccountReadError(
            "HCS11_ACCOUNT_RESPONSE_INVALID",
            invalid=True,
        )
    if len(body) > bounds.max_response_bytes:
        raise _AccountReadError("HCS11_ACCOUNT_RESPONSE_TOO_LARGE")

    try:
        parsed = json.loads(
            body.decode("utf-8", errors="strict"),
            parse_constant=_invalid_json_constant,
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValueError,
    ) as exc:
        raise _AccountReadError(
            "HCS11_ACCOUNT_RESPONSE_INVALID",
            invalid=True,
        ) from exc

    return _record(parsed)


def _decode_memo(value: object) -> str:
    if (
        not isinstance(value, str)
        or len(value) > 1024
        or _BASE64_RE.fullmatch(value) is None
    ):
        raise _AccountReadError(
            "HCS11_ACCOUNT_MEMO_INVALID",
            invalid=True,
        )

    try:
        raw = base64.b64decode(
            value,
            validate=True,
        )
    except (binascii.Error, ValueError) as exc:
        raise _AccountReadError(
            "HCS11_ACCOUNT_MEMO_INVALID",
            invalid=True,
        ) from exc

    if base64.b64encode(raw).decode("ascii") != value:
        raise _AccountReadError(
            "HCS11_ACCOUNT_MEMO_INVALID",
            invalid=True,
        )

    try:
        decoded = raw.decode(
            "utf-8",
            errors="strict",
        )
    except UnicodeDecodeError as exc:
        raise _AccountReadError(
            "HCS11_ACCOUNT_MEMO_INVALID",
            invalid=True,
        ) from exc

    if len(decoded.encode("utf-8")) > 100:
        raise _AccountReadError(
            "HCS11_ACCOUNT_MEMO_INVALID",
            invalid=True,
        )

    return decoded


def _observed_account_memo(
    row: Mapping[str, object],
) -> Hcs11V1Memo:
    encoded = row.get("memo_base64")
    memo: str | None = None

    if encoded is not None:
        memo = _decode_memo(encoded)

    plain_value = row.get("memo")
    if plain_value is not None:
        if not isinstance(plain_value, str):
            raise _AccountReadError(
                "HCS11_ACCOUNT_MEMO_INVALID",
                invalid=True,
            )

        plain = (
            plain_value
            if plain_value.startswith("hcs-11:")
            else _decode_memo(plain_value)
        )

        if memo is not None and memo != plain:
            raise _AccountReadError(
                "HCS11_ACCOUNT_MEMO_CONFLICT",
                invalid=True,
            )

        memo = plain

    if not memo:
        raise _AccountReadError("HCS11_ACCOUNT_MEMO_UNAVAILABLE")

    try:
        return parse_hcs11_account_memo_v1(memo)
    except Exception as exc:
        raise _AccountReadError(
            "HCS11_ACCOUNT_MEMO_INVALID",
            invalid=True,
        ) from exc


def _checked_request(request: Hcs11MirrorV1Request) -> None:
    network: object = request.hedera_network
    account: object = request.account_id
    sequence: object = request.hcs2_sequence_number

    if (
        network not in {"mainnet", "testnet"}
        or not isinstance(account, str)
        or len(account) > 128
        or _ACCOUNT_RE.fullmatch(account) is None
    ):
        raise TypeError("HCS11_ACCOUNT_LOCATOR_INVALID")

    if (
        sequence is not None
        and (
            isinstance(sequence, bool)
            or not isinstance(sequence, int)
            or sequence < 1
            or sequence > _MAX_SAFE_INTEGER
        )
    ):
        raise TypeError("HCS11_HCS2_SEQUENCE_INVALID")

    expected_profile: object = request.expected_profile_reference
    if expected_profile is not None:
        parse_hcs11_account_memo_v1(f"hcs-11:{expected_profile}")

    expected_hcs1: object = request.expected_hcs1_reference
    if expected_hcs1 is not None:
        parse_hcs1_reference_v1(expected_hcs1)

    for raw_checksum in (
        request.expected_hcs1_sha256,
        request.expected_profile_sha256,
    ):
        checksum: object = raw_checksum
        if (
            checksum is not None
            and (
                not isinstance(checksum, str)
                or _SHA256_RE.fullmatch(checksum) is None
            )
        ):
            raise TypeError("HCS11_EXPECTED_SHA256_INVALID")

    expected_uaid: object = request.expected_uaid
    if expected_uaid is not None:
        parse_hcs14_did_uaid_v1(expected_uaid)

    expected_did: object = request.expected_base_did
    if (
        expected_did is not None
        and (
            not isinstance(expected_did, str)
            or not expected_did.strip()
            or len(expected_did) > 2048
        )
    ):
        raise TypeError("HCS11_EXPECTED_DID_INVALID")


def _output(
    request: Hcs11MirrorV1Request,
    *,
    status: Hcs11MirrorStatusV1,
    reason_code: str | None,
    account_memo: Hcs11V1Memo | None,
    registry_entry: Hcs11RegistryEntryV1 | None,
    profile_reference: str | None,
    content_sha256: str | None,
    canonical_profile_sha256: str | None,
    profile: Hcs11V1Profile | None,
    did_binding: Literal["match", "not_checked"],
) -> Hcs11MirrorV1Result:
    return Hcs11MirrorV1Result(
        status=status,
        reason_code=reason_code,
        hedera_network=request.hedera_network,
        account_id=request.account_id,
        resolver_id="hedera.mirror-rest.hcs11.v1",
        account_memo_temporal_scope="current_observation",
        account_memo=account_memo,
        registry_entry=registry_entry,
        profile_reference=profile_reference,
        content_sha256=content_sha256,
        canonical_profile_sha256=canonical_profile_sha256,
        profile=profile,
        did_binding=did_binding,
    )


async def resolve_hcs11_profile_v1(
    config: Hcs1MirrorV1Config,
    request: Hcs11MirrorV1Request,
    decode_options: Hcs1V1ContentOptions | None = None,
) -> Hcs11MirrorV1Result:
    """
    Resolve a current HCS-11 account memo and its pinned profile.

    An HCS-2 account memo requires a caller-selected historical sequence.
    Mirror observations are corroboration, not consensus authentication.
    """
    _checked_request(request)
    base = _base_url(config, request.hedera_network)
    bounds = _validated_limits(config)

    account_memo: Hcs11V1Memo | None = None
    registry_entry: Hcs11RegistryEntryV1 | None = None
    profile_reference: str | None = None
    content_sha256: str | None = None
    canonical_sha256: str | None = None
    profile: Hcs11V1Profile | None = None
    did_binding: Literal["match", "not_checked"] = "not_checked"

    def result(
        status: Hcs11MirrorStatusV1,
        reason_code: str | None,
    ) -> Hcs11MirrorV1Result:
        return _output(
            request,
            status=status,
            reason_code=reason_code,
            account_memo=account_memo,
            registry_entry=registry_entry,
            profile_reference=profile_reference,
            content_sha256=content_sha256,
            canonical_profile_sha256=canonical_sha256,
            profile=profile,
            did_binding=did_binding,
        )

    try:
        row = await _read_account(
            config,
            f"{base}/accounts/{request.account_id}",
            bounds,
        )
        if row is None:
            return result(
                "unavailable",
                "HCS11_ACCOUNT_NOT_FOUND",
            )
        if row.get("account") != request.account_id:
            return result(
                "invalid",
                "HCS11_ACCOUNT_SCOPE_MISMATCH",
            )
        if row.get("deleted") is True:
            return result(
                "unavailable",
                "HCS11_ACCOUNT_DELETED",
            )

        account_memo = _observed_account_memo(row)

        if (
            request.expected_profile_reference is not None
            and account_memo.profile_reference
            != request.expected_profile_reference
        ):
            return result(
                "conflict",
                "HCS11_ACCOUNT_REFERENCE_MISMATCH",
            )

        if account_memo.protocol == "hcs-2":
            sequence = request.hcs2_sequence_number
            if sequence is None:
                return result(
                    "unavailable",
                    "HCS11_HCS2_SEQUENCE_REQUIRED",
                )

            expected_topic: str | None = None
            if request.expected_hcs1_reference is not None:
                expected_topic = parse_hcs1_reference_v1(
                    request.expected_hcs1_reference
                ).topic_id

            registry = await resolve_hcs2_register_v1(
                config,
                Hcs2MirrorV1Request(
                    hedera_network=request.hedera_network,
                    registry_topic_id=account_memo.topic_id,
                    sequence_number=sequence,
                    expected_t_id=expected_topic,
                ),
            )

            if (
                registry.status != "resolved"
                or registry.verification is None
                or registry.verification.register is None
                or registry.consensus_timestamp is None
            ):
                if registry.status == "conflict":
                    mapped: Hcs11MirrorStatusV1 = "conflict"
                elif registry.status == "invalid":
                    mapped = "invalid"
                else:
                    mapped = "unavailable"

                return result(
                    mapped,
                    registry.reason_code
                    or "HCS11_HCS2_ENTRY_UNAVAILABLE",
                )

            registry_entry = Hcs11RegistryEntryV1(
                topic_id=account_memo.topic_id,
                sequence_number=sequence,
                consensus_timestamp=registry.consensus_timestamp,
            )
            profile_reference = (
                f"hcs://1/{registry.verification.register.t_id}"
            )

        else:
            if request.hcs2_sequence_number is not None:
                return result(
                    "invalid",
                    "HCS11_HCS2_SEQUENCE_NOT_APPLICABLE",
                )
            profile_reference = account_memo.profile_reference

        if (
            request.expected_hcs1_reference is not None
            and profile_reference != request.expected_hcs1_reference
        ):
            return result(
                "conflict",
                "HCS11_PROFILE_REFERENCE_MISMATCH",
            )

        assert profile_reference is not None

        hcs1 = await resolve_hcs1_file_v1(
            config,
            Hcs1MirrorV1Request(
                network=request.hedera_network,
                reference=profile_reference,
                expected_sha256=request.expected_hcs1_sha256,
            ),
            decode_options,
        )

        if (
            hcs1.status != "resolved"
            or hcs1.verification is None
            or hcs1.verification.bytes is None
            or hcs1.verification.sha256 is None
        ):
            if hcs1.reason_code == "HCS1_EXPECTED_CHECKSUM_MISMATCH":
                mapped_hcs1: Hcs11MirrorStatusV1 = "conflict"
            elif hcs1.reason_code == "HCS1_CHECKSUM_MISMATCH":
                mapped_hcs1 = "invalid"
            elif hcs1.status == "resolved":
                mapped_hcs1 = "unavailable"
            else:
                mapped_hcs1 = hcs1.status

            return result(
                mapped_hcs1,
                hcs1.reason_code
                or "HCS11_PROFILE_CONTENT_UNAVAILABLE",
            )

        content_sha256 = hcs1.verification.sha256

        offline = verify_hcs11_ai_agent_profile_v1(
            Hcs11V1Input(
                profile=hcs1.verification.bytes,
                expected_sha256=request.expected_profile_sha256,
                expected_uaid=request.expected_uaid,
                expected_base_did=request.expected_base_did,
                account_memo=account_memo.memo,
                expected_profile_reference=request.expected_profile_reference,
            )
        )

        profile = offline.profile
        canonical_sha256 = offline.sha256

        if offline.status != "pass":
            if offline.status == "unsupported":
                mapped_offline: Hcs11MirrorStatusV1 = "unsupported"
            elif (
                offline.reason_code
                in {
                    "HCS11_CHECKSUM_MISMATCH",
                    "HCS11_UAID_MISMATCH",
                    "HCS11_PROFILE_REFERENCE_MISMATCH",
                }
                or (
                    offline.reason_code is not None
                    and offline.reason_code.startswith("HCS14_")
                )
            ):
                mapped_offline = "conflict"
            else:
                mapped_offline = "invalid"

            return result(
                mapped_offline,
                offline.reason_code,
            )

        if profile is None or canonical_sha256 is None:
            return result(
                "invalid",
                "HCS11_PROFILE_CONTENT_UNAVAILABLE",
            )

        native_id = parse_hcs14_did_uaid_v1(
            profile.uaid
        ).params.get("nativeId")
        native_network = (
            _NATIVE_HEDERA_RE.fullmatch(native_id)
            if isinstance(native_id, str)
            else None
        )

        if (
            native_network is not None
            and native_network.group(1) != request.hedera_network
        ):
            return result(
                "conflict",
                "HCS11_UAID_NETWORK_MISMATCH",
            )

        if canonical_sha256 != content_sha256:
            return result(
                "unsupported",
                "HCS11_PROFILE_CONTENT_NOT_CANONICAL",
            )

        if request.expected_base_did is not None:
            did_binding = "match"

        return result("resolved", None)

    except _AccountReadError as exc:
        return result(
            "invalid" if exc.invalid else "unavailable",
            exc.code,
        )