"""Bounded Hedera Mirror resolution for exact HCS message observations."""

import asyncio
import base64
import binascii
import json
import math
import re
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Literal, cast
from urllib.error import HTTPError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from ..contracts import (
    HederaNetwork,
    VerificationFact,
    VerificationObservation,
    VerificationSubject,
)
from ..triangulation.message_observation_v1 import MirrorMessageV1Input, observe_mirror_message_v1
from .explorer_public_v1 import ExplorerPublicationV1

_DEFAULT_MIRROR: dict[HederaNetwork, str] = {
    "mainnet": "https://mainnet-public.mirrornode.hedera.com/api/v1",
    "testnet": "https://testnet.mirrornode.hedera.com/api/v1",
}
_DEFAULT_RESPONSE_BYTES = 2 * 1024 * 1024
_MAX_RESPONSE_BYTES = 4 * 1024 * 1024
_MAX_LOGICAL_BYTES = 1024 * 1024
_MAX_CHUNKS = 100
_MAX_SAFE_INTEGER = (1 << 53) - 1
_TOPIC_RE = re.compile(r"^0\.0\.[1-9][0-9]*$", re.ASCII)
_TRANSACTION_RE = re.compile(r"^(0\.0\.\d+)[@-](\d{1,12})[.\-](\d{1,9})$", re.ASCII)
_BASE64_RE = re.compile(
    r"^(?:[A-Za-z0-9+/]{4})*"
    r"(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$",
    re.ASCII,
)
_CONSENSUS_RE = re.compile(r"^\d{1,12}\.\d{1,9}$", re.ASCII)
_ACCOUNT_RE = re.compile(r"^0\.0\.\d+$", re.ASCII)

type HederaMessageStatusV1 = Literal["resolved", "unavailable", "invalid", "conflict"]


@dataclass(frozen=True, slots=True)
class HederaMirrorFetchResponseV1:
    status: int
    headers: Mapping[str, str]
    body: bytes | None


type HederaMirrorFetchImplV1 = Callable[
    [str, Mapping[str, str], int, int],
    Awaitable[HederaMirrorFetchResponseV1],
]


@dataclass(frozen=True, slots=True)
class HederaMirrorV1Config:
    base_urls: Mapping[HederaNetwork, str] | None = None
    fetch_impl: HederaMirrorFetchImplV1 | None = None
    timeout_ms: int = 8_000
    max_response_bytes: int = _DEFAULT_RESPONSE_BYTES


@dataclass(frozen=True, slots=True)
class HederaMessageLocatorV1:
    hedera_network: HederaNetwork
    topic_id: str
    sequence_number: int
    transaction_id: str | None = None


@dataclass(frozen=True, slots=True)
class HederaMessageObservationV1:
    status: HederaMessageStatusV1
    reason_code: str | None
    observation: VerificationObservation | None


type HederaPublicationObservationV1 = HederaMessageObservationV1


@dataclass(frozen=True, slots=True)
class _TopicRow:
    topic_id: str
    sequence_number: int
    consensus_timestamp: str
    bytes: bytes
    chunk_group: str | None
    chunk_number: int | None
    chunk_total: int | None


class _MirrorReadFailure(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


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


def _object(value: object) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise _MirrorReadFailure("MIRROR_RESPONSE_INVALID")
    return cast(Mapping[str, object], value)


def _required_string(value: object, maximum: int = 256) -> str:
    if (
        not isinstance(value, str)
        or not value
        or _js_length(value) > maximum
        or value.strip() != value
    ):
        raise _MirrorReadFailure("MIRROR_RESPONSE_INVALID")

    return value


def _number(value: object, *, allow_bool: bool = False) -> float:
    if isinstance(value, bool):
        if allow_bool:
            return 1.0 if value else 0.0
        return math.nan

    if isinstance(value, (int, float)):
        try:
            return float(value)
        except OverflowError:
            return math.nan

    if not isinstance(value, str):
        return math.nan

    normalized = value.strip()

    if not normalized:
        return 0.0

    lowered = normalized.lower()

    try:
        if lowered.startswith("0x") and len(normalized) > 2:
            return float(int(normalized[2:], 16))
        if lowered.startswith("0b") and len(normalized) > 2:
            return float(int(normalized[2:], 2))
        if lowered.startswith("0o") and len(normalized) > 2:
            return float(int(normalized[2:], 8))
        return float(normalized)
    except (ValueError, OverflowError):
        return math.nan


def _positive_integer(value: object) -> int:
    if not isinstance(value, (str, int, float)) or isinstance(value, bool):
        raise _MirrorReadFailure("MIRROR_RESPONSE_INVALID")
    if value == "":
        raise _MirrorReadFailure("MIRROR_RESPONSE_INVALID")

    number = _number(value)

    if (
        not math.isfinite(number)
        or not number.is_integer()
        or number < 1
        or number > _MAX_SAFE_INTEGER
    ):
        raise _MirrorReadFailure("MIRROR_RESPONSE_INVALID")

    return int(number)


def _transaction_id(value: str) -> str:
    match = _TRANSACTION_RE.fullmatch(value)

    if match is None:
        raise TypeError("Invalid Hedera transaction identifier")

    return f"{match.group(1)}@{match.group(2)}.{match.group(3).zfill(9)}"


def _number_string(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if value.is_integer():
            return str(int(value))
        return str(value)
    return str(value)


def _initial_transaction_id(value: object) -> str | None:
    if isinstance(value, str):
        try:
            return _transaction_id(value)
        except TypeError:
            return None

    if not isinstance(value, Mapping):
        return None

    raw = cast(Mapping[str, object], value)
    direct = (
        raw.get("transaction_id")
        if raw.get("transaction_id") is not None
        else raw.get("transactionId")
        if raw.get("transactionId") is not None
        else raw.get("transactionID")
    )

    if isinstance(direct, str):
        return _initial_transaction_id(direct)

    account = raw.get("account_id") if raw.get("account_id") is not None else raw.get("accountId")
    start = (
        raw.get("transaction_valid_start")
        if raw.get("transaction_valid_start") is not None
        else raw.get("transactionValidStart")
        if raw.get("transactionValidStart") is not None
        else raw.get("valid_start_timestamp")
    )

    if not isinstance(account, str) or _ACCOUNT_RE.fullmatch(account) is None:
        return None

    stamp: str | None = start if isinstance(start, str) else None

    if isinstance(start, Mapping):
        seconds = start.get("seconds")
        nanos = start.get("nanos")

        if isinstance(seconds, (str, int, float)) and isinstance(nanos, (str, int, float)):
            stamp = f"{_number_string(seconds)}.{_number_string(nanos).zfill(9)}"

    if stamp is None:
        return None

    try:
        identifier = _transaction_id(f"{account}@{stamp}")
    except TypeError:
        return None

    raw_nonce = raw.get("nonce")
    nonce_value = 0.0 if raw_nonce is None else _number(raw_nonce, allow_bool=True)

    if (
        not math.isfinite(nonce_value)
        or not nonce_value.is_integer()
        or nonce_value < 0
        or nonce_value > _MAX_SAFE_INTEGER
    ):
        return None

    nonce = int(nonce_value)
    mode = "scheduled" if raw.get("scheduled") is True else "direct"

    return f"{identifier}#{nonce}#{mode}"


def _topic_row(value: object, topic: str, sequence: int | None = None) -> _TopicRow:
    row = _object(value)

    if row.get("topic_id") != topic:
        raise _MirrorReadFailure("MIRROR_MESSAGE_SCOPE_INVALID")

    sequence_number = _positive_integer(row.get("sequence_number"))

    if sequence is not None and sequence_number != sequence:
        raise _MirrorReadFailure("MIRROR_MESSAGE_SCOPE_INVALID")

    consensus_timestamp = _required_string(row.get("consensus_timestamp"), 64)

    if _CONSENSUS_RE.fullmatch(consensus_timestamp) is None:
        raise _MirrorReadFailure("MIRROR_RESPONSE_INVALID")

    encoded = _required_string(row.get("message"), _MAX_RESPONSE_BYTES * 2)

    if _BASE64_RE.fullmatch(encoded) is None:
        raise _MirrorReadFailure("MIRROR_RESPONSE_INVALID")

    try:
        decoded = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError):
        raise _MirrorReadFailure("MIRROR_RESPONSE_INVALID") from None

    if base64.b64encode(decoded).decode("ascii") != encoded or len(decoded) > _MAX_LOGICAL_BYTES:
        raise _MirrorReadFailure("MIRROR_RESPONSE_INVALID")

    chunk_info = row.get("chunk_info")

    if chunk_info is None:
        return _TopicRow(
            topic_id=topic,
            sequence_number=sequence_number,
            consensus_timestamp=consensus_timestamp,
            bytes=decoded,
            chunk_group=None,
            chunk_number=None,
            chunk_total=None,
        )

    chunk = _object(chunk_info)
    chunk_number = _positive_integer(chunk.get("number"))
    chunk_total = _positive_integer(chunk.get("total"))
    chunk_group = _initial_transaction_id(
        (
            chunk.get("initial_transaction_id")
            if chunk.get("initial_transaction_id") is not None
            else chunk.get("initialTransactionId")
        ),
    )

    if chunk_group is None or chunk_total > _MAX_CHUNKS or chunk_number > chunk_total:
        raise _MirrorReadFailure("MIRROR_RESPONSE_INVALID")

    return _TopicRow(
        topic_id=topic,
        sequence_number=sequence_number,
        consensus_timestamp=consensus_timestamp,
        bytes=decoded,
        chunk_group=chunk_group,
        chunk_number=chunk_number,
        chunk_total=chunk_total,
    )


def _mirror_base(config: HederaMirrorV1Config, network: HederaNetwork) -> str:
    raw = (
        config.base_urls.get(network)
        if config.base_urls is not None and network in config.base_urls
        else _DEFAULT_MIRROR[network]
    )

    if not isinstance(raw, str):
        raise TypeError("Invalid Mirror base URL")

    try:
        parsed = urlsplit(raw)
        port = parsed.port
    except ValueError as exc:
        raise TypeError("Invalid Mirror base URL") from exc

    hostname = parsed.hostname

    if hostname is None:
        raise TypeError("Mirror requires a fixed HTTPS /api/v1 endpoint (or HTTP loopback)")

    local = hostname in {"localhost", "127.0.0.1", "::1"}

    if (
        parsed.scheme not in {"http", "https"}
        or (parsed.scheme != "https" and not (parsed.scheme == "http" and local))
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or not parsed.path.rstrip("/").endswith("/api/v1")
    ):
        raise TypeError("Mirror requires a fixed HTTPS /api/v1 endpoint (or HTTP loopback)")

    host = f"[{hostname}]" if ":" in hostname else hostname
    authority = f"{host}:{port}" if port is not None else host
    path = parsed.path.rstrip("/")

    return f"{parsed.scheme}://{authority}{path}"


def _safe_bound(value: object, *, minimum: int, maximum: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < minimum
        or value > maximum
    ):
        raise TypeError("Invalid Mirror request bounds")

    return value


def _headers(value: Mapping[str, str]) -> dict[str, str]:
    return {str(key).lower(): str(item) for key, item in value.items()}


def _read_bounded(response: object, maximum: int) -> bytes:
    parts: list[bytes] = []
    total = 0

    while total <= maximum:
        remaining = maximum + 1 - total
        chunk = response.read(min(64 * 1024, remaining))  # type: ignore[attr-defined]

        if not chunk:
            break
        if not isinstance(chunk, bytes):
            raise OSError("Invalid Mirror response body")

        parts.append(chunk)
        total += len(chunk)

    return b"".join(parts)


def _default_fetch_sync(
    url: str,
    headers: Mapping[str, str],
    timeout_ms: int,
    max_response_bytes: int,
) -> HederaMirrorFetchResponseV1:
    request = Request(url, headers=dict(headers), method="GET")
    opener = build_opener(_NoRedirect())

    try:
        with opener.open(request, timeout=timeout_ms / 1000) as response:
            response_headers = {
                key.lower(): value
                for key, value in response.headers.items()
            }
            declared = response_headers.get("content-length")

            if declared is not None:
                try:
                    if int(declared) > max_response_bytes:
                        return HederaMirrorFetchResponseV1(
                            status=int(response.getcode()),
                            headers=response_headers,
                            body=b"x" * (max_response_bytes + 1),
                        )
                except ValueError:
                    pass

            return HederaMirrorFetchResponseV1(
                status=int(response.getcode()),
                headers=response_headers,
                body=_read_bounded(response, max_response_bytes),
            )

    except HTTPError as exc:
        response_headers = (
            {}
            if exc.headers is None
            else {key.lower(): value for key, value in exc.headers.items()}
        )
        return HederaMirrorFetchResponseV1(
            status=exc.code,
            headers=response_headers,
            body=b"",
        )


async def _default_fetch(
    url: str,
    headers: Mapping[str, str],
    timeout_ms: int,
    max_response_bytes: int,
) -> HederaMirrorFetchResponseV1:
    return await asyncio.to_thread(
        _default_fetch_sync,
        url,
        headers,
        timeout_ms,
        max_response_bytes,
    )


def _invalid_json_constant(value: str) -> None:
    raise ValueError(f"Invalid JSON constant: {value}")


async def _read(
    config: HederaMirrorV1Config,
    network: HederaNetwork,
    path: str,
) -> dict[str, object] | None:
    timeout = _safe_bound(config.timeout_ms, minimum=250, maximum=15_000)
    maximum = _safe_bound(
        config.max_response_bytes,
        minimum=1024,
        maximum=_MAX_RESPONSE_BYTES,
    )
    base = _mirror_base(config, network)
    endpoint = f"{base}/{path}"
    base_url = urlsplit(base)
    resolved = urlsplit(endpoint)
    base_path = base_url.path.rstrip("/")

    if (
        resolved.scheme != base_url.scheme
        or resolved.hostname != base_url.hostname
        or resolved.port != base_url.port
        or not resolved.path.startswith(f"{base_path}/")
    ):
        raise TypeError("Mirror path escaped configured endpoint")

    fetch = config.fetch_impl or _default_fetch

    try:
        response = await fetch(
            endpoint,
            {"Accept": "application/json"},
            timeout,
            maximum,
        )
    except Exception:
        raise _MirrorReadFailure("MIRROR_TRANSPORT_UNAVAILABLE") from None

    if response.status == 404:
        return None
    if response.status == 429:
        raise _MirrorReadFailure("MIRROR_RATE_LIMITED")
    if not 200 <= response.status < 300:
        raise _MirrorReadFailure("MIRROR_HTTP_UNAVAILABLE")

    response_headers = _headers(response.headers)
    declared = response_headers.get("content-length")

    if declared is not None:
        try:
            if int(declared) > maximum:
                raise _MirrorReadFailure("MIRROR_RESPONSE_TOO_LARGE")
        except ValueError:
            pass

    if response.body is None:
        raise _MirrorReadFailure("MIRROR_RESPONSE_INVALID")
    if len(response.body) > maximum:
        raise _MirrorReadFailure("MIRROR_RESPONSE_TOO_LARGE")

    try:
        text = response.body.decode("utf-8", errors="strict")
        parsed = json.loads(text, parse_constant=_invalid_json_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise _MirrorReadFailure("MIRROR_RESPONSE_INVALID") from None

    if type(parsed) is not dict:
        raise _MirrorReadFailure("MIRROR_RESPONSE_INVALID")

    return cast(dict[str, object], parsed)


async def _reassembled(
    config: HederaMirrorV1Config,
    network: HederaNetwork,
    topic: str,
    first: _TopicRow,
) -> bytes:
    if first.chunk_total is None or first.chunk_total == 1:
        return first.bytes

    async def scan(direction: Literal["before", "after"]) -> list[_TopicRow]:
        parameters = urlencode(
            {
                "order": "desc" if direction == "before" else "asc",
                "limit": "100",
                "timestamp": (
                    ("lte:" if direction == "before" else "gte:")
                    + first.consensus_timestamp
                ),
            },
        )
        result = await _read(config, network, f"topics/{topic}/messages?{parameters}")

        if result is None:
            raise _MirrorReadFailure("MIRROR_MESSAGE_REASSEMBLY_UNAVAILABLE")

        messages = result.get("messages")

        if type(messages) is not list or len(messages) > 100:
            raise _MirrorReadFailure("MIRROR_MESSAGE_REASSEMBLY_UNAVAILABLE")

        return [_topic_row(item, topic) for item in cast(list[object], messages)]

    tasks: list[Awaitable[list[_TopicRow]]] = []

    if first.chunk_number is not None and first.chunk_number > 1:
        tasks.append(scan("before"))
    if first.chunk_number is not None and first.chunk_number < first.chunk_total:
        tasks.append(scan("after"))

    windows = await asyncio.gather(*tasks) if tasks else []
    unique: dict[int, _TopicRow] = {first.sequence_number: first}

    for window in windows:
        for chunk in window:
            existing = unique.get(chunk.sequence_number)

            if (
                existing is not None
                and (
                    existing.chunk_number != chunk.chunk_number
                    or existing.bytes != chunk.bytes
                )
            ):
                raise _MirrorReadFailure("MIRROR_RESPONSE_INVALID")

            unique[chunk.sequence_number] = chunk

    by_number: dict[int, _TopicRow] = {}

    for chunk in unique.values():
        if chunk.chunk_group != first.chunk_group:
            continue
        if chunk.chunk_total != first.chunk_total or chunk.chunk_number is None:
            raise _MirrorReadFailure("MIRROR_RESPONSE_INVALID")
        if chunk.chunk_number in by_number:
            raise _MirrorReadFailure("MIRROR_RESPONSE_INVALID")

        by_number[chunk.chunk_number] = chunk

    if len(by_number) != first.chunk_total:
        raise _MirrorReadFailure("MIRROR_MESSAGE_REASSEMBLY_UNAVAILABLE")

    parts: list[bytes] = []
    total = 0

    for number in range(1, first.chunk_total + 1):
        part = by_number.get(number)

        if part is None:
            raise _MirrorReadFailure("MIRROR_MESSAGE_REASSEMBLY_UNAVAILABLE")

        total += len(part.bytes)

        if total > _MAX_LOGICAL_BYTES:
            raise _MirrorReadFailure("MIRROR_MESSAGE_TOO_LARGE")

        parts.append(part.bytes)

    return b"".join(parts)


def _output(
    status: HederaMessageStatusV1,
    reason: str,
) -> HederaMessageObservationV1:
    return HederaMessageObservationV1(
        status=status,
        reason_code=reason,
        observation=None,
    )


def _valid_locator(
    locator: HederaMessageLocatorV1,
    subject: VerificationSubject,
) -> bool:
    return (
        locator.hedera_network in ("mainnet", "testnet")
        and subject.get("hedera_network") == locator.hedera_network
        and bool(subject.get("id"))
        and _TOPIC_RE.fullmatch(locator.topic_id) is not None
        and isinstance(locator.sequence_number, int)
        and not isinstance(locator.sequence_number, bool)
        and 1 <= locator.sequence_number <= _MAX_SAFE_INTEGER
    )


async def resolve_hedera_message_v1(
    config: HederaMirrorV1Config,
    locator: HederaMessageLocatorV1,
    subject: VerificationSubject,
) -> HederaMessageObservationV1:
    """Resolve and independently hash an explicitly scoped HCS message."""
    if not _valid_locator(locator, subject):
        return _output("unavailable", "MIRROR_MESSAGE_LOCATOR_UNAVAILABLE")

    network = locator.hedera_network
    topic = locator.topic_id
    sequence = locator.sequence_number

    try:
        reply = await _read(config, network, f"topics/{topic}/messages/{sequence}")

        if reply is None:
            return _output("unavailable", "MIRROR_MESSAGE_NOT_FOUND")

        first = _topic_row(reply, topic, sequence)
        message_bytes = await _reassembled(config, network, topic, first)
        transaction: str | None = None
        transaction_consensus: str | None = None

        if locator.transaction_id:
            transaction = _transaction_id(locator.transaction_id)
            transaction_path = re.sub(r"@(\d+)\.", r"-\1-", transaction, count=1)
            transaction_reply = await _read(
                config,
                network,
                f"transactions/{transaction_path}",
            )

            if transaction_reply is None:
                return _output("unavailable", "MIRROR_TRANSACTION_NOT_FOUND")

            transactions = transaction_reply.get("transactions")

            if type(transactions) is not list:
                raise _MirrorReadFailure("MIRROR_RESPONSE_INVALID")

            matching: list[Mapping[str, object]] = []

            for item in cast(list[object], transactions):
                if not isinstance(item, Mapping):
                    continue

                raw_transaction = item.get("transaction_id")
                candidate = "" if raw_transaction is None else str(raw_transaction)

                try:
                    if _transaction_id(candidate) == transaction:
                        matching.append(cast(Mapping[str, object], item))
                except TypeError:
                    continue

            if len(matching) != 1:
                raise _MirrorReadFailure("MIRROR_RESPONSE_INVALID")

            resolved = matching[0]
            result = _required_string(resolved.get("result"), 64).upper()

            if result != "SUCCESS":
                return _output("conflict", "MIRROR_TRANSACTION_FAILED")

            raw_consensus = resolved.get("consensus_timestamp")

            if raw_consensus is not None:
                transaction_consensus = _required_string(raw_consensus, 64)

                if _CONSENSUS_RE.fullmatch(transaction_consensus) is None:
                    raise _MirrorReadFailure("MIRROR_RESPONSE_INVALID")

        original = observe_mirror_message_v1(
            MirrorMessageV1Input(
                id=f"{subject['kind']}.hedera_mirror",
                subject=subject,
                topic_id=topic,
                sequence_number=sequence,
                message_bytes=message_bytes,
            ),
        )

        additional = [
            VerificationFact(
                key="hedera.consensus_timestamp_exact",
                state="available",
                value=first.consensus_timestamp,
            ),
        ]

        if transaction is not None:
            additional.append(
                VerificationFact(
                    key="hedera.transaction_id",
                    state="available",
                    value=transaction,
                ),
            )

        if transaction_consensus is not None:
            additional.append(
                VerificationFact(
                    key="hedera.transaction_consensus_timestamp_exact",
                    state="available",
                    value=transaction_consensus,
                ),
            )

        observation = VerificationObservation(
            id=original.id,
            subject=original.subject,
            source=original.source,
            resolver_id="hedera.mirror-rest.v1",
            facts=(*original.facts, *additional),
        )

        return HederaMessageObservationV1(
            status="resolved",
            reason_code=None,
            observation=observation,
        )

    except _MirrorReadFailure as exc:
        return _output("unavailable", exc.code)
    except TypeError:
        return _output("invalid", "MIRROR_REFERENCE_INVALID")


async def resolve_hedera_publication_v1(
    config: HederaMirrorV1Config,
    publication: ExplorerPublicationV1 | None,
    subject: VerificationSubject,
) -> HederaPublicationObservationV1:
    """Resolve a normalized Explorer publication through Hedera Mirror."""
    if publication is None:
        return _output("unavailable", "MIRROR_MESSAGE_LOCATOR_UNAVAILABLE")

    return await resolve_hedera_message_v1(
        config,
        HederaMessageLocatorV1(
            hedera_network=publication.hedera_network,
            topic_id=publication.topic_id or "",
            sequence_number=publication.sequence_number or 0,
            transaction_id=publication.transaction_id,
        ),
        subject,
    )