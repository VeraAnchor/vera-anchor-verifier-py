"""Independent Hedera Mirror resolution for execution ledger targets."""

import base64
import binascii
import json
import math
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Literal, cast

from ..contracts import (
    HederaNetwork,
    VerificationFact,
    VerificationObservation,
    VerificationSubject,
)
from ..triangulation.execution_plan_v1 import (
    EXECUTION_HEDERA_OBSERVATION_V1_ID,
    ExecutionHederaTargetV1,
)
from .hedera_mirror_v1 import HederaMirrorV1Config, _default_fetch, _mirror_base

_TRANSACTION_RE = re.compile(
    r"^(0\.0\.\d+)[@-](\d{1,12})[.\-](\d{1,9})$", re.ASCII
)
_TOPIC_RE = re.compile(r"^0\.0\.\d+$", re.ASCII)
_BASE64_RE = re.compile(
    r"^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$",
    re.ASCII,
)
_TIMESTAMP_RE = re.compile(r"^\d{1,12}\.\d{1,9}$", re.ASCII)
_DIGITS_RE = re.compile(r"^\d+$", re.ASCII)

_MAX_RESPONSE_BYTES = 256 * 1024
_SHARED_MIRROR_DEFAULT_BYTES = 2 * 1024 * 1024
_MAX_TARGETS = 8
_MAX_TRANSACTION_ROWS = 32
_MAX_MESSAGE_BASE64_LENGTH = 1368
_MAX_SAFE_INTEGER = (1 << 53) - 1

type ExecutionMirrorStatusV1 = Literal["resolved", "unavailable", "conflict", "invalid"]
type _MirrorReadStatusV1 = Literal["found", "not_found", "unavailable", "invalid"]


@dataclass(frozen=True, slots=True)
class ExecutionMirrorV1Result:
    status: ExecutionMirrorStatusV1
    reason_code: str | None
    observation: VerificationObservation


@dataclass(frozen=True, slots=True)
class _MirrorReadV1:
    status: _MirrorReadStatusV1
    body: Mapping[str, object] | None


def _bound(value: object, minimum: int, maximum: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        raise TypeError("Invalid Mirror transport bounds")
    return value


def _response_limit(config: HederaMirrorV1Config) -> int:
    value = config.max_response_bytes
    if value == _SHARED_MIRROR_DEFAULT_BYTES:
        return _MAX_RESPONSE_BYTES
    return _bound(value, 1024, _MAX_RESPONSE_BYTES)


def _header(headers: Mapping[str, str], name: str) -> str | None:
    lowered = name.lower()
    for key, value in headers.items():
        if str(key).lower() == lowered:
            return str(value)
    return None


def _invalid_json_constant(value: str) -> None:
    raise ValueError(f"Invalid JSON constant: {value}")


async def _get(
    config: HederaMirrorV1Config,
    network: HederaNetwork,
    path: str,
) -> _MirrorReadV1:
    timeout = _bound(config.timeout_ms, 250, 15_000)
    maximum = _response_limit(config)
    endpoint = f"{_mirror_base(config, network)}/{path}"
    fetch = config.fetch_impl or _default_fetch

    try:
        response = await fetch(
            endpoint,
            {"Accept": "application/json"},
            timeout,
            maximum,
        )
    except Exception:
        return _MirrorReadV1("unavailable", None)

    if response.status == 404:
        return _MirrorReadV1("not_found", None)
    if not 200 <= response.status < 300:
        return _MirrorReadV1("unavailable", None)

    declared = _header(response.headers, "content-length")
    if declared and (
        _DIGITS_RE.fullmatch(declared) is None or int(declared) > maximum
    ):
        return _MirrorReadV1("invalid", None)
    if response.body is None or len(response.body) > maximum:
        return _MirrorReadV1("invalid", None)

    try:
        parsed = json.loads(
            response.body.decode("utf-8", errors="strict"),
            parse_constant=_invalid_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        return _MirrorReadV1("invalid", None)

    if type(parsed) is not dict:
        return _MirrorReadV1("invalid", None)
    return _MirrorReadV1("found", cast(dict[str, object], parsed))


def _record(value: object) -> Mapping[str, object] | None:
    return cast(Mapping[str, object], value) if isinstance(value, Mapping) else None


def _transaction(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    match = _TRANSACTION_RE.fullmatch(value)
    if match is None:
        return None
    return f"{match.group(1)}@{match.group(2)}.{match.group(3).zfill(9)}"


def _js_number(value: object) -> float:
    if value is None:
        return 0.0
    if isinstance(value, bool):
        return 1.0 if value else 0.0
    if isinstance(value, int | float):
        return float(value)
    if not isinstance(value, str):
        return math.nan

    raw = value.strip()
    if raw == "":
        return 0.0
    try:
        return float(raw)
    except ValueError:
        try:
            return float(int(raw, 0))
        except ValueError:
            return math.nan


def _js_string(value: object) -> str:
    if value is True:
        return "true"
    if value is False:
        return "false"
    if value is None:
        return "null"
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value)


def _sequence(value: object) -> int | None:
    number = _js_number(value)
    if (
        not math.isfinite(number)
        or not number.is_integer()
        or not 1 <= number <= _MAX_SAFE_INTEGER
    ):
        return None
    return int(number)


def _valid_base64(value: object) -> bool:
    if (
        not isinstance(value, str)
        or len(value) > _MAX_MESSAGE_BASE64_LENGTH
        or _BASE64_RE.fullmatch(value) is None
    ):
        return False
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return False
    return base64.b64encode(decoded).decode("ascii") == value


def _available(key: str, value: str) -> VerificationFact:
    return VerificationFact(key=key, state="available", value=value)


def _unavailable(key: str, reason_code: str) -> VerificationFact:
    return VerificationFact(key=key, state="unavailable", reason_code=reason_code)


def _observation(
    subject: VerificationSubject,
    facts: Sequence[VerificationFact],
) -> VerificationObservation:
    return VerificationObservation(
        id=EXECUTION_HEDERA_OBSERVATION_V1_ID,
        source="hedera_mirror",
        subject=cast(VerificationSubject, dict(subject)),
        resolver_id="hedera.execution-mirror.v1",
        facts=tuple(facts),
    )


def _validate_target(target: ExecutionHederaTargetV1, network: HederaNetwork) -> None:
    valid_source = target.source in ("provided_evidence", "public_record")
    valid_role = target.role in ("acceptance_anchor", "result_evidence_anchor")
    valid_prefix = (
        target.observation_fact_prefix == f"ledger.{target.source}.{target.role}"
    )
    valid_tx = (
        target.transaction_id is None
        or _transaction(target.transaction_id) == target.transaction_id
    )
    valid_topic = target.topic_id is None or (
        isinstance(target.topic_id, str)
        and _TOPIC_RE.fullmatch(target.topic_id) is not None
    )
    valid_sequence = target.sequence_number is None or (
        type(target.sequence_number) is int
        and 1 <= target.sequence_number <= _MAX_SAFE_INTEGER
    )
    paired_locator = (target.topic_id is None) == (target.sequence_number is None)
    has_locator = target.transaction_id is not None or target.topic_id is not None

    if (
        target.network != network
        or not valid_source
        or not valid_role
        or not valid_prefix
        or not valid_tx
        or not valid_topic
        or not valid_sequence
        or not paired_locator
        or not has_locator
    ):
        raise TypeError("Invalid scoped Hedera execution target")


def _degrade(
    current: ExecutionMirrorStatusV1,
    observed: _MirrorReadStatusV1,
) -> ExecutionMirrorStatusV1:
    if current == "conflict":
        return current
    if observed == "invalid":
        return "invalid"
    if current == "resolved":
        return "unavailable"
    return current


async def resolve_execution_hedera_v1(
    config: HederaMirrorV1Config,
    subject: VerificationSubject,
    targets: Sequence[ExecutionHederaTargetV1],
) -> ExecutionMirrorV1Result:
    network = subject.get("hedera_network")
    subject_id = subject.get("id")

    if (
        network not in ("mainnet", "testnet")
        or subject.get("kind") != "execution"
        or not isinstance(subject_id, str)
        or not subject_id
    ):
        raise TypeError("Invalid Hedera execution resolution scope")

    targets_value: object = targets
    if isinstance(targets_value, (str, bytes)) or not isinstance(
        targets_value, Sequence
    ):
        raise TypeError("Invalid Hedera execution resolution scope")

    target_items = cast(Sequence[object], targets_value)
    if len(target_items) > _MAX_TARGETS:
        raise TypeError("Invalid Hedera execution resolution scope")

    facts: list[VerificationFact] = []
    observed: set[str] = set()

    if not target_items:
        return ExecutionMirrorV1Result(
            status="unavailable",
            reason_code="MIRROR_LEDGER_TARGETS_MISSING",
            observation=_observation(subject, ()),
        )

    status: ExecutionMirrorStatusV1 = "resolved"
    reason: str | None = None

    for target in target_items:
        if not isinstance(target, ExecutionHederaTargetV1):
            raise TypeError("Invalid scoped Hedera execution target")

        _validate_target(target, network)
        prefix = target.observation_fact_prefix

        if prefix in observed:
            raise TypeError("Duplicate Hedera execution target")
        observed.add(prefix)

        if target.transaction_id is not None:
            match = _TRANSACTION_RE.fullmatch(target.transaction_id)
            if match is None:
                raise AssertionError("Validated transaction became invalid")

            resolved = await _get(
                config,
                network,
                f"transactions/{match.group(1)}-{match.group(2)}-{match.group(3)}",
            )
            key = f"{prefix}.transaction_id"

            if resolved.status == "found" and resolved.body is not None:
                rows = resolved.body.get("transactions")
                if type(rows) is not list or len(rows) > _MAX_TRANSACTION_ROWS:
                    facts.append(_unavailable(key, "MIRROR_RESPONSE_INVALID"))
                    if status != "conflict":
                        status = "invalid"
                    reason = reason or "MIRROR_RESPONSE_INVALID"
                else:
                    candidates: list[Mapping[str, object]] = []
                    for item in cast(list[object], rows):
                        row = _record(item)
                        if row is not None:
                            candidates.append(row)

                    exact = [
                        row
                        for row in candidates
                        if _transaction(row.get("transaction_id"))
                        == target.transaction_id
                    ]
                    if len(exact) != 1 or exact[0].get("result") != "SUCCESS":
                        facts.append(
                            _unavailable(key, "MIRROR_TRANSACTION_CONFLICT")
                        )
                        status = "conflict"
                        reason = "MIRROR_TRANSACTION_CONFLICT"
                    else:
                        actual = _transaction(exact[0].get("transaction_id"))
                        if actual is None:
                            raise AssertionError(
                                "Matched transaction was not canonical"
                            )
                        facts.append(_available(key, actual))
            else:
                code = f"MIRROR_TRANSACTION_{resolved.status.upper()}"
                facts.append(_unavailable(key, code))
                status = _degrade(status, resolved.status)
                reason = reason or code

        if target.topic_id is not None and target.sequence_number is not None:
            resolved = await _get(
                config,
                network,
                f"topics/{target.topic_id}/messages/{target.sequence_number}",
            )
            topic_key = f"{prefix}.topic_id"
            sequence_key = f"{prefix}.sequence_number"

            if resolved.status == "found" and resolved.body is not None:
                row = resolved.body
                row_topic = row.get("topic_id")
                raw_sequence = row.get("sequence_number")
                sequence = _sequence(raw_sequence)
                consensus = row.get("consensus_timestamp")
                message = row.get("message")

                valid = (
                    isinstance(row_topic, str)
                    and _TOPIC_RE.fullmatch(row_topic) is not None
                    and sequence is not None
                    and isinstance(consensus, str)
                    and _TIMESTAMP_RE.fullmatch(consensus) is not None
                    and _valid_base64(message)
                )

                if not valid:
                    facts.extend(
                        (
                            _unavailable(topic_key, "MIRROR_RESPONSE_INVALID"),
                            _unavailable(sequence_key, "MIRROR_RESPONSE_INVALID"),
                        )
                    )
                    if status != "conflict":
                        status = "invalid"
                    reason = reason or "MIRROR_RESPONSE_INVALID"
                else:
                    assert isinstance(row_topic, str)
                    facts.extend(
                        (
                            _available(topic_key, row_topic),
                            _available(sequence_key, _js_string(raw_sequence)),
                        )
                    )
                    if (
                        row_topic != target.topic_id
                        or sequence != target.sequence_number
                    ):
                        status = "conflict"
                        reason = "MIRROR_MESSAGE_SCOPE_MISMATCH"
            else:
                code = f"MIRROR_MESSAGE_{resolved.status.upper()}"
                facts.extend(
                    (
                        _unavailable(topic_key, code),
                        _unavailable(sequence_key, code),
                    )
                )
                status = _degrade(status, resolved.status)
                reason = reason or code

    return ExecutionMirrorV1Result(
        status=status,
        reason_code=reason,
        observation=_observation(subject, facts),
    )


__all__ = ["ExecutionMirrorV1Result", "resolve_execution_hedera_v1"]