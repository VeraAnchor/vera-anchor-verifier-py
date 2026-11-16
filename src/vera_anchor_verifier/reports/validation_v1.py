"""Validate and compare saved portable verification reports."""

import json
import math
import re
from dataclasses import dataclass
from typing import Literal, cast

from ..contracts import EvidenceConsistency, VerificationOutcome, VerificationReport
from ..crypto.sha3 import sha3_512_hex
from .core_v1 import (
    _json_stringify,
    canonicalize_verification_core_v1,
    compute_verification_core_digest_v1,
)
from .portable_v1 import PORTABLE_VERIFICATION_REPORT_SCHEMA_VERSION, PortableVerificationReportV1

_DOMAIN = "va:portable-verification-report:v1"
_MAX_BYTES = 1024 * 1024
_MAX_DEPTH = 32
_MAX_NODES = 65_536

_DIGEST_RE = re.compile(r"^[0-9a-f]{128}$", re.ASCII)
_ID_RE = re.compile(r"^[a-z][a-z0-9._:-]{0,159}$", re.ASCII)
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE | re.ASCII,
)
_TOPIC_RE = re.compile(r"^0\.0\.[0-9]+$", re.ASCII)
_TRANSACTION_RE = re.compile(
    r"^0\.0\.[0-9]+@[0-9]{1,12}\.[0-9]{9}$",
    re.ASCII,
)
_MAX_SAFE_INTEGER = (1 << 53) - 1
_KINDS = {
    "verification",
    "execution",
    "independent_standards",
    "public_triangulation",
    "authorized_dataset_triangulation",
    "authorized_ingest_triangulation",
    "execution_triangulation",
}
_OUTCOMES = {
    "pass",
    "fail",
    "indeterminate",
    "unsupported",
    "skipped",
}
_PUBLIC_RELATIONSHIPS = {
    "provided_public_record",
    "public_record_hedera",
    "provided_hedera",
}
_AUTHORIZED_RELATIONSHIPS = {
    "provided_authorized",
    "authorized_hedera",
}
_PUBLIC_RECORD_STATUSES = {
    "resolved",
    "not_found",
    "unavailable",
    "invalid",
    "conflict",
}
_PUBLIC_DISCLOSURE_STATUSES = {
    "resolved",
    "unavailable",
    "invalid",
    "conflict",
    "unsupported",
}
_PUBLIC_MIRROR_STATUSES = {
    "resolved",
    "unavailable",
    "invalid",
    "conflict",
    "not_requested",
}
_AUTHORIZED_CORE_STATUSES = {
    "resolved",
    "unauthorized",
    "forbidden",
    "not_found",
    "rate_limited",
    "unavailable",
    "invalid",
}
_AUTHORIZED_MIRROR_STATUSES = {
    "resolved",
    "unavailable",
    "invalid",
    "conflict",
    "not_requested",
    "not_resolved",
    "locator_unavailable",
}
_AUTHORIZED_PROFILE_STATUSES = {
    "resolved",
    "unavailable",
    "unsupported",
    "invalid",
    "conflict",
}
_EXECUTION_RESOLUTION_STATUSES = {
    "resolved",
    "not_found",
    "unavailable",
    "invalid",
    "conflict",
    "verification_material_unavailable",
    "unsupported",
}
_STANDARDS_ITEM_STATUSES = {
    "resolved",
    "conflict",
    "invalid",
    "unavailable",
    "unsupported",
}
_STANDARDS_STATUSES = {
    "verified",
    "failed",
    "unavailable",
    "not_performed",
}
_STANDARDS_ASSURANCE = {
    "mirror_corroborated",
    "not_established",
}

type Json = None | str | int | float | bool | list[Json] | dict[str, Json]
type Row = dict[str, Json]

type PortableVerificationReportValidationReasonV1 = Literal[
    "PORTABLE_REPORT_INVALID",
    "PORTABLE_CORE_DIGEST_MISMATCH",
    "PORTABLE_REPORT_DIGEST_MISMATCH",
]

type PortableVerificationReportDifferenceV1 = Literal[
    "kind",
    "subject",
    "intent",
    "findings",
    "observations",
    "context",
]


@dataclass(frozen=True, slots=True)
class PortableVerificationReportValidationV1:
    status: Literal["valid", "invalid"]
    reason_code: PortableVerificationReportValidationReasonV1 | None
    authenticity: Literal["not_checked"] = "not_checked"
    evidence_recomputation: Literal["not_performed"] = "not_performed"


@dataclass(frozen=True, slots=True)
class PortableVerificationReportComparisonV1:
    status: Literal["equivalent", "different"]
    differences: tuple[PortableVerificationReportDifferenceV1, ...]
    authenticity: Literal["not_checked"] = "not_checked"
    evidence_recomputation: Literal["not_performed"] = "not_performed"


@dataclass(frozen=True, slots=True)
class _Checked:
    kind: str
    core: Row
    context: Row
    serialized: str


class _DigestError(Exception):
    def __init__(
        self,
        code: Literal[
            "PORTABLE_CORE_DIGEST_MISMATCH",
            "PORTABLE_REPORT_DIGEST_MISMATCH",
        ],
    ) -> None:
        super().__init__(code)
        self.code = code


_MISSING = object()


def _js_length(value: str) -> int:
    return len(value.encode("utf-16-le", "surrogatepass")) // 2


def _js_sort_key(value: str) -> tuple[int, ...]:
    encoded = value.encode("utf-16-be", "surrogatepass")
    return tuple(
        int.from_bytes(encoded[index : index + 2], "big")
        for index in range(0, len(encoded), 2)
    )


def _top_level(value: object) -> dict[str, object]:
    if isinstance(value, PortableVerificationReportV1):
        return {
            "schema_version": value.schema_version,
            "kind": value.kind,
            "core_sha3_512": value.core_sha3_512,
            "report_sha3_512": value.report_sha3_512,
            "core": value.core,
            "context": value.context,
        }

    if type(value) is not dict:
        raise TypeError("Invalid portable report")

    row = cast(dict[object, object], value)

    if not all(isinstance(key, str) for key in row):
        raise TypeError("Invalid portable report")

    return cast(dict[str, object], row)


def _clone_json(value: object) -> Json:
    nodes = 0
    ancestors: set[int] = set()

    def visit(entry: object, depth: int) -> Json:
        nonlocal nodes

        nodes += 1

        if nodes > _MAX_NODES or depth > _MAX_DEPTH:
            raise ValueError("Portable report exceeds resource limit")

        if entry is None or isinstance(entry, bool):
            return entry

        if isinstance(entry, int):
            return entry

        if isinstance(entry, float):
            if (
                not math.isfinite(entry)
                or entry == 0.0
                and math.copysign(1.0, entry) < 0
            ):
                raise TypeError("Invalid portable report number")

            return entry

        if isinstance(entry, str):
            if _js_length(entry) > _MAX_BYTES:
                raise TypeError("Invalid portable report string")

            try:
                return entry.encode(
                    "utf-16-le",
                    "surrogatepass",
                ).decode(
                    "utf-16-le",
                    "strict",
                )
            except UnicodeDecodeError as exc:
                raise TypeError("Invalid portable report string") from exc

        entry_id = id(entry)

        if entry_id in ancestors:
            raise TypeError("Cyclic portable report")

        if isinstance(entry, list):
            if len(entry) > 512:
                raise ValueError("Portable report array exceeds limit")

            ancestors.add(entry_id)

            try:
                return [
                    visit(item, depth + 1)
                    for item in entry
                ]
            finally:
                ancestors.remove(entry_id)

        if type(entry) is not dict:
            raise TypeError("Invalid portable report JSON value")

        row = cast(dict[object, object], entry)

        if (
            len(row) > 512
            or not all(isinstance(key, str) for key in row)
        ):
            raise ValueError("Portable report object exceeds limit")

        ancestors.add(entry_id)

        try:
            result: Row = {}

            for raw_key in sorted(
                row,
                key=lambda item: _js_sort_key(cast(str, item)),
            ):
                key = cast(str, raw_key)

                if (
                    not key
                    or _js_length(key) > 160
                    or any(
                        ord(character) < 0x20
                        or ord(character) == 0x7F
                        for character in key
                    )
                ):
                    raise TypeError("Invalid portable report field")

                result[key] = visit(row[raw_key], depth + 1)

            return result

        finally:
            ancestors.remove(entry_id)

    copy = visit(value, 0)

    if len(_json_stringify(copy).encode("utf-8")) > _MAX_BYTES + 256:
        raise ValueError("Portable report exceeds size limit")

    return copy


def _object(value: Json, name: str) -> Row:
    if not isinstance(value, dict):
        raise TypeError(f"Invalid {name}")

    return value


def _shape(
    value: Json,
    name: str,
    keys: set[str],
) -> Row:
    row = _object(value, name)

    if set(row) != keys:
        raise TypeError(f"Invalid {name} fields")

    return row


def _array(
    value: Json,
    name: str,
    limit: int,
) -> list[Json]:
    if not isinstance(value, list) or len(value) > limit:
        raise TypeError(f"Invalid {name}")

    return value


def _string(
    value: Json,
    name: str,
    maximum: int = 256,
) -> str:
    if (
        not isinstance(value, str)
        or not value
        or _js_length(value) > maximum
        or value.strip() != value
    ):
        raise TypeError(f"Invalid {name}")

    return value


def _maybe_string(
    value: Json,
    name: str,
    maximum: int = 256,
) -> None:
    if value is not None:
        _string(value, name, maximum)


def _one_of(
    value: Json,
    name: str,
    allowed: set[str],
) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise TypeError(f"Invalid {name}")

    return value


def _identifier(value: Json, name: str) -> str:
    result = _string(value, name, 160)

    if _ID_RE.fullmatch(result) is None:
        raise TypeError(f"Invalid {name}")

    return result


def _hash(value: Json, name: str) -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise TypeError(f"Invalid {name}")

    return value


def _sha256(value: Json, name: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise TypeError(f"Invalid {name}")
    return value


def _safe_integer(value: Json) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        number = value
    elif isinstance(value, float) and math.isfinite(value) and value.is_integer():
        number = int(value)
    else:
        return None
    return number if 0 <= number <= _MAX_SAFE_INTEGER else None


def _subject(core: Row) -> Row:
    intent = _object(core["intent"], "verification intent")
    return _object(intent["subject"], "verification subject")


def _finding(
    core: Row,
    check_id: str,
    outcome: VerificationOutcome,
    reason: Json | object = _MISSING,
) -> None:
    findings = _array(core["findings"], "findings", 512)
    match: Row | None = None

    for value in findings:
        row = _object(value, "finding")

        if row.get("check_id") == check_id:
            match = row
            break

    if (
        match is None
        or match.get("outcome") != outcome
        or (
            reason is not _MISSING
            and match.get("reason_code") != reason
        )
    ):
        raise TypeError(f"Inconsistent portable finding: {check_id}")
    

def _has_finding(core: Row, check_id: str) -> bool:
    return any(
        _object(value, "finding").get("check_id") == check_id
        for value in _array(core["findings"], "findings", 512)
    )


def _scope(value: Json, core: Row) -> None:
    row = _shape(
        value,
        "execution scope",
        {"profile", "expected_program", "requested_result_id"},
    )
    subject = _subject(core)
    if subject.get("kind") != "execution" or subject.get("hedera_network") not in (
        "mainnet",
        "testnet",
    ):
        raise TypeError("Invalid execution report subject")

    profile = _one_of(
        row["profile"],
        "execution profile",
        {"execution-v1", "sage-standards-v1"},
    )
    _maybe_string(row["expected_program"], "expected program", 128)

    requested_result_id = row["requested_result_id"]
    if requested_result_id is not None:
        result_id = _string(requested_result_id, "result ID", 64)
        if _UUID_RE.fullmatch(result_id) is None:
            raise TypeError("Invalid result ID")
        if not _has_finding(core, "intent.result"):
            raise TypeError("Missing result-scope finding")

    if profile == "execution-v1" and row["expected_program"] is None:
        raise TypeError("Generic execution requires an expected program")


def _standards(value: Json, core: Row) -> None:
    row = _shape(
        value,
        "independent standards",
        {"network", "status", "assurance", "items"},
    )
    if row["network"] != _subject(core).get("hedera_network"):
        raise TypeError("Standards network mismatch")

    state = _one_of(
        row["status"],
        "standards status",
        _STANDARDS_STATUSES,
    )
    assurance = _one_of(
        row["assurance"],
        "standards assurance",
        _STANDARDS_ASSURANCE,
    )
    items = _array(row["items"], "standards items", 16)
    seen: set[str] = set()
    any_failed = False
    all_resolved = bool(items)

    for index, item in enumerate(items):
        part = _shape(
            item,
            "standards item",
            {
                "key",
                "standard",
                "reference",
                "status",
                "reason_code",
                "resolver_id",
                "historical_consensus_timestamps_exact",
                "current_topic_or_account_memo_observed",
                "content_sha256",
                "assurance",
            },
        )
        key = _string(part["key"], "standards key")
        if key in seen:
            raise TypeError("Duplicate standards key")
        seen.add(key)

        _string(part["standard"], "standard", 128)
        _string(part["reference"], "standards reference", 256)
        _maybe_string(part["reason_code"], "standards reason", 160)
        _maybe_string(part["resolver_id"], "resolver ID", 256)

        if not isinstance(
            part["current_topic_or_account_memo_observed"],
            bool,
        ):
            raise TypeError("Invalid memo observation")
        if part["content_sha256"] is not None:
            _sha256(
                part["content_sha256"],
                "standards content digest",
            )

        status = _one_of(
            part["status"],
            "standards item status",
            _STANDARDS_ITEM_STATUSES,
        )
        for timestamp in _array(
            part["historical_consensus_timestamps_exact"],
            "historical timestamps",
            16,
        ):
            _string(timestamp, "historical timestamp", 128)

        expected_assurance = (
            "mirror_corroborated"
            if status == "resolved"
            else "not_established"
        )
        if part["assurance"] != expected_assurance:
            raise TypeError("Inconsistent standards assurance")

        any_failed = any_failed or status in ("conflict", "invalid")
        all_resolved = all_resolved and status == "resolved"

        outcome: VerificationOutcome = (
            "pass"
            if status == "resolved"
            else "fail"
            if status in ("conflict", "invalid")
            else "unsupported"
            if status == "unsupported"
            else "indeterminate"
        )
        _finding(
            core,
            f"standards.reference.{index}",
            outcome,
        )

    expected_state = (
        "failed"
        if any_failed
        else "verified"
        if all_resolved
        else "not_performed"
        if not items
        else "unavailable"
    )
    expected_assurance = (
        "mirror_corroborated"
        if state == "verified"
        else "not_established"
    )

    if state != expected_state or assurance != expected_assurance:
        raise TypeError("Inconsistent standards summary")

    summary_outcome: VerificationOutcome = (
        "pass"
        if state == "verified"
        else "fail"
        if state == "failed"
        else "indeterminate"
    )
    _finding(
        core,
        "standards.references_resolved",
        summary_outcome,
    )


def _relationships(
    value: Json,
    core: Row,
    allowed_ids: set[str],
) -> list[Json]:
    entries = _array(value, "triangulation relationships", 3)
    seen: set[str] = set()

    for value in entries:
        relationship = _shape(
            value,
            "triangulation relationship",
            {"id", "status", "fact_comparisons"},
        )
        relationship_id = _one_of(
            relationship["id"],
            "triangulation relationship ID",
            allowed_ids,
        )

        if relationship_id in seen:
            raise TypeError("Duplicate triangulation relationship")

        seen.add(relationship_id)

        state = _one_of(
            relationship["status"],
            "relationship status",
            {"consistent", "conflict", "incomplete", "not_applicable"},
        )
        comparisons = _array(
            relationship["fact_comparisons"],
            "fact comparisons",
            64,
        )
        keys: set[str] = set()
        outcomes: list[VerificationOutcome] = []

        for value in comparisons:
            comparison = _shape(
                value,
                "fact comparison",
                {"key", "outcome", "reason_code"},
            )
            key = _identifier(comparison["key"], "comparison key")

            if key in keys:
                raise TypeError("Duplicate comparison key")

            keys.add(key)

            outcome = cast(
                VerificationOutcome,
                _one_of(
                    comparison["outcome"],
                    "comparison outcome",
                    _OUTCOMES,
                ),
            )
            reason = comparison["reason_code"]

            if reason is not None:
                _string(reason, "comparison reason", 160)

            outcomes.append(outcome)
            _finding(
                core,
                f"triangulation.{relationship_id}.{key}",
                outcome,
                reason,
            )

        if not outcomes or all(outcome == "skipped" for outcome in outcomes):
            aggregate = "not_applicable"
        elif "fail" in outcomes:
            aggregate = "conflict"
        elif any(
            outcome in ("indeterminate", "unsupported")
            for outcome in outcomes
        ):
            aggregate = "incomplete"
        else:
            aggregate = "consistent"

        if state != aggregate:
            raise TypeError("Inconsistent triangulation relationship")

    return entries


def _consistency(
    value: Json,
    relationships: list[Json],
) -> EvidenceConsistency:
    state = cast(
        EvidenceConsistency,
        _one_of(
            value,
            "triangulation consistency",
            {"consistent", "conflict", "incomplete"},
        ),
    )

    if state == "consistent" and (
        not relationships
        or any(
            _object(relationship, "relationship").get("status") != "consistent"
            for relationship in relationships
        )
    ):
        raise TypeError("Incomplete triangulation cannot be consistent")

    return state


def _public_execution(
    value: Json,
    *,
    resolved: bool,
) -> Row:
    keys = {
        "status",
        "reason_code",
        "public_record_acquisition",
        "hedera_resolution",
    }
    if resolved:
        keys.update(
            {
                "mirror_status",
                "mirror_reason_code",
            }
        )

    row = _shape(
        value,
        "public execution",
        keys,
    )
    status = _one_of(
        row["status"],
        "execution resolution status",
        _EXECUTION_RESOLUTION_STATUSES,
    )
    acquisition = _one_of(
        row["public_record_acquisition"],
        "public record acquisition",
        _EXECUTION_RESOLUTION_STATUSES,
    )

    if row["reason_code"] is not None:
        _string(
            row["reason_code"],
            "execution reason",
            160,
        )

    if resolved:
        if acquisition != "resolved":
            raise TypeError("Unresolved execution acquisition")

        mirror = _one_of(
            row["mirror_status"],
            "Mirror status",
            _EXECUTION_RESOLUTION_STATUSES,
        )
        if row["hedera_resolution"] != mirror:
            raise TypeError("Mirror status mismatch")

        if row["mirror_reason_code"] is not None:
            _string(
                row["mirror_reason_code"],
                "Mirror reason",
                160,
            )
        if status == "not_found" and mirror == "resolved":
            raise TypeError("Inconsistent execution status")
    elif (
        acquisition == "resolved"
        or row["hedera_resolution"] != "not_checked"
        or status != acquisition
    ):
        raise TypeError("Invalid unresolved execution status")

    return row


def _plan_relationships(value: Json) -> None:
    rows = _array(
        value,
        "triangulation plan relationships",
        3,
    )
    ids: set[str] = set()

    for value in rows:
        item = _shape(
            value,
            "relationship plan",
            {
                "id",
                "left_observation_id",
                "right_observation_id",
                "comparisons",
            },
        )
        relationship_id = _one_of(
            item["id"],
            "plan relationship ID",
            _PUBLIC_RELATIONSHIPS,
        )
        if relationship_id in ids:
            raise TypeError("Duplicate plan relationship")
        ids.add(relationship_id)

        left_id = _identifier(
            item["left_observation_id"],
            "left observation ID",
        )
        right_id = _identifier(
            item["right_observation_id"],
            "right observation ID",
        )
        if left_id == right_id:
            raise TypeError("Self-referential plan relationship")

        keys: set[str] = set()
        for part in _array(
            item["comparisons"],
            "planned comparisons",
            64,
        ):
            comparison = _shape(
                part,
                "comparison plan",
                {
                    "key",
                    "left_key",
                    "right_key",
                },
            )
            key = _identifier(
                comparison["key"],
                "plan comparison key",
            )
            if key in keys:
                raise TypeError("Duplicate planned comparison")
            keys.add(key)

            _identifier(
                comparison["left_key"],
                "planned left key",
            )
            _identifier(
                comparison["right_key"],
                "planned right key",
            )


def _execution_targets(
    value: Json,
    core: Row,
) -> None:
    subject = _subject(core)

    for target_value in _array(
        value,
        "Hedera targets",
        64,
    ):
        target = _shape(
            target_value,
            "Hedera target",
            {
                "source",
                "role",
                "network",
                "transaction_id",
                "topic_id",
                "sequence_number",
                "observation_fact_prefix",
            },
        )
        source = _one_of(
            target["source"],
            "target source",
            {
                "provided_evidence",
                "public_record",
            },
        )
        role = _one_of(
            target["role"],
            "target role",
            {
                "acceptance_anchor",
                "result_evidence_anchor",
            },
        )

        if target["network"] != subject.get("hedera_network"):
            raise TypeError("Target network mismatch")

        _maybe_string(
            target["transaction_id"],
            "target transaction",
            128,
        )
        _maybe_string(
            target["topic_id"],
            "target topic",
            64,
        )

        transaction_id = target["transaction_id"]
        if (
            transaction_id is not None
            and (
                not isinstance(transaction_id, str)
                or _TRANSACTION_RE.fullmatch(transaction_id) is None
            )
        ):
            raise TypeError("Invalid Hedera transaction locator")

        topic_id = target["topic_id"]
        if (
            topic_id is not None
            and (
                not isinstance(topic_id, str)
                or _TOPIC_RE.fullmatch(topic_id) is None
            )
        ):
            raise TypeError("Invalid Hedera topic locator")

        sequence = target["sequence_number"]
        if (
            (topic_id is None) != (sequence is None)
            or (
                topic_id is None
                and transaction_id is None
            )
        ):
            raise TypeError("Incomplete Hedera target locator")

        if sequence is not None:
            number = _safe_integer(sequence)
            if number is None or number < 1:
                raise TypeError("Invalid target sequence")

        prefix = _identifier(
            target["observation_fact_prefix"],
            "target observation prefix",
        )
        if prefix != f"ledger.{source}.{role}":
            raise TypeError("Invalid target observation prefix")

        
def _public_context(value: Json, core: Row) -> Row:
    row = _shape(
        value,
        "public triangulation context",
        {"consistency", "relationships", "resolution"},
    )
    subject = _subject(core)

    if subject.get("kind") not in ("dataset", "ingest"):
        raise TypeError("Invalid public triangulation subject")

    relationships = _relationships(
        row["relationships"],
        core,
        _PUBLIC_RELATIONSHIPS,
    )
    _consistency(row["consistency"], relationships)

    resolution = _shape(
        row["resolution"],
        "public resolution",
        {
            "public_record",
            "publication_disclosure",
            "hedera_mirror",
        },
    )
    _one_of(
        resolution["public_record"],
        "public record status",
        _PUBLIC_RECORD_STATUSES,
    )
    _one_of(
        resolution["publication_disclosure"],
        "publication disclosure status",
        _PUBLIC_DISCLOSURE_STATUSES,
    )
    _one_of(
        resolution["hedera_mirror"],
        "Hedera Mirror status",
        _PUBLIC_MIRROR_STATUSES,
    )

    return row


def _authorized_context(
    value: Json,
    core: Row,
    *,
    profile: Literal["dataset", "ingest"],
) -> Row:
    label = "Dataset" if profile == "dataset" else "Ingest"
    row = _shape(
        value,
        f"authorized {label} triangulation context",
        {"consistency", "relationships", "resolution"},
    )
    subject = _subject(core)

    if (
        subject.get("kind") != profile
        or subject.get("hedera_network") not in ("mainnet", "testnet")
    ):
        raise TypeError(f"Invalid authorized {label} triangulation subject")

    relationships = _relationships(
        row["relationships"],
        core,
        _AUTHORIZED_RELATIONSHIPS,
    )
    state = _consistency(row["consistency"], relationships)

    ids = {
        cast(str, _object(relationship, "relationship")["id"])
        for relationship in relationships
    }

    if not _AUTHORIZED_RELATIONSHIPS.issubset(ids):
        raise TypeError(f"Missing authorized {label} relationship")

    profile_field = (
        "dataset_registry_event"
        if profile == "dataset"
        else "ingest_receipt"
    )
    resolution = _shape(
        row["resolution"],
        f"authorized {label} resolution",
        {"authorized_core", "hedera_mirror", profile_field},
    )
    core_status = _one_of(
        resolution["authorized_core"],
        "authorized Core status",
        _AUTHORIZED_CORE_STATUSES,
    )
    mirror_status = _one_of(
        resolution["hedera_mirror"],
        f"authorized {label} Mirror status",
        _AUTHORIZED_MIRROR_STATUSES,
    )
    profile_status = _one_of(
        resolution[profile_field],
        (
            "Dataset Registry event status"
            if profile == "dataset"
            else "Ingest receipt status"
        ),
        _AUTHORIZED_PROFILE_STATUSES,
    )
    profile_check = (
        "triangulation.authorized_dataset.registry_event_profile"
        if profile == "dataset"
        else "triangulation.authorized_ingest.receipt_profile"
    )
    profile_outcome: VerificationOutcome = (
        "pass"
        if profile_status == "resolved"
        else "fail"
        if profile_status in ("invalid", "conflict")
        else "unsupported"
        if profile_status == "unsupported"
        else "indeterminate"
    )

    _finding(core, profile_check, profile_outcome)

    relationship_conflict = any(
        _object(relationship, "relationship").get("status") == "conflict"
        for relationship in relationships
    )
    resolution_conflict = (
        mirror_status == "conflict"
        or profile_status in ("invalid", "conflict")
    )
    complete = (
        core_status == "resolved"
        and mirror_status == "resolved"
        and profile_status == "resolved"
        and all(
            _object(relationship, "relationship").get("status") == "consistent"
            for relationship in relationships
        )
    )
    expected_state: EvidenceConsistency = (
        "conflict"
        if relationship_conflict or resolution_conflict
        else "consistent"
        if complete
        else "incomplete"
    )

    if state != expected_state:
        raise TypeError(f"Inconsistent authorized {label} aggregate")

    return row


def _execution_triangulation_context(
    value: Json,
    core: Row,
) -> Row:
    if _subject(core).get("kind") != "execution":
        raise TypeError(
            "Invalid execution triangulation subject"
        )

    row = _object(
        value,
        "portable report context",
    )
    resolved = "triangulation" in row
    keys = (
        {
            "verification_scope",
            "source_core_sha3_512",
            "public_execution",
            "triangulation",
        }
        if resolved
        else {
            "verification_scope",
            "public_execution",
        }
    )
    row = _shape(
        value,
        "execution triangulation context",
        keys,
    )

    _scope(
        row["verification_scope"],
        core,
    )
    public = _public_execution(
        row["public_execution"],
        resolved=resolved,
    )

    if resolved:
        _hash(
            row["source_core_sha3_512"],
            "source core digest",
        )
        triangulation = _shape(
            row["triangulation"],
            "execution triangulation",
            {
                "consistency",
                "relationships",
                "targets",
                "plan_relationships",
            },
        )
        relationships = _relationships(
            triangulation["relationships"],
            core,
            _PUBLIC_RELATIONSHIPS,
        )
        state = _consistency(
            triangulation["consistency"],
            relationships,
        )
        _execution_targets(
            triangulation["targets"],
            core,
        )
        _plan_relationships(
            triangulation["plan_relationships"]
        )

        mirror = cast(
            str,
            public["mirror_status"],
        )
        resolved_status = (
            "conflict"
            if (
                state == "conflict"
                or mirror == "conflict"
            )
            else mirror
        )
        if public["status"] != resolved_status:
            raise TypeError(
                "Inconsistent resolved execution status"
            )

    return row


def _context(
    kind: str,
    value: Json,
    core: Row,
) -> Row:
    if kind == "verification":
        row = _shape(
            value,
            "verification context",
            set(),
        )
        if _subject(core).get("kind") == "execution":
            raise TypeError(
                "Execution requires scoped report"
            )
        return row

    if kind == "execution":
        row = _shape(
            value,
            "execution context",
            {"verification_scope"},
        )
        _scope(
            row["verification_scope"],
            core,
        )
        return row

    if kind == "independent_standards":
        row = _shape(
            value,
            "standards context",
            {
                "verification_scope",
                "independent_standards",
            },
        )
        _scope(
            row["verification_scope"],
            core,
        )
        _standards(
            row["independent_standards"],
            core,
        )
        return row

    if kind == "public_triangulation":
        return _public_context(
            value,
            core,
        )

    if kind == "authorized_dataset_triangulation":
        return _authorized_context(
            value,
            core,
            profile="dataset",
        )

    if kind == "authorized_ingest_triangulation":
        return _authorized_context(
            value,
            core,
            profile="ingest",
        )

    if kind == "execution_triangulation":
        return _execution_triangulation_context(
            value,
            core,
        )

    raise TypeError(
        "Unsupported portable report kind"
    )


def _checked(value: object) -> _Checked:
    clone = _object(
        _clone_json(_top_level(value)),
        "portable report",
    )
    _shape(
        clone,
        "portable report",
        {
            "schema_version",
            "kind",
            "core_sha3_512",
            "report_sha3_512",
            "core",
            "context",
        },
    )

    if clone["schema_version"] != PORTABLE_VERIFICATION_REPORT_SCHEMA_VERSION:
        raise TypeError("Unsupported portable report version")

    kind = _one_of(
        clone["kind"],
        "portable report kind",
        _KINDS,
    )
    core_hash = _hash(
        clone["core_sha3_512"],
        "core digest",
    )
    report_hash = _hash(
        clone["report_sha3_512"],
        "report digest",
    )
    core = _shape(
        clone["core"],
        "portable core",
        {
            "schema_version",
            "intent",
            "findings",
            "observations",
        },
    )
    expected_canonical = canonicalize_verification_core_v1(
        cast(VerificationReport, core)
    )
    expected_core = _object(
        _clone_json(json.loads(expected_canonical)),
        "canonical portable core",
    )

    if _json_stringify(core) != _json_stringify(expected_core):
        raise TypeError("Noncanonical portable core")

    computed_core = compute_verification_core_digest_v1(
        cast(VerificationReport, core)
    )

    if computed_core != core_hash:
        raise _DigestError("PORTABLE_CORE_DIGEST_MISMATCH")

    context = _context(kind, clone["context"], core)
    base: Row = {
        key: item
        for key, item in clone.items()
        if key != "report_sha3_512"
    }
    serialized = _json_stringify(base)

    if len(serialized.encode("utf-8")) > _MAX_BYTES:
        raise ValueError("Portable report exceeds size limit")

    digest = sha3_512_hex(
        _DOMAIN.encode("utf-8")
        + b"\x00"
        + serialized.encode("utf-8")
    )

    if digest != report_hash:
        raise _DigestError("PORTABLE_REPORT_DIGEST_MISMATCH")

    return _Checked(
        kind=kind,
        core=core,
        context=context,
        serialized=serialized,
    )


def validate_portable_verification_report_v1(
    value: object,
) -> PortableVerificationReportValidationV1:
    """Validate saved-report structure and digest integrity only."""
    try:
        _checked(value)
    except _DigestError as exc:
        return PortableVerificationReportValidationV1(
            status="invalid",
            reason_code=exc.code,
        )
    except (TypeError, ValueError, OverflowError):
        return PortableVerificationReportValidationV1(
            status="invalid",
            reason_code="PORTABLE_REPORT_INVALID",
        )

    return PortableVerificationReportValidationV1(
        status="valid",
        reason_code=None,
    )


def compare_portable_verification_reports_v1(
    left: object,
    right: object,
) -> PortableVerificationReportComparisonV1:
    """Compare two internally valid saved reports without authenticating either."""
    first = _checked(left)
    second = _checked(right)
    differences: list[PortableVerificationReportDifferenceV1] = []

    if first.kind != second.kind:
        differences.append("kind")

    first_intent = _object(first.core["intent"], "left intent")
    second_intent = _object(second.core["intent"], "right intent")

    if _json_stringify(first_intent["subject"]) != _json_stringify(
        second_intent["subject"]
    ):
        differences.append("subject")

    if _json_stringify(first_intent) != _json_stringify(second_intent):
        differences.append("intent")

    if _json_stringify(first.core["findings"]) != _json_stringify(
        second.core["findings"]
    ):
        differences.append("findings")

    if _json_stringify(first.core["observations"]) != _json_stringify(
        second.core["observations"]
    ):
        differences.append("observations")

    if _json_stringify(first.context) != _json_stringify(second.context):
        differences.append("context")

    return PortableVerificationReportComparisonV1(
        status=(
            "equivalent"
            if first.serialized == second.serialized
            else "different"
        ),
        differences=tuple(differences),
    )