"""Digest-bound portable verification reports."""

import json
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass, fields, is_dataclass
from typing import Any, Literal, cast

from ..contracts import EvidenceConsistency, VerificationOutcome, VerificationReport
from ..crypto.sha3 import sha3_512_hex
from ..profiles.execution.independent_standards_v1 import IndependentStandardsV1Report
from ..profiles.execution.verification_v1 import ExecutionV1Report
from ..triangulation.authorized_dataset_v1 import (
    AuthorizedDatasetTriangulationV1Result,
)
from ..triangulation.authorized_ingest_v1 import (
    AuthorizedIngestTriangulationV1Result,
)
from ..triangulation.compare_v1 import TriangulationRelationshipResultV1
from ..triangulation.execution_public_v1 import PublicExecutionTriangulationV1Result
from ..triangulation.public_v1 import PublicTriangulationV1Result
from .core_v1 import (
    _json_stringify,
    canonicalize_verification_core_v1,
    compute_verification_core_digest_v1,
)

PORTABLE_VERIFICATION_REPORT_SCHEMA_VERSION = "va.portable-verification-report.v1"

_DOMAIN = "va:portable-verification-report:v1"
_MAX_BYTES = 1024 * 1024
_MAX_DEPTH = 32
_MAX_ARRAY_ITEMS = 512
_MAX_OBJECT_FIELDS = 512
_MAX_STANDARDS_ITEMS = 16

_ID_RE = re.compile(r"^[a-z][a-z0-9._:-]{0,159}$", re.ASCII)
_SHA256_RE = re.compile(r"^[a-f0-9]{64}$", re.ASCII)
_UUID_RE = re.compile(
    r"^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-"
    r"[89ab][a-f0-9]{3}-[a-f0-9]{12}$",
    re.IGNORECASE | re.ASCII,
)

_PUBLIC_RELATIONSHIPS = {
    "provided_public_record",
    "public_record_hedera",
    "provided_hedera",
}
_AUTHORIZED_RELATIONSHIPS = {"provided_authorized", "authorized_hedera"}
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
}
_STANDARDS_ITEM_STATUSES = {
    "resolved",
    "conflict",
    "invalid",
    "unavailable",
    "unsupported",
}
_STANDARDS_STATUSES = {"verified", "failed", "unavailable", "not_performed"}
_STANDARDS_ASSURANCE = {"mirror_corroborated", "not_established"}

type Json = None | str | int | float | bool | list[Json] | dict[str, Json]
type JsonObject = dict[str, Json]

type PortableVerificationReportKindV1 = Literal[
    "verification",
    "execution",
    "independent_standards",
    "public_triangulation",
    "authorized_dataset_triangulation",
    "authorized_ingest_triangulation",
    "execution_triangulation",
]

type PortableVerificationResultV1 = (
    VerificationReport
    | ExecutionV1Report
    | IndependentStandardsV1Report
    | PublicTriangulationV1Result
    | AuthorizedDatasetTriangulationV1Result
    | AuthorizedIngestTriangulationV1Result
    | PublicExecutionTriangulationV1Result
)


@dataclass(frozen=True, slots=True)
class PortableVerificationReportV1Input:
    kind: PortableVerificationReportKindV1
    result: PortableVerificationResultV1
    source_report: ExecutionV1Report | None = None


@dataclass(frozen=True, slots=True)
class PortableVerificationReportV1:
    schema_version: Literal["va.portable-verification-report.v1"]
    kind: PortableVerificationReportKindV1
    core_sha3_512: str
    report_sha3_512: str
    core: JsonObject
    context: JsonObject


def _js_length(value: str) -> int:
    return len(value.encode("utf-16-le", "surrogatepass")) // 2


def _checked_string(value: str) -> str:
    if _js_length(value) > _MAX_BYTES:
        raise TypeError("Invalid portable report string")
    try:
        return value.encode("utf-16-le", "surrogatepass").decode("utf-16-le", "strict")
    except UnicodeDecodeError as exc:
        raise TypeError("Invalid portable report string") from exc


def _bounded_string(value: object, name: str, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not value
        or _js_length(value) > maximum
        or value.strip() != value
    ):
        raise TypeError(f"Invalid {name}")
    return _checked_string(value)


def _js_sort_key(value: str) -> tuple[int, ...]:
    encoded = value.encode("utf-16-be", "surrogatepass")
    return tuple(
        int.from_bytes(encoded[index : index + 2], "big")
        for index in range(0, len(encoded), 2)
    )


def _object(value: object, name: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise TypeError(f"Invalid {name}")
    return cast(Mapping[str, object], value)


def _dataclass_row(value: object) -> dict[str, object] | None:
    if not is_dataclass(value) or isinstance(value, type):
        return None
    instance = cast(Any, value)
    return {field.name: getattr(instance, field.name) for field in fields(instance)}


def _json(value: object, depth: int = 0) -> Json:
    if depth > _MAX_DEPTH:
        raise TypeError("Portable report exceeds nesting limit")
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, str):
        return _checked_string(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value) or (
            value == 0.0 and math.copysign(1.0, value) < 0
        ):
            raise TypeError("Invalid portable report number")
        return value
    if isinstance(value, (list, tuple)):
        if len(value) > _MAX_ARRAY_ITEMS:
            raise TypeError("Portable report array exceeds limit")
        return [_json(item, depth + 1) for item in value]

    dataclass_row = _dataclass_row(value)
    if dataclass_row is not None:
        value = dataclass_row
    row = _object(value, "portable report JSON object")
    if len(row) > _MAX_OBJECT_FIELDS:
        raise TypeError("Portable report object exceeds field limit")

    result: JsonObject = {}
    for key in sorted(row, key=_js_sort_key):
        if (
            not key
            or _js_length(key) > 160
            or any(ord(character) < 0x20 or ord(character) == 0x7F for character in key)
        ):
            raise TypeError("Invalid portable report field")
        result[key] = _json(row[key], depth + 1)
    return result


def _json_object(value: object) -> JsonObject:
    normalized = _json(value)
    if not isinstance(normalized, dict):
        raise TypeError("Invalid portable report object")
    return normalized


def _checked_core(report: VerificationReport) -> tuple[JsonObject, str]:
    canonical = canonicalize_verification_core_v1(report)
    parsed = json.loads(canonical)
    return _json_object(parsed), compute_verification_core_digest_v1(report)


def _expected_outcome(status: str) -> VerificationOutcome:
    if status == "resolved":
        return "pass"
    if status in ("conflict", "invalid"):
        return "fail"
    if status == "unsupported":
        return "unsupported"
    return "indeterminate"


def _require_finding(
    report: VerificationReport,
    check_id: str,
    outcome: VerificationOutcome,
) -> None:
    found = next(
        (finding for finding in report.findings if finding.check_id == check_id),
        None,
    )
    if found is None or found.outcome != outcome:
        raise TypeError(f"Inconsistent report finding: {check_id}")


def _relationship_context(
    report: VerificationReport,
    relationships: tuple[TriangulationRelationshipResultV1, ...],
    allowed_ids: set[str],
) -> Json:
    if len(relationships) > 3:
        raise TypeError("Invalid triangulation relationships")

    used: set[str] = set()
    for relationship in relationships:
        if (
            relationship.id not in allowed_ids
            or relationship.id in used
            or relationship.status
            not in ("consistent", "conflict", "incomplete", "not_applicable")
            or len(relationship.fact_comparisons) > 64
        ):
            raise TypeError("Invalid triangulation relationship")
        used.add(relationship.id)

        keys: set[str] = set()
        outcomes: list[VerificationOutcome] = []
        for fact in relationship.fact_comparisons:
            if _ID_RE.fullmatch(fact.key) is None or fact.key in keys:
                raise TypeError("Invalid triangulation fact result")
            keys.add(fact.key)
            outcomes.append(fact.outcome)
            _require_finding(
                report,
                f"triangulation.{relationship.id}.{fact.key}",
                fact.outcome,
            )

        if not outcomes or all(outcome == "skipped" for outcome in outcomes):
            aggregate: EvidenceConsistency | Literal["not_applicable"] = (
                "not_applicable"
            )
        elif "fail" in outcomes:
            aggregate = "conflict"
        elif any(
            outcome in ("indeterminate", "unsupported") for outcome in outcomes
        ):
            aggregate = "incomplete"
        else:
            aggregate = "consistent"

        if relationship.status != aggregate:
            raise TypeError("Inconsistent triangulation relationship status")
    return _json(relationships)


def _consistency(value: object) -> EvidenceConsistency:
    if value not in ("consistent", "conflict", "incomplete"):
        raise TypeError("Invalid triangulation consistency")
    return value


def _checked_execution_scope(report: ExecutionV1Report) -> JsonObject:
    scope = report.verification_scope
    if report.intent["subject"]["kind"] != "execution" or scope.profile not in (
        "execution-v1",
        "sage-standards-v1",
    ):
        raise TypeError("Invalid execution report scope")

    if scope.expected_program is not None:
        _bounded_string(scope.expected_program, "expected program", 128)
    if scope.requested_result_id is not None:
        result_id = _bounded_string(
            scope.requested_result_id, "requested result ID", 64
        )
        if _UUID_RE.fullmatch(result_id) is None:
            raise TypeError("Invalid execution result scope")
    if scope.profile == "execution-v1" and scope.expected_program is None:
        raise TypeError("Generic execution profile requires expected program")
    if scope.requested_result_id is not None and not any(
        finding.check_id == "intent.result" for finding in report.findings
    ):
        raise TypeError("Missing result-scope finding")

    return _json_object(
        {
            "profile": scope.profile,
            "expected_program": scope.expected_program,
            "requested_result_id": scope.requested_result_id,
        }
    )


def _standards_context(result: IndependentStandardsV1Report) -> JsonObject:
    standards = result.independent_standards
    subject = result.intent["subject"]
    if (
        standards.network != subject.get("hedera_network")
        or standards.status not in _STANDARDS_STATUSES
        or standards.assurance not in _STANDARDS_ASSURANCE
        or len(standards.items) > _MAX_STANDARDS_ITEMS
    ):
        raise TypeError("Invalid independent standards summary")

    all_resolved = bool(standards.items) and all(
        item.status == "resolved" for item in standards.items
    )
    any_failed = any(item.status in ("conflict", "invalid") for item in standards.items)
    if (
        (standards.status == "verified") != all_resolved
        or (standards.status == "failed") != any_failed
        or (standards.status == "not_performed") != (len(standards.items) == 0)
        or (standards.assurance == "mirror_corroborated")
        != (standards.status == "verified")
    ):
        raise TypeError("Inconsistent independent standards aggregate")

    seen: set[str] = set()
    for index, item in enumerate(standards.items):
        key = _bounded_string(item.key, "standards plan key", 256)
        if (
            key in seen
            or item.status not in _STANDARDS_ITEM_STATUSES
            or item.assurance
            != (
                "mirror_corroborated"
                if item.status == "resolved"
                else "not_established"
            )
            or (
                item.content_sha256 is not None
                and _SHA256_RE.fullmatch(item.content_sha256) is None
            )
        ):
            raise TypeError("Invalid independent standards item")
        seen.add(key)
        _require_finding(
            result,
            f"standards.reference.{index}",
            _expected_outcome(item.status),
        )

    summary_outcome: VerificationOutcome = (
        "pass"
        if standards.status == "verified"
        else "fail"
        if standards.status == "failed"
        else "indeterminate"
    )
    _require_finding(result, "standards.references_resolved", summary_outcome)
    return _json_object(
        {
            "verification_scope": _checked_execution_scope(result),
            "independent_standards": standards,
        }
    )


def _verification_context(
    result: VerificationReport,
) -> tuple[VerificationReport, JsonObject]:
    if result.intent["subject"]["kind"] == "execution":
        raise TypeError("Execution assurance requires an explicit portable report kind")
    return result, {}


def _execution_context(
    result: ExecutionV1Report,
) -> tuple[VerificationReport, JsonObject]:
    return result, {"verification_scope": _checked_execution_scope(result)}


def _public_context(
    result: PublicTriangulationV1Result,
) -> tuple[VerificationReport, JsonObject]:
    state = _consistency(result.consistency)
    if state == "consistent" and (
        not result.relationships
        or any(
            relationship.status != "consistent"
            for relationship in result.relationships
        )
    ):
        raise TypeError("Incomplete triangulation cannot be consistent")
    return (
        result.report,
        {
            "consistency": state,
            "relationships": _relationship_context(
                result.report,
                result.relationships,
                _PUBLIC_RELATIONSHIPS,
            ),
            "resolution": _json(result.resolution),
        },
    )


def _authorized_dataset_context(
    result: AuthorizedDatasetTriangulationV1Result,
) -> tuple[VerificationReport, JsonObject]:
    state = _consistency(result.consistency)
    subject = result.report.intent["subject"]
    if subject["kind"] != "dataset" or subject.get("hedera_network") not in (
        "mainnet",
        "testnet",
    ):
        raise TypeError(
            "Authorized Dataset triangulation requires a network-scoped Dataset subject"
        )

    relationships = _relationship_context(
        result.report,
        result.relationships,
        _AUTHORIZED_RELATIONSHIPS,
    )
    ids = {relationship.id for relationship in result.relationships}
    if not _AUTHORIZED_RELATIONSHIPS.issubset(ids):
        raise TypeError(
            "Authorized Dataset triangulation is missing a required relationship"
        )

    resolution = result.resolution
    if (
        resolution.authorized_core not in _AUTHORIZED_CORE_STATUSES
        or resolution.hedera_mirror not in _AUTHORIZED_MIRROR_STATUSES
        or resolution.dataset_registry_event not in _AUTHORIZED_PROFILE_STATUSES
    ):
        raise TypeError("Invalid authorized Dataset resolution")

    _require_finding(
        result.report,
        "triangulation.authorized_dataset.registry_event_profile",
        _expected_outcome(resolution.dataset_registry_event),
    )
    relationship_conflict = any(
        relationship.status == "conflict" for relationship in result.relationships
    )
    resolution_conflict = resolution.hedera_mirror == "conflict" or (
        resolution.dataset_registry_event in ("invalid", "conflict")
    )
    complete = (
        resolution.authorized_core == "resolved"
        and resolution.hedera_mirror == "resolved"
        and resolution.dataset_registry_event == "resolved"
        and all(
            relationship.status == "consistent" for relationship in result.relationships
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
        raise TypeError("Inconsistent authorized Dataset aggregate")
    return (
        result.report,
        {
            "consistency": state,
            "relationships": relationships,
            "resolution": _json(resolution),
        },
    )


def _authorized_ingest_context(
    result: AuthorizedIngestTriangulationV1Result,
) -> tuple[VerificationReport, JsonObject]:
    state = _consistency(result.consistency)
    subject = result.report.intent["subject"]
    if subject["kind"] != "ingest" or subject.get("hedera_network") not in (
        "mainnet",
        "testnet",
    ):
        raise TypeError(
            "Authorized Ingest triangulation requires a network-scoped Ingest subject"
        )

    relationships = _relationship_context(
        result.report,
        result.relationships,
        _AUTHORIZED_RELATIONSHIPS,
    )
    ids = {relationship.id for relationship in result.relationships}
    if not _AUTHORIZED_RELATIONSHIPS.issubset(ids):
        raise TypeError(
            "Authorized Ingest triangulation is missing a required relationship"
        )

    resolution = result.resolution
    if (
        resolution.authorized_core not in _AUTHORIZED_CORE_STATUSES
        or resolution.hedera_mirror not in _AUTHORIZED_MIRROR_STATUSES
        or resolution.ingest_receipt not in _AUTHORIZED_PROFILE_STATUSES
    ):
        raise TypeError("Invalid authorized Ingest resolution")

    _require_finding(
        result.report,
        "triangulation.authorized_ingest.receipt_profile",
        _expected_outcome(resolution.ingest_receipt),
    )
    relationship_conflict = any(
        relationship.status == "conflict" for relationship in result.relationships
    )
    resolution_conflict = resolution.hedera_mirror == "conflict" or (
        resolution.ingest_receipt in ("invalid", "conflict")
    )
    complete = (
        resolution.authorized_core == "resolved"
        and resolution.hedera_mirror == "resolved"
        and resolution.ingest_receipt == "resolved"
        and all(
            relationship.status == "consistent" for relationship in result.relationships
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
        raise TypeError("Inconsistent authorized Ingest aggregate")
    return (
        result.report,
        {
            "consistency": state,
            "relationships": relationships,
            "resolution": _json(resolution),
        },
    )


def _execution_triangulation_context(
    input: PortableVerificationReportV1Input,
    result: PublicExecutionTriangulationV1Result,
) -> tuple[VerificationReport, JsonObject]:
    if (
        result.status not in _EXECUTION_RESOLUTION_STATUSES
        or result.public_record_acquisition not in _EXECUTION_RESOLUTION_STATUSES
    ):
        raise TypeError("Invalid public execution acquisition")

    if result.plan is None:
        if (
            result.comparison is not None
            or result.mirror is not None
            or result.hedera_resolution != "not_checked"
            or result.public_record_acquisition == "resolved"
            or input.source_report is None
        ):
            raise TypeError(
                "Unresolved execution requires independently computed offline report"
            )
        offline_report = input.source_report
        return (
            offline_report,
            {
                "verification_scope": _checked_execution_scope(offline_report),
                "public_execution": _json_object(
                    {
                        "status": result.status,
                        "reason_code": result.reason_code,
                        "public_record_acquisition": result.public_record_acquisition,
                        "hedera_resolution": result.hedera_resolution,
                    }
                ),
            },
        )

    if (
        result.comparison is None
        or result.mirror is None
        or result.public_record_acquisition != "resolved"
        or result.plan.stage != "unresolved_authority_plan"
        or result.plan.hedera_resolution != "not_checked"
        or result.plan.public_record_acquisition != "not_checked"
    ):
        raise TypeError("Invalid resolved execution triangulation structure")

    report = result.comparison.report
    source = result.plan.source_report
    if (
        report.intent["subject"]["kind"] != "execution"
        or report.intent != source.intent
        or result.hedera_resolution != result.mirror.status
    ):
        raise TypeError("Execution triangulation subject or resolver mismatch")

    network = report.intent["subject"].get("hedera_network")
    if any(target.network != network for target in result.plan.hedera_targets):
        raise TypeError("Execution Hedera target network mismatch")

    state = _consistency(result.comparison.consistency)
    if state == "consistent" and (
        not result.comparison.relationships
        or any(
            relationship.status != "consistent"
            for relationship in result.comparison.relationships
        )
    ):
        raise TypeError("Incomplete execution triangulation cannot be consistent")

    return (
        report,
        {
            "verification_scope": _checked_execution_scope(source),
            "source_core_sha3_512": compute_verification_core_digest_v1(source),
            "public_execution": _json_object(
                {
                    "status": result.status,
                    "reason_code": result.reason_code,
                    "public_record_acquisition": result.public_record_acquisition,
                    "hedera_resolution": result.hedera_resolution,
                    "mirror_status": result.mirror.status,
                    "mirror_reason_code": result.mirror.reason_code,
                }
            ),
            "triangulation": _json_object(
                {
                    "consistency": state,
                    "relationships": _relationship_context(
                        report,
                        result.comparison.relationships,
                        _PUBLIC_RELATIONSHIPS,
                    ),
                    "targets": result.plan.hedera_targets,
                    "plan_relationships": result.plan.triangulation.relationships,
                }
            ),
        },
    )


def _context(
    input: PortableVerificationReportV1Input,
) -> tuple[VerificationReport, JsonObject]:
    if input.kind == "verification":
        if not isinstance(input.result, VerificationReport):
            raise TypeError("Invalid verification result")
        return _verification_context(input.result)

    if input.kind == "execution":
        if not isinstance(input.result, ExecutionV1Report):
            raise TypeError("Invalid execution result")
        return _execution_context(input.result)

    if input.kind == "independent_standards":
        if not isinstance(input.result, IndependentStandardsV1Report):
            raise TypeError("Invalid independent standards result")
        return input.result, _standards_context(input.result)

    if input.kind == "public_triangulation":
        if not isinstance(input.result, PublicTriangulationV1Result):
            raise TypeError("Invalid public triangulation result")
        return _public_context(input.result)

    if input.kind == "authorized_dataset_triangulation":
        if not isinstance(input.result, AuthorizedDatasetTriangulationV1Result):
            raise TypeError("Invalid authorized Dataset result")
        return _authorized_dataset_context(input.result)

    if input.kind == "authorized_ingest_triangulation":
        if not isinstance(input.result, AuthorizedIngestTriangulationV1Result):
            raise TypeError("Invalid authorized Ingest result")
        return _authorized_ingest_context(input.result)

    if input.kind == "execution_triangulation":
        if not isinstance(input.result, PublicExecutionTriangulationV1Result):
            raise TypeError("Invalid public execution triangulation result")
        return _execution_triangulation_context(input, input.result)

    raise TypeError("Unsupported portable report kind")


def create_portable_verification_report_v1(
    input: PortableVerificationReportV1Input,
) -> PortableVerificationReportV1:
    """Create a content-addressed portable verification report."""
    if not isinstance(input, PortableVerificationReportV1Input):
        raise TypeError("Portable report input is required")

    source_report, context = _context(input)
    core, core_digest = _checked_core(source_report)
    base = _json_object(
        {
            "schema_version": PORTABLE_VERIFICATION_REPORT_SCHEMA_VERSION,
            "kind": input.kind,
            "core_sha3_512": core_digest,
            "core": core,
            "context": context,
        }
    )
    canonical = _json_stringify(base)
    if len(canonical.encode("utf-8")) > _MAX_BYTES:
        raise ValueError("Portable report exceeds size limit")

    report_digest = sha3_512_hex(
        _DOMAIN.encode("utf-8") + b"\x00" + canonical.encode("utf-8")
    )
    return PortableVerificationReportV1(
        schema_version="va.portable-verification-report.v1",
        kind=input.kind,
        core_sha3_512=core_digest,
        report_sha3_512=report_digest,
        core=core,
        context=context,
    )


def canonicalize_portable_verification_report_v1(
    input: PortableVerificationReportV1Input,
) -> str:
    """Serialize a portable report deterministically."""
    report = create_portable_verification_report_v1(input)
    return _json_stringify(_json_object(report))


def compute_portable_verification_report_digest_v1(
    input: PortableVerificationReportV1Input,
) -> str:
    """Return the portable envelope digest."""
    return create_portable_verification_report_v1(input).report_sha3_512