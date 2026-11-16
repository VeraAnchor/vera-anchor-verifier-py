"""Bounded execution evidence and verification rule contracts."""

import math
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal, TypedDict

from ...contracts import HederaNetwork
from .reason_codes_v1 import EXECUTION_VERIFICATION_REASON_CODES as REASONS
from .reason_codes_v1 import ExecutionVerificationReasonCode
from .recomputation_v1 import canonicalize_execution_verification_value

EXECUTION_VERIFICATION_SCHEMA_VERSION = "vera.execution-verification.v1"
EXECUTION_VERIFIER_VERSION = "1.0.0"
SUPPORTED_PUBLIC_STANDARDS_CONTRACT_VERSIONS = ("1.0.0",)

EXECUTION_VERIFICATION_STATUSES = (
    "consistent",
    "incomplete",
    "failed",
)
EXECUTION_VERIFICATION_CHECK_STATUSES = (
    "pass",
    "fail",
    "unavailable",
    "not_applicable",
)
EXECUTION_VERIFICATION_REQUIREMENTS = (
    "required",
    "optional",
    "conditional",
)

type ExecutionVerificationStatus = Literal[
    "consistent",
    "incomplete",
    "failed",
]
type ExecutionVerificationCheckStatus = Literal[
    "pass",
    "fail",
    "unavailable",
    "not_applicable",
]
type ExecutionVerificationRequirement = Literal[
    "required",
    "optional",
    "conditional",
]


class PublicStandardsSourceDocument(TypedDict, total=False):
    standard: str | None
    version: str | None
    path: str | None
    sha256: str | None


class PublicStandardsBaselineEvidence(TypedDict, total=False):
    baseline_id: str | None
    title: str | None
    source_repository: str | None
    source_commit: str | None
    frozen_at: str | datetime | None
    source_documents: list[PublicStandardsSourceDocument] | None


class PublicHcs11Evidence(TypedDict, total=False):
    profile_version: str | None
    account_id: str | None
    profile_registry_topic_id: str | None
    profile_registry_sequence: int | float | None
    profile_hcs1_ref: str | None
    profile_checksum_sha256: str | None


class PublicAgentEvidence(TypedDict, total=False):
    logical_id: str | None
    display_name: str | None
    base_did: str | None
    hcs14_uaid: str | None
    hcs11: PublicHcs11Evidence | None


class PublicCapabilityEvidence(TypedDict, total=False):
    standard: str | None
    capability_version_id: str | None
    display_name: str | None
    discovery_registry_topic_id: str | None
    skill_uid: str | None
    skill_version: str | None
    version_registry_topic_id: str | None
    version_sequence_number: int | float | None
    manifest_hcs1_ref: str | None
    manifest_checksum_sha256: str | None
    repository_uri: str | None
    repository_commit: str | None
    published_at: str | datetime | None


class PublicSchemaEvidence(TypedDict, total=False):
    role: str | None
    ordinal: int | float | None
    schema_uid: str | None
    display_name: str | None
    semantic_version: str | None
    registry_topic_id: str | None
    registry_sequence_number: int | float | None
    hcs13_ref: str | None
    schema_checksum_sha256: str | None
    instance_digest_sha3_512: str | None


class PublicExecutionDatasetEvidence(TypedDict, total=False):
    dataset_key: str | None
    dataset_version: int | float | None
    dataset_fingerprint_sha3_512: str | None
    dataset_manifest_sha3_512: str | None


class PublicExecutionEvidence(TypedDict, total=False):
    job_id: str | None
    result_id: str | None
    proof_date: str | None
    program: str | None
    status: str | None
    hedera_network: str | None
    pipeline_hash: str | None
    dataset: PublicExecutionDatasetEvidence | None


class PublicParameterInstanceVerificationMaterial(TypedDict, total=False):
    role: str | None
    hcs13_ref: str | None
    domain_separator: str | None
    payload: object


class PublicExecutionStartVerificationMaterial(TypedDict, total=False):
    started_at: str | datetime | None
    hcs_transaction_id: str | None
    hcs_topic_id: str | None
    consensus_timestamp_exact: str | None


type PublicStandardsResolutionState = Literal[
    "verified",
    "failed",
    "unavailable",
]


class PublicStandardsResolutionItem(TypedDict, total=False):
    key: str | None
    standard: str | None
    reference: str | None
    state: PublicStandardsResolutionState | None
    reason: str | None


class PublicStandardsResolutionMaterial(TypedDict, total=False):
    schema_version: str | None
    hedera_network: str | None
    state: PublicStandardsResolutionState | None
    items: list[PublicStandardsResolutionItem] | None


class PublicExecutionVerificationMaterial(TypedDict, total=False):
    parameter_instance: PublicParameterInstanceVerificationMaterial | None
    execution_start: PublicExecutionStartVerificationMaterial | None
    standards_resolution: PublicStandardsResolutionMaterial | None


class PublicSoftwareReleaseEvidence(TypedDict, total=False):
    repository_uri: str | None
    git_commit: str | None
    pipeline_hash_sha3_512: str | None


class PublicContractMetadataRecord(TypedDict, total=False):
    schema: str | None
    digest: str | None
    digest_payload: dict[str, object] | None
    canonicalization: str | None
    digest_algorithm: str | None
    domain_separator: str | None


class PublicBindingEvidence(PublicContractMetadataRecord, total=False):
    id: str | None
    finalized_at: str | datetime | None


class PublicAcceptanceHcsEvidence(TypedDict, total=False):
    topic_id: str | None
    transaction_id: str | None
    message_id: str | None
    sequence_number: int | float | None
    consensus_timestamp: str | datetime | None
    consensus_timestamp_exact: str | None
    data_hash_sha3_512: str | None


class PublicAcceptanceEvidence(PublicContractMetadataRecord, total=False):
    id: str | None
    state: str | None
    admission_policy_id: str | None
    requires_hcs_confirmation: bool | None
    binding_digest: str | None
    accepted_at: str | datetime | None
    confirmed_at: str | datetime | None
    failure_code: str | None
    hcs: PublicAcceptanceHcsEvidence | None


class PublicResultEvidenceHcsEvidence(TypedDict, total=False):
    transaction_id: str | None
    topic_id: str | None


class PublicResultEvidence(PublicContractMetadataRecord, total=False):
    id: str | None
    result_id: str | None
    binding_digest: str | None
    acceptance_digest: str | None
    pipeline_hash: str | None
    result_hash: str | None
    service_hash: str | None
    global_hash: str | None
    artifact_count: int | float | None
    sealed_at: str | datetime | None
    hcs: PublicResultEvidenceHcsEvidence | None


class PublicExecutionStandardsBlock(TypedDict, total=False):
    baseline: PublicStandardsBaselineEvidence | None
    schemas: list[PublicSchemaEvidence] | None
    reference_complete: bool | None
    publicly_resolvable: bool | None


class PublicExecutionAgentsEvidence(TypedDict, total=False):
    requester: PublicAgentEvidence | None
    executor: PublicAgentEvidence | None


class PublicExecutionStandardsEvidence(TypedDict, total=False):
    available: bool
    contract_version: str | None
    reason: str | None
    execution: PublicExecutionEvidence | None
    standards: PublicExecutionStandardsBlock | None
    agents: PublicExecutionAgentsEvidence | None
    capability: PublicCapabilityEvidence | None
    software_release: PublicSoftwareReleaseEvidence | None
    binding: PublicBindingEvidence | None
    acceptance: PublicAcceptanceEvidence | None
    result_evidence: PublicResultEvidence | None


@dataclass(frozen=True, slots=True)
class ExecutionVerificationSubject:
    hedera_network: HederaNetwork | None
    program: str | None
    job_id: str | None
    result_id: str | None


@dataclass(frozen=True, slots=True)
class ExecutionVerificationCheck:
    id: str
    group: str
    label: str
    requirement: ExecutionVerificationRequirement
    status: ExecutionVerificationCheckStatus
    reason_code: ExecutionVerificationReasonCode
    evidence_refs: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ExecutionVerificationSummary:
    total: int
    outcome_relevant: int
    passed: int
    failed: int
    unavailable: int
    not_applicable: int


@dataclass(frozen=True, slots=True)
class ExecutionVerificationReport:
    schema_version: Literal["vera.execution-verification.v1"]
    verifier_version: Literal["1.0.0"]
    subject: ExecutionVerificationSubject
    status: ExecutionVerificationStatus
    summary: ExecutionVerificationSummary
    checks: tuple[ExecutionVerificationCheck, ...]


@dataclass(frozen=True, slots=True)
class ExecutionVerificationRuleResult:
    status: ExecutionVerificationCheckStatus
    reason_code: ExecutionVerificationReasonCode


@dataclass(frozen=True, slots=True)
class ExecutionVerificationContext:
    evidence: PublicExecutionStandardsEvidence
    verification_material: PublicExecutionVerificationMaterial | None
    expected_network: HederaNetwork | Literal[""]
    requested_result_id: str
    supported_contract_versions: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ExecutionVerificationRule:
    id: str
    group: str
    label: str
    requirement: ExecutionVerificationRequirement
    evidence_refs: tuple[str, ...]
    evaluate: Callable[
        [ExecutionVerificationContext],
        ExecutionVerificationRuleResult,
    ]


@dataclass(frozen=True, slots=True)
class ExecutionVerificationInputBoundsResult:
    ok: bool
    reason_code: ExecutionVerificationReasonCode


_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-"
    r"[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-"
    r"[0-9a-f]{12}$",
    re.IGNORECASE | re.ASCII,
)
_SHA3_512_RE = re.compile(r"^[0-9a-f]{128}$", re.ASCII)
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_GIT_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$", re.ASCII)
_HEDERA_ID_RE = re.compile(r"^0\.0\.[0-9]+$", re.ASCII)
_HCS_TX_ID_RE = re.compile(r"^0\.0\.[0-9]+@[0-9]+\.[0-9]+$", re.ASCII)
_HCS1_REF_RE = re.compile(r"^hcs://1/0\.0\.[0-9]+(?:/.*)?$", re.ASCII)
_HCS13_REF_RE = re.compile(r"^hcs://13/0\.0\.[0-9]+#[1-9][0-9]*$", re.ASCII)
_DATE_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})$", re.ASCII)

_MAX_SAFE_INTEGER = (1 << 53) - 1
_MAX_DEPTH = 20
_MAX_OBJECT_KEYS = 4096
_MAX_ARRAY_LENGTH = 256
_MAX_STRING_LENGTH = 8192
_MAX_VISITED_VALUES = 20_000
_MAX_KEY_LENGTH = 256


def _js_length(value: str) -> int:
    return len(value.encode("utf-16-le", "surrogatepass")) // 2


def _js_sort_key(value: str) -> tuple[int, ...]:
    encoded = value.encode("utf-16-be", "surrogatepass")
    return tuple(
        int.from_bytes(encoded[index : index + 2], "big")
        for index in range(0, len(encoded), 2)
    )


def clean_string(value: object) -> str:
    if not isinstance(value, str):
        return ""

    out = value.strip()
    return out if out else ""


def normalize_identifier(value: object) -> str:
    return clean_string(value).lower()


def same_identifier(left: object, right: object) -> bool:
    first = normalize_identifier(left)
    second = normalize_identifier(right)
    return bool(first and second and first == second)


def is_uuid(value: object) -> bool:
    return _UUID_RE.fullmatch(clean_string(value)) is not None


def is_sha3_512(value: object) -> bool:
    return _SHA3_512_RE.fullmatch(clean_string(value)) is not None


def is_sha256(value: object) -> bool:
    return _SHA256_RE.fullmatch(clean_string(value)) is not None


def is_git_commit(value: object) -> bool:
    return _GIT_COMMIT_RE.fullmatch(clean_string(value)) is not None


def is_hedera_id(value: object) -> bool:
    return _HEDERA_ID_RE.fullmatch(clean_string(value)) is not None


def is_hcs_transaction_id(value: object) -> bool:
    return _HCS_TX_ID_RE.fullmatch(clean_string(value)) is not None


def is_hcs1_ref(value: object) -> bool:
    return _HCS1_REF_RE.fullmatch(clean_string(value)) is not None


def is_hcs13_ref(value: object) -> bool:
    return _HCS13_REF_RE.fullmatch(clean_string(value)) is not None


def is_supported_hedera_network(value: object) -> bool:
    network = normalize_identifier(value)
    return network in ("testnet", "mainnet")


def is_valid_date(value: object) -> bool:
    text = clean_string(value)
    match = _DATE_RE.fullmatch(text)

    if match is None:
        return False

    try:
        datetime(
            int(match.group(1)),
            int(match.group(2)),
            int(match.group(3)),
            tzinfo=UTC,
        )
    except ValueError:
        return False

    return True


def has_timestamp(value: object) -> bool:
    if isinstance(value, datetime):
        return True

    return bool(clean_string(value))


def is_positive_safe_integer(value: object) -> bool:
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return 1 <= value <= _MAX_SAFE_INTEGER

    return (
        isinstance(value, float)
        and math.isfinite(value)
        and value.is_integer()
        and 1 <= value <= _MAX_SAFE_INTEGER
    )


def is_plain_object(value: object) -> bool:
    return type(value) is dict


def _finite_js_number(value: int | float) -> bool:
    if isinstance(value, bool):
        return True
    if isinstance(value, float):
        return math.isfinite(value)

    try:
        return math.isfinite(float(value))
    except OverflowError:
        return False


def validate_execution_verification_input_bounds(
    value: object,
) -> ExecutionVerificationInputBoundsResult:
    if not is_plain_object(value):
        return ExecutionVerificationInputBoundsResult(
            ok=False,
            reason_code=REASONS.INPUT_STRUCTURE_INVALID,
        )

    stack: list[tuple[object, int]] = [(value, 0)]
    seen: set[int] = set()
    visited = 0
    object_keys = 0

    while stack:
        item, depth = stack.pop()
        visited += 1

        if visited > _MAX_VISITED_VALUES:
            return ExecutionVerificationInputBoundsResult(
                ok=False,
                reason_code=REASONS.INPUT_LIMIT_EXCEEDED,
            )

        if item is None or isinstance(item, bool):
            continue

        if isinstance(item, (int, float)):
            if not _finite_js_number(item):
                return ExecutionVerificationInputBoundsResult(
                    ok=False,
                    reason_code=REASONS.INPUT_STRUCTURE_INVALID,
                )
            continue

        if isinstance(item, str):
            if _js_length(item) > _MAX_STRING_LENGTH:
                return ExecutionVerificationInputBoundsResult(
                    ok=False,
                    reason_code=REASONS.INPUT_LIMIT_EXCEEDED,
                )
            continue

        if isinstance(item, datetime):
            continue

        if depth >= _MAX_DEPTH:
            return ExecutionVerificationInputBoundsResult(
                ok=False,
                reason_code=REASONS.INPUT_LIMIT_EXCEEDED,
            )

        if not isinstance(item, (list, dict)):
            return ExecutionVerificationInputBoundsResult(
                ok=False,
                reason_code=REASONS.INPUT_STRUCTURE_INVALID,
            )

        identity = id(item)

        if identity in seen:
            return ExecutionVerificationInputBoundsResult(
                ok=False,
                reason_code=REASONS.INPUT_STRUCTURE_INVALID,
            )

        seen.add(identity)

        if isinstance(item, list):
            if len(item) > _MAX_ARRAY_LENGTH:
                return ExecutionVerificationInputBoundsResult(
                    ok=False,
                    reason_code=REASONS.INPUT_LIMIT_EXCEEDED,
                )

            for child in reversed(item):
                stack.append((child, depth + 1))

            continue

        if type(item) is not dict:
            return ExecutionVerificationInputBoundsResult(
                ok=False,
                reason_code=REASONS.INPUT_STRUCTURE_INVALID,
            )

        object_keys += len(item)

        if object_keys > _MAX_OBJECT_KEYS:
            return ExecutionVerificationInputBoundsResult(
                ok=False,
                reason_code=REASONS.INPUT_LIMIT_EXCEEDED,
            )

        for key, child in item.items():
            if not isinstance(key, str):
                return ExecutionVerificationInputBoundsResult(
                    ok=False,
                    reason_code=REASONS.INPUT_STRUCTURE_INVALID,
                )
            if _js_length(key) > _MAX_KEY_LENGTH:
                return ExecutionVerificationInputBoundsResult(
                    ok=False,
                    reason_code=REASONS.INPUT_LIMIT_EXCEEDED,
                )

            stack.append((child, depth + 1))

    return ExecutionVerificationInputBoundsResult(
        ok=True,
        reason_code=REASONS.CHECK_PASSED,
    )


def make_verification_check(
    *,
    id: str,
    group: str,
    label: str,
    requirement: ExecutionVerificationRequirement,
    status: ExecutionVerificationCheckStatus,
    reason_code: ExecutionVerificationReasonCode,
    evidence_refs: tuple[str, ...] = (),
) -> ExecutionVerificationCheck:
    checked_id = clean_string(id)
    checked_group = clean_string(group)
    checked_label = clean_string(label)

    if not checked_id or not checked_group or not checked_label:
        raise TypeError("Verification checks require id, group, and label.")
    if requirement not in EXECUTION_VERIFICATION_REQUIREMENTS:
        raise TypeError(f"Unsupported verification requirement: {requirement}.")
    if status not in EXECUTION_VERIFICATION_CHECK_STATUSES:
        raise TypeError(f"Unsupported verification check status: {status}.")
    if not clean_string(reason_code):
        raise TypeError("Verification checks require a reason code.")

    refs = {
        cleaned
        for value in evidence_refs
        if (cleaned := clean_string(value))
    }

    return ExecutionVerificationCheck(
        id=checked_id,
        group=checked_group,
        label=checked_label,
        requirement=requirement,
        status=status,
        reason_code=reason_code,
        evidence_refs=tuple(sorted(refs, key=_js_sort_key)),
    )


def rule_pass(
    reason_code: ExecutionVerificationReasonCode = REASONS.CHECK_PASSED,
) -> ExecutionVerificationRuleResult:
    return ExecutionVerificationRuleResult(
        status="pass",
        reason_code=reason_code,
    )


def rule_fail(
    reason_code: ExecutionVerificationReasonCode,
) -> ExecutionVerificationRuleResult:
    return ExecutionVerificationRuleResult(
        status="fail",
        reason_code=reason_code,
    )


def rule_unavailable(
    reason_code: ExecutionVerificationReasonCode = REASONS.REQUIRED_EVIDENCE_MISSING,
) -> ExecutionVerificationRuleResult:
    return ExecutionVerificationRuleResult(
        status="unavailable",
        reason_code=reason_code,
    )


def rule_not_applicable(
    reason_code: ExecutionVerificationReasonCode = REASONS.NOT_APPLICABLE,
) -> ExecutionVerificationRuleResult:
    return ExecutionVerificationRuleResult(
        status="not_applicable",
        reason_code=reason_code,
    )


def outcome_status(
    checks: tuple[ExecutionVerificationCheck, ...]
    | list[ExecutionVerificationCheck],
) -> ExecutionVerificationStatus:
    applicable = tuple(
        check
        for check in checks
        if check.requirement == "required"
        or (
            check.requirement == "conditional"
            and check.status != "not_applicable"
        )
    )

    if any(check.status == "fail" for check in applicable):
        return "failed"
    if any(check.status == "unavailable" for check in applicable):
        return "incomplete"

    return "consistent"


def verification_summary(
    checks: tuple[ExecutionVerificationCheck, ...]
    | list[ExecutionVerificationCheck],
) -> ExecutionVerificationSummary:
    passed = 0
    failed = 0
    unavailable = 0
    not_applicable = 0
    outcome_relevant = 0

    for check in checks:
        if check.status == "pass":
            passed += 1
        elif check.status == "fail":
            failed += 1
        elif check.status == "unavailable":
            unavailable += 1
        else:
            not_applicable += 1

        if (
            check.requirement == "required"
            or (
                check.requirement == "conditional"
                and check.status != "not_applicable"
            )
        ):
            outcome_relevant += 1

    return ExecutionVerificationSummary(
        total=len(checks),
        outcome_relevant=outcome_relevant,
        passed=passed,
        failed=failed,
        unavailable=unavailable,
        not_applicable=not_applicable,
    )


def freeze_verification_report(
    report: ExecutionVerificationReport,
) -> ExecutionVerificationReport:
    return report


def canonicalize_execution_verification_report(
    report: ExecutionVerificationReport,
) -> str:
    value = {
        "schema_version": report.schema_version,
        "verifier_version": report.verifier_version,
        "subject": {
            "hedera_network": report.subject.hedera_network,
            "program": report.subject.program,
            "job_id": report.subject.job_id,
            "result_id": report.subject.result_id,
        },
        "status": report.status,
        "summary": {
            "total": report.summary.total,
            "outcome_relevant": report.summary.outcome_relevant,
            "passed": report.summary.passed,
            "failed": report.summary.failed,
            "unavailable": report.summary.unavailable,
            "not_applicable": report.summary.not_applicable,
        },
        "checks": [
            {
                "id": check.id,
                "group": check.group,
                "label": check.label,
                "requirement": check.requirement,
                "status": check.status,
                "reason_code": check.reason_code,
                "evidence_refs": list(check.evidence_refs),
            }
            for check in report.checks
        ],
    }

    return canonicalize_execution_verification_value(value)