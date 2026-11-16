"""Pure preparation of execution triangulation authority plans."""

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal, cast

from ..contracts import (
    HederaNetwork,
    VerificationFact,
    VerificationObservation,
    VerificationSubject,
)
from ..profiles.execution.contract_v1 import PublicExecutionStandardsEvidence
from ..profiles.execution.verification_v1 import (
    ExecutionV1Input,
    ExecutionV1Report,
    verify_execution_v1_with_intent,
)
from .compare_v1 import (
    TriangulationFactPlanV1,
    TriangulationRelationshipPlanV1,
    TriangulationV1Input,
)

_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE | re.ASCII,
)
_HASH_RE = re.compile(r"^[0-9a-f]{128}$", re.IGNORECASE | re.ASCII)
_TOPIC_RE = re.compile(r"^0\.0\.[0-9]+$", re.ASCII)
_TRANSACTION_RE = re.compile(
    r"^(0\.0\.[0-9]+)[@-]([0-9]{1,12})[.\-]([0-9]{1,9})$", re.ASCII
)
_MESSAGE_RE = re.compile(
    r"^(?:([1-9][0-9]*)@(0\.0\.[0-9]+)|(0\.0\.[0-9]+)@([1-9][0-9]*))$",
    re.ASCII,
)

_MAX_SAFE_INTEGER = (1 << 53) - 1
_PROVIDED_ID = "execution.provided.claims"
_PUBLIC_ID = "execution.public"
EXECUTION_HEDERA_OBSERVATION_V1_ID = "execution.hedera"

type ExecutionEvidenceSideV1 = Literal["provided_evidence", "public_record"]
type ExecutionHederaRoleV1 = Literal["acceptance_anchor", "result_evidence_anchor"]


@dataclass(frozen=True, slots=True)
class ExecutionHederaTargetV1:
    source: ExecutionEvidenceSideV1
    role: ExecutionHederaRoleV1
    network: HederaNetwork
    transaction_id: str | None
    topic_id: str | None
    sequence_number: int | None
    observation_fact_prefix: str


@dataclass(frozen=True, slots=True)
class ExecutionTriangulationPlanV1:
    stage: Literal["unresolved_authority_plan"]
    public_record_acquisition: Literal["not_checked"]
    hedera_resolution: Literal["not_checked"]
    source_report: ExecutionV1Report
    triangulation: TriangulationV1Input
    hedera_targets: tuple[ExecutionHederaTargetV1, ...]


def _js_length(value: str) -> int:
    return len(value.encode("utf-16-le", "surrogatepass")) // 2


def _mapping(value: object) -> Mapping[str, object]:
    if isinstance(value, Mapping):
        return cast(Mapping[str, object], value)
    return {}


def _record(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise TypeError(f"{field} must be an object")
    return cast(Mapping[str, object], value)


def _optional(value: object, field: str, limit: int = 256) -> str | None:
    if value is None or value == "":
        return None
    if not isinstance(value, str) or _js_length(value) > limit or value != value.strip():
        raise TypeError(f"{field} must be a bounded canonical string")
    return value


def _scoped_uuid(value: object, field: str, required: bool = False) -> str | None:
    raw = _optional(value, field, 64)
    normalized = raw.lower() if raw is not None else None
    if (required and normalized is None) or (
        normalized is not None and _UUID_RE.fullmatch(normalized) is None
    ):
        raise TypeError(f"{field} must be a UUID")
    return normalized


def _digest(value: object, field: str) -> str | None:
    raw = _optional(value, field, 128)
    normalized = raw.lower() if raw is not None else None
    if normalized is not None and _HASH_RE.fullmatch(normalized) is None:
        raise TypeError(f"{field} must be SHA3-512 hex")
    return normalized


def _transaction(value: object, field: str) -> str | None:
    raw = _optional(value, field, 128)
    if raw is None:
        return None

    match = _TRANSACTION_RE.fullmatch(raw)
    if match is None:
        raise TypeError(f"{field} must be a Hedera transaction identifier")
    return f"{match.group(1)}@{match.group(2)}.{match.group(3).zfill(9)}"


def _message_scope(value: object) -> tuple[str, int] | None:
    raw = _optional(value, "acceptance.hcs.message_id", 128)
    if raw is None:
        return None

    match = _MESSAGE_RE.fullmatch(raw)
    if match is None:
        raise TypeError("Invalid acceptance HCS message identifier")

    raw_number = match.group(1) or match.group(4)
    topic_id = match.group(2) or match.group(3)
    if raw_number is None or topic_id is None:
        raise TypeError("Invalid acceptance HCS message identifier")

    sequence_number = int(raw_number)
    if not 1 <= sequence_number <= _MAX_SAFE_INTEGER:
        raise TypeError("Invalid HCS message sequence")
    return topic_id, sequence_number


def _ledger_claim(
    value: object,
    source: ExecutionEvidenceSideV1,
    role: ExecutionHederaRoleV1,
    network: HederaNetwork,
) -> ExecutionHederaTargetV1 | None:
    if value is None:
        return None

    hcs = _record(value, f"{role}.hcs")
    transaction_id = _transaction(
        hcs.get("transaction_id"), f"{role}.hcs.transaction_id"
    )
    message = _message_scope(hcs.get("message_id")) if role == "acceptance_anchor" else None
    raw_topic = _optional(hcs.get("topic_id"), f"{role}.hcs.topic_id", 64)
    if raw_topic is not None and _TOPIC_RE.fullmatch(raw_topic) is None:
        raise TypeError("Invalid HCS topic identifier")

    raw_sequence = hcs.get("sequence_number")
    if raw_sequence is None:
        sequence_number: int | None = None
    else:
        if type(raw_sequence) is not int or not 1 <= raw_sequence <= _MAX_SAFE_INTEGER:
            raise TypeError("Invalid HCS sequence number")
        sequence_number = raw_sequence

    if message is not None:
        message_topic, message_sequence = message
        if (raw_topic is not None and raw_topic != message_topic) or (
            sequence_number is not None and sequence_number != message_sequence
        ):
            raise TypeError("HCS message locator conflict")
    else:
        message_topic = None
        message_sequence = None

    topic_id = raw_topic if raw_topic is not None else message_topic
    sequence_number = sequence_number if sequence_number is not None else message_sequence

    if (topic_id is None) != (sequence_number is None):
        if transaction_id is None:
            raise TypeError("Incomplete HCS message locator")
        topic_id = None
        sequence_number = None

    if transaction_id is None and topic_id is None:
        return None

    return ExecutionHederaTargetV1(
        source=source,
        role=role,
        network=network,
        transaction_id=transaction_id,
        topic_id=topic_id,
        sequence_number=sequence_number,
        observation_fact_prefix=f"ledger.{source}.{role}",
    )


def _fact(key: str, value: str | None) -> VerificationFact:
    if value is None:
        return VerificationFact(
            key=key,
            state="unavailable",
            reason_code="EXECUTION_COMMITMENT_UNAVAILABLE",
        )
    return VerificationFact(key=key, state="available", value=value)


def _scope_facts(
    evidence: Mapping[str, object],
    result_id: str | None,
) -> list[VerificationFact]:
    execution = _mapping(evidence.get("execution"))
    dataset = _mapping(execution.get("dataset"))
    binding = _mapping(evidence.get("binding"))
    acceptance = _mapping(evidence.get("acceptance"))
    result_evidence = _mapping(evidence.get("result_evidence"))

    facts = [
        _fact("execution.job_id", _scoped_uuid(execution.get("job_id"), "execution.job_id")),
        _fact(
            "execution.hedera_network",
            _optional(execution.get("hedera_network"), "execution.hedera_network", 16),
        ),
        _fact(
            "execution.program",
            (
                value.lower()
                if (value := _optional(execution.get("program"), "execution.program", 128))
                is not None
                else None
            ),
        ),
        _fact(
            "execution.pipeline_hash",
            _digest(execution.get("pipeline_hash"), "execution.pipeline_hash"),
        ),
        _fact(
            "dataset.fingerprint_sha3_512",
            _digest(
                dataset.get("dataset_fingerprint_sha3_512"),
                "dataset.fingerprint",
            ),
        ),
        _fact(
            "dataset.manifest_sha3_512",
            _digest(dataset.get("dataset_manifest_sha3_512"), "dataset.manifest"),
        ),
        _fact("binding.digest", _digest(binding.get("digest"), "binding.digest")),
        _fact(
            "acceptance.digest",
            _digest(acceptance.get("digest"), "acceptance.digest"),
        ),
    ]

    if result_id is not None:
        facts.extend(
            (
                _fact(
                    "execution.result_id",
                    _scoped_uuid(
                        result_evidence.get("result_id")
                        if result_evidence.get("result_id") is not None
                        else execution.get("result_id"),
                        "result_id",
                    ),
                ),
                _fact(
                    "result_evidence.digest",
                    _digest(result_evidence.get("digest"), "result_evidence.digest"),
                ),
                _fact(
                    "result_evidence.result_hash",
                    _digest(result_evidence.get("result_hash"), "result_hash"),
                ),
                _fact(
                    "result_evidence.service_hash",
                    _digest(result_evidence.get("service_hash"), "service_hash"),
                ),
                _fact(
                    "result_evidence.global_hash",
                    _digest(result_evidence.get("global_hash"), "global_hash"),
                ),
            )
        )

    return facts


def _claim_facts(
    facts: list[VerificationFact],
    claims: tuple[ExecutionHederaTargetV1, ...],
    result_id: str | None,
) -> None:
    roles: tuple[ExecutionHederaRoleV1, ...] = (
        ("acceptance_anchor", "result_evidence_anchor")
        if result_id is not None
        else ("acceptance_anchor",)
    )

    for role in roles:
        claim = next((candidate for candidate in claims if candidate.role == role), None)
        facts.extend(
            (
                _fact(
                    f"{role}.transaction_id",
                    claim.transaction_id if claim is not None else None,
                ),
                _fact(f"{role}.topic_id", claim.topic_id if claim is not None else None),
                _fact(
                    f"{role}.sequence_number",
                    str(claim.sequence_number)
                    if claim is not None and claim.sequence_number is not None
                    else None,
                ),
            )
        )


def _observation(
    evidence: Mapping[str, object],
    side: ExecutionEvidenceSideV1,
    subject: VerificationSubject,
    result_id: str | None,
    targets: tuple[ExecutionHederaTargetV1, ...],
) -> VerificationObservation:
    facts = _scope_facts(evidence, result_id)
    _claim_facts(facts, targets, result_id)
    return VerificationObservation(
        id=_PUBLIC_ID if side == "public_record" else _PROVIDED_ID,
        subject=cast(VerificationSubject, dict(subject)),
        source=side,
        resolver_id=None,
        facts=tuple(facts),
    )


def _targets_of(
    evidence: Mapping[str, object],
    side: ExecutionEvidenceSideV1,
    network: HederaNetwork,
    result_id: str | None,
) -> tuple[ExecutionHederaTargetV1, ...]:
    acceptance = _mapping(evidence.get("acceptance"))
    result_evidence = _mapping(evidence.get("result_evidence"))
    targets: list[ExecutionHederaTargetV1] = []

    acceptance_target = _ledger_claim(
        acceptance.get("hcs"), side, "acceptance_anchor", network
    )
    if acceptance_target is not None:
        targets.append(acceptance_target)

    if result_id is not None:
        result_target = _ledger_claim(
            result_evidence.get("hcs"), side, "result_evidence_anchor", network
        )
        if result_target is not None:
            targets.append(result_target)

    return tuple(targets)


def _pairs(
    left: VerificationObservation,
    right: VerificationObservation,
) -> tuple[TriangulationFactPlanV1, ...]:
    right_keys = {fact.key for fact in right.facts}
    return tuple(
        TriangulationFactPlanV1(key=fact.key, left_key=fact.key, right_key=fact.key)
        for fact in left.facts
        if fact.state == "available" and fact.key in right_keys
    )


def _hedera_comparisons(
    targets: tuple[ExecutionHederaTargetV1, ...],
) -> tuple[TriangulationFactPlanV1, ...]:
    comparisons: list[TriangulationFactPlanV1] = []

    for target in targets:
        base = target.observation_fact_prefix
        if target.transaction_id is not None:
            comparisons.append(
                TriangulationFactPlanV1(
                    key=f"{target.role}.transaction_id",
                    left_key=f"{target.role}.transaction_id",
                    right_key=f"{base}.transaction_id",
                )
            )
        if target.topic_id is not None and target.sequence_number is not None:
            comparisons.extend(
                (
                    TriangulationFactPlanV1(
                        key=f"{target.role}.topic_id",
                        left_key=f"{target.role}.topic_id",
                        right_key=f"{base}.topic_id",
                    ),
                    TriangulationFactPlanV1(
                        key=f"{target.role}.sequence_number",
                        left_key=f"{target.role}.sequence_number",
                        right_key=f"{base}.sequence_number",
                    ),
                )
            )

    return tuple(comparisons)


def _required_network(subject: VerificationSubject) -> HederaNetwork:
    network = subject.get("hedera_network")
    if network == "mainnet":
        return "mainnet"
    if network == "testnet":
        return "testnet"
    raise TypeError("Execution network is required")


def prepare_execution_triangulation_v1(
    execution: ExecutionV1Input,
    public_evidence: PublicExecutionStandardsEvidence,
) -> ExecutionTriangulationPlanV1:
    """Prepare provided/public comparisons and exact unresolved Hedera targets."""
    source = verify_execution_v1_with_intent(execution)
    input_bounds = next(
        (finding for finding in source.findings if finding.check_id == "input.bounds"),
        None,
    )
    if input_bounds is None or input_bounds.outcome != "pass":
        raise TypeError("Provided execution evidence failed structural bounds")

    subject = source.intent["subject"]
    network = _required_network(subject)
    requested_result = source.verification_scope.requested_result_id
    public = _record(public_evidence, "public execution evidence")

    if public.get("available") is not True:
        raise TypeError("Public execution evidence is unavailable")

    public_execution = _mapping(public.get("execution"))
    if (
        _scoped_uuid(
            public_execution.get("job_id"),
            "public.execution.job_id",
            required=True,
        )
        != subject["id"]
        or public_execution.get("hedera_network") != network
    ):
        raise TypeError("Public execution scope mismatch")

    if requested_result is not None:
        public_result_evidence = _mapping(public.get("result_evidence"))
        raw_public_result = (
            public_result_evidence.get("result_id")
            if public_result_evidence.get("result_id") is not None
            else public_execution.get("result_id")
        )
        actual = _scoped_uuid(raw_public_result, "public.result_id", required=True)
        if actual != requested_result:
            raise TypeError("Public execution result scope mismatch")

    provided = _record(execution["evidence"], "provided execution evidence")
    provided_execution = _mapping(provided.get("execution"))

    if requested_result is not None:
        provided_result_evidence = _mapping(provided.get("result_evidence"))
        raw_provided_result = (
            provided_result_evidence.get("result_id")
            if provided_result_evidence.get("result_id") is not None
            else provided_execution.get("result_id")
        )
        provided_result = _scoped_uuid(raw_provided_result, "provided.result_id")
        if provided_result is not None and provided_result != requested_result:
            raise TypeError("Provided result scope mismatch")

    provided_job = provided_execution.get("job_id")
    if (
        provided_job is not None
        and _scoped_uuid(provided_job, "provided.job_id") != subject["id"]
    ):
        raise TypeError("Provided execution job scope mismatch")

    provided_network = provided_execution.get("hedera_network")
    if provided_network is not None and provided_network != network:
        raise TypeError("Provided execution network scope mismatch")

    public_targets = _targets_of(public, "public_record", network, requested_result)
    provided_targets = _targets_of(provided, "provided_evidence", network, requested_result)
    public_observation = _observation(
        public, "public_record", subject, requested_result, public_targets
    )
    provided_observation = _observation(
        provided, "provided_evidence", subject, requested_result, provided_targets
    )

    relationships = (
        TriangulationRelationshipPlanV1(
            id="provided_public_record",
            left_observation_id=_PROVIDED_ID,
            right_observation_id=_PUBLIC_ID,
            comparisons=_pairs(provided_observation, public_observation),
        ),
        TriangulationRelationshipPlanV1(
            id="public_record_hedera",
            left_observation_id=_PUBLIC_ID,
            right_observation_id=EXECUTION_HEDERA_OBSERVATION_V1_ID,
            comparisons=_hedera_comparisons(public_targets),
        ),
        TriangulationRelationshipPlanV1(
            id="provided_hedera",
            left_observation_id=_PROVIDED_ID,
            right_observation_id=EXECUTION_HEDERA_OBSERVATION_V1_ID,
            comparisons=_hedera_comparisons(provided_targets),
        ),
    )

    return ExecutionTriangulationPlanV1(
        stage="unresolved_authority_plan",
        public_record_acquisition="not_checked",
        hedera_resolution="not_checked",
        source_report=source,
        triangulation=TriangulationV1Input(
            source_report=source,
            observations=(provided_observation, public_observation),
            relationships=relationships,
        ),
        hedera_targets=(*public_targets, *provided_targets),
    )


__all__ = [
    "EXECUTION_HEDERA_OBSERVATION_V1_ID",
    "ExecutionHederaTargetV1",
    "ExecutionTriangulationPlanV1",
    "prepare_execution_triangulation_v1",
]