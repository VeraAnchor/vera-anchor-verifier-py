"""Pure offline execution verification with explicit caller-owned scope."""

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal, NotRequired, TypedDict, cast

from ...contracts import (
    HederaNetwork,
    VerificationFact,
    VerificationFinding,
    VerificationIntent,
    VerificationObservation,
    VerificationOutcome,
    VerificationReport,
    VerificationSubject,
)
from .contract_v1 import (
    SUPPORTED_PUBLIC_STANDARDS_CONTRACT_VERSIONS,
    ExecutionVerificationCheck,
    ExecutionVerificationContext,
    ExecutionVerificationReport,
    ExecutionVerificationSubject,
    PublicExecutionStandardsEvidence,
    PublicExecutionVerificationMaterial,
    freeze_verification_report,
    make_verification_check,
    outcome_status,
    validate_execution_verification_input_bounds,
    verification_summary,
)
from .reason_codes_v1 import EXECUTION_VERIFICATION_REASON_CODES as REASONS
from .rules_v1 import COMMON_EXECUTION_VERIFICATION_RULES, EXECUTION_VERIFICATION_RULES

type ExecutionV1Profile = Literal["execution-v1", "sage-standards-v1"]


class ExecutionV1Input(TypedDict):
    evidence: object
    intent: VerificationIntent
    profile: NotRequired[ExecutionV1Profile]
    result_id: NotRequired[str | None]
    verification_material: NotRequired[PublicExecutionVerificationMaterial | None]
    expected_program: NotRequired[str]


@dataclass(frozen=True, slots=True)
class ExecutionV1VerificationScope:
    profile: ExecutionV1Profile
    expected_program: str | None
    requested_result_id: str | None


@dataclass(frozen=True, slots=True)
class ExecutionV1Report(VerificationReport):
    verification_scope: ExecutionV1VerificationScope


@dataclass(frozen=True, slots=True)
class _CheckedInput:
    network: HederaNetwork
    job_id: str
    result_id: str
    expected_program: str
    profile: ExecutionV1Profile


_UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-"
    r"[1-5][0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-"
    r"[0-9a-f]{12}$",
    re.IGNORECASE | re.ASCII,
)
_MAX_PROGRAM = 128
_SOURCE_ID = "execution.provided"
_COMPUTED_ID = "execution.recomputed"


def _js_length(value: str) -> int:
    return len(value.encode("utf-16-le", "surrogatepass")) // 2


def _mapping(value: object) -> Mapping[str, object]:
    if isinstance(value, Mapping):
        return cast(Mapping[str, object], value)
    return {}


def _fact(key: str, value: str | int | bool | None) -> VerificationFact:
    return VerificationFact(key=key, state="available", value=value)


def _finding(
    check_id: str,
    outcome: VerificationOutcome,
    reason_code: str | None,
    observation_ids: tuple[str, ...] = (),
) -> VerificationFinding:
    return VerificationFinding(
        check_id=check_id,
        outcome=outcome,
        reason_code=reason_code,
        observation_ids=observation_ids,
    )


def _map_status(check: ExecutionVerificationCheck) -> VerificationOutcome:
    if check.status == "pass":
        return "pass"
    if check.status == "fail":
        return "fail"
    if check.status == "unavailable":
        return "indeterminate"
    return "skipped"


def _checked_input(input: ExecutionV1Input) -> _CheckedInput:
    if not isinstance(input, Mapping):
        raise TypeError("Execution verification requires caller intent")

    raw_intent = input.get("intent")
    if not isinstance(raw_intent, Mapping):
        raise TypeError("Execution verification requires caller intent")

    raw_profile = input.get("profile", "sage-standards-v1")
    if raw_profile not in ("execution-v1", "sage-standards-v1"):
        raise TypeError("Unsupported execution verification profile")
    profile = raw_profile

    raw_subject = raw_intent.get("subject")
    if not isinstance(raw_subject, Mapping):
        raise TypeError("Execution intent requires an exact job UUID and Hedera network")

    subject_kind = raw_subject.get("kind")
    subject_id = raw_subject.get("id")
    network = raw_subject.get("hedera_network")
    if (
        subject_kind != "execution"
        or not isinstance(subject_id, str)
        or _UUID.fullmatch(subject_id) is None
        or network not in ("mainnet", "testnet")
    ):
        raise TypeError("Execution intent requires an exact job UUID and Hedera network")

    expected = raw_intent.get("expected")
    if not isinstance(expected, list) or expected:
        raise TypeError(
            "Execution v1 does not support generic expected commitments; "
            "supply explicit supported inputs"
        )

    raw_result_id = input.get("result_id")
    if raw_result_id is None:
        result_id = ""
    elif isinstance(raw_result_id, str):
        result_id = raw_result_id.strip().lower()
    else:
        raise TypeError("Requested result_id must be a UUID")

    if result_id and _UUID.fullmatch(result_id) is None:
        raise TypeError("Requested result_id must be a UUID")

    raw_program = input.get("expected_program")
    if raw_program is None:
        expected_program = ""
    elif isinstance(raw_program, str):
        expected_program = raw_program
    else:
        raise TypeError("Expected program must be a bounded canonical string")

    if (
        _js_length(expected_program) > _MAX_PROGRAM
        or expected_program
        and expected_program.strip() != expected_program
    ):
        raise TypeError("Expected program must be a bounded canonical string")

    if profile == "execution-v1" and not expected_program:
        raise TypeError(
            "execution-v1 requires an independently supplied expected_program"
        )

    if profile == "execution-v1" and expected_program.lower() == "sage":
        raise TypeError("SAGE requires sage-standards-v1 verification profile")

    return _CheckedInput(
        network=network,
        job_id=subject_id.lower(),
        result_id=result_id,
        expected_program=expected_program.lower(),
        profile=profile,
    )


def _check_execution_standards_v1(
    evidence_input: object,
    *,
    network: HederaNetwork,
    profile: ExecutionV1Profile,
    result_id: str,
    verification_material: PublicExecutionVerificationMaterial | None,
) -> ExecutionVerificationReport:
    bounds = validate_execution_verification_input_bounds(evidence_input)
    material_bounds = (
        None
        if verification_material is None
        else validate_execution_verification_input_bounds(verification_material)
    )
    input_error = (
        bounds.reason_code
        if not bounds.ok
        else material_bounds.reason_code
        if material_bounds is not None and not material_bounds.ok
        else None
    )

    if input_error is not None:
        check = make_verification_check(
            id="input.bounds",
            group="contract",
            label="Verification input is safely bounded and structurally supported",
            requirement="required",
            status="fail",
            reason_code=input_error,
            evidence_refs=(),
        )
        return freeze_verification_report(
            ExecutionVerificationReport(
                schema_version="vera.execution-verification.v1",
                verifier_version="1.0.0",
                subject=ExecutionVerificationSubject(
                    hedera_network=network,
                    program=None,
                    job_id=None,
                    result_id=result_id,
                ),
                status="failed",
                summary=verification_summary((check,)),
                checks=(check,),
            )
        )

    evidence = cast(PublicExecutionStandardsEvidence, evidence_input)
    context = ExecutionVerificationContext(
        evidence=evidence,
        verification_material=verification_material,
        expected_network=network,
        requested_result_id=result_id,
        supported_contract_versions=SUPPORTED_PUBLIC_STANDARDS_CONTRACT_VERSIONS,
    )
    checks: list[ExecutionVerificationCheck] = [
        make_verification_check(
            id="input.bounds",
            group="contract",
            label="Verification input is safely bounded and structurally supported",
            requirement="required",
            status="pass",
            reason_code=REASONS.CHECK_PASSED,
            evidence_refs=(),
        )
    ]

    applicable = (
        EXECUTION_VERIFICATION_RULES
        if profile == "sage-standards-v1"
        else COMMON_EXECUTION_VERIFICATION_RULES
    )
    rules = (
        applicable
        if evidence.get("available") is True
        else tuple(
            rule
            for rule in applicable
            if rule.id
            in (
                "public_evidence.available",
                "public_evidence.contract_version",
            )
        )
    )

    for rule in rules:
        result = rule.evaluate(context)
        checks.append(
            make_verification_check(
                id=rule.id,
                group=rule.group,
                label=rule.label,
                requirement=rule.requirement,
                status=result.status,
                reason_code=result.reason_code,
                evidence_refs=rule.evidence_refs,
            )
        )

    execution = _mapping(evidence.get("execution"))
    raw_network = execution.get("hedera_network")
    subject_network: HederaNetwork | None
    if raw_network == "testnet":
        subject_network = "testnet"
    elif raw_network == "mainnet":
        subject_network = "mainnet"
    else:
        subject_network = None

    raw_program = execution.get("program")
    program = (
        raw_program.strip().lower() or None
        if isinstance(raw_program, str)
        else None
    )
    raw_job_id = execution.get("job_id")
    job_id = (
        raw_job_id.strip().lower() or None
        if isinstance(raw_job_id, str)
        else None
    )

    return freeze_verification_report(
        ExecutionVerificationReport(
            schema_version="vera.execution-verification.v1",
            verifier_version="1.0.0",
            subject=ExecutionVerificationSubject(
                hedera_network=subject_network,
                program=program,
                job_id=job_id,
                result_id=result_id or None,
            ),
            status=outcome_status(checks),
            summary=verification_summary(checks),
            checks=tuple(checks),
        )
    )


def verify_execution_v1_with_intent(input: ExecutionV1Input) -> ExecutionV1Report:
    """Verify supplied execution evidence without authenticating its source."""
    checked = _checked_input(input)
    raw = _check_execution_standards_v1(
        input["evidence"],
        network=checked.network,
        profile=checked.profile,
        result_id=checked.result_id,
        verification_material=input.get("verification_material"),
    )
    safe = bool(raw.checks and raw.checks[0].status == "pass")
    evidence = (
        cast(PublicExecutionStandardsEvidence, input["evidence"]) if safe else None
    )
    execution = _mapping(evidence.get("execution")) if evidence is not None else {}
    subject = cast(
        VerificationSubject,
        {
            "kind": "execution",
            "id": checked.job_id,
            "hedera_network": checked.network,
        },
    )

    source_facts: list[VerificationFact] = []
    if raw.subject.job_id:
        source_facts.append(_fact("job_id", raw.subject.job_id))
    if raw.subject.hedera_network:
        source_facts.append(_fact("hedera_network", raw.subject.hedera_network))
    if raw.subject.program:
        source_facts.append(_fact("program", raw.subject.program))

    observations: list[VerificationObservation] = [
        VerificationObservation(
            id=_SOURCE_ID,
            subject=subject,
            source="provided_evidence",
            facts=tuple(source_facts),
        )
    ]

    recomputed = tuple(
        check
        for check in raw.checks
        if check.status == "pass"
        and (
            check.id.endswith(".digest_recomputed")
            or check.id == "acceptance.digest_recomputed"
            or check.id == "parameters.commitment_matches"
        )
    )
    recomputed_ids = {check.id for check in recomputed}

    if recomputed:
        observations.append(
            VerificationObservation(
                id=_COMPUTED_ID,
                subject=subject,
                source="local_computation",
                facts=tuple(
                    _fact(f"check.{check.id}", True)
                    for check in recomputed
                ),
            )
        )

    findings: list[VerificationFinding] = []
    for check in raw.checks:
        untrusted_resolution = check.id == "standards.references_resolved"

        if check.id == "input.bounds":
            observation_ids: tuple[str, ...] = ()
        elif check.id in recomputed_ids:
            observation_ids = (_SOURCE_ID, _COMPUTED_ID)
        else:
            observation_ids = (_SOURCE_ID,)

        findings.append(
            _finding(
                check.id,
                (
                    "indeterminate"
                    if untrusted_resolution
                    else _map_status(check)
                ),
                (
                    "STANDARDS_RESOLUTION_NOT_INDEPENDENTLY_VERIFIED"
                    if untrusted_resolution
                    else (
                        None
                        if check.reason_code
                        in (REASONS.CHECK_PASSED, REASONS.NOT_APPLICABLE)
                        else check.reason_code
                    )
                ),
                observation_ids,
            )
        )

    declared_program = raw.subject.program
    profile_matches = (
        declared_program == "sage"
        if checked.profile == "sage-standards-v1"
        else declared_program != "sage"
    )
    findings.append(
        _finding(
            "profile.program_scope",
            (
                "indeterminate"
                if not safe or not declared_program
                else "pass"
                if profile_matches
                else "fail"
            ),
            (
                "EXECUTION_PROGRAM_UNAVAILABLE"
                if not safe or not declared_program
                else None
                if profile_matches
                else "EXECUTION_PROFILE_PROGRAM_MISMATCH"
            ),
            (_SOURCE_ID,) if safe else (),
        )
    )

    if checked.profile == "execution-v1":
        findings.append(
            _finding(
                "profile.standards_scope",
                "skipped",
                "STANDARDS_PROFILE_NOT_SELECTED",
            )
        )

    actual_job = raw.subject.job_id
    findings.append(
        _finding(
            "intent.subject",
            (
                "indeterminate"
                if not safe or not actual_job
                else "pass"
                if actual_job == checked.job_id
                else "fail"
            ),
            (
                "EXECUTION_SUBJECT_UNAVAILABLE"
                if not safe or not actual_job
                else None
                if actual_job == checked.job_id
                else "SUBJECT_MISMATCH"
            ),
            (_SOURCE_ID,) if safe else (),
        )
    )

    if checked.result_id:
        result_evidence = (
            _mapping(evidence.get("result_evidence"))
            if evidence is not None
            else {}
        )
        raw_result = result_evidence.get("result_id")
        actual_result = (
            raw_result.strip().lower()
            if isinstance(raw_result, str)
            else ""
        )
        findings.append(
            _finding(
                "intent.result",
                (
                    "indeterminate"
                    if not safe or not actual_result
                    else "pass"
                    if actual_result == checked.result_id
                    else "fail"
                ),
                (
                    "RESULT_EVIDENCE_UNAVAILABLE"
                    if not safe or not actual_result
                    else None
                    if actual_result == checked.result_id
                    else "RESULT_SCOPE_MISMATCH"
                ),
                (_SOURCE_ID,) if safe else (),
            )
        )

    if checked.expected_program:
        raw_program = execution.get("program")
        actual_program = (
            raw_program.strip().lower()
            if isinstance(raw_program, str)
            else ""
        )
        findings.append(
            _finding(
                "intent.program",
                (
                    "indeterminate"
                    if not safe or not actual_program
                    else "pass"
                    if actual_program == checked.expected_program
                    else "fail"
                ),
                (
                    "EXECUTION_PROGRAM_UNAVAILABLE"
                    if not safe or not actual_program
                    else None
                    if actual_program == checked.expected_program
                    else "PROGRAM_MISMATCH"
                ),
                (_SOURCE_ID,) if safe else (),
            )
        )

    return ExecutionV1Report(
        intent=cast(
            VerificationIntent,
            {
                "subject": subject,
                "expected": [],
            },
        ),
        findings=tuple(findings),
        observations=tuple(observations),
        verification_scope=ExecutionV1VerificationScope(
            profile=checked.profile,
            expected_program=checked.expected_program or None,
            requested_result_id=checked.result_id or None,
        ),
    )