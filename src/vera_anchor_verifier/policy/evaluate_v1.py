"""Exact relying-party verification policy evaluation."""

import re
from collections.abc import Mapping
from typing import Literal, cast

from ..contracts import HederaNetwork, VerificationSubject, VerificationSubjectKind
from ..profiles.execution.independent_standards_v1 import (
    verify_execution_with_independent_standards_v1,
)
from ..profiles.execution.verification_v1 import (
    ExecutionV1Input,
    verify_execution_v1_with_intent,
)
from ..profiles.source_v1_helpers import SourceV1File, SourceV1Limits
from ..reports.portable_v1 import (
    PortableVerificationReportV1,
    PortableVerificationReportV1Input,
    create_portable_verification_report_v1,
)
from ..reports.validation_v1 import validate_portable_verification_report_v1
from ..resolvers.hcs1_mirror_v1 import Hcs1MirrorV1Config
from ..standards.hcs.hcs1_v1 import Hcs1V1ContentOptions
from ..triangulation.authorized_dataset_v1 import (
    AuthorizedDatasetTriangulationV1Config,
    AuthorizedDatasetTriangulationV1Input,
    triangulate_authorized_dataset_v1,
)
from ..triangulation.authorized_ingest_v1 import (
    AuthorizedIngestTriangulationV1Config,
    AuthorizedIngestTriangulationV1Input,
    triangulate_authorized_ingest_v1,
)
from ..triangulation.execution_public_v1 import (
    PublicExecutionTriangulationV1Config,
    triangulate_public_execution_v1,
)
from ..triangulation.public_v1 import (
    PublicTriangulationV1Config,
    triangulate_dataset_v1,
    triangulate_ingest_v1,
)
from ..verification.source_intent_v1 import (
    verify_dataset_v1_with_intent,
    verify_ingest_v1_with_intent,
)
from .contract_v1 import (
    VERIFICATION_POLICY_SCHEMA_VERSION,
    VerificationPolicyAssuranceV1,
    VerificationPolicyAuthorityV1,
    VerificationPolicyDecisionStatusV1,
    VerificationPolicyDecisionV1,
    VerificationPolicyExecutionScopeV1,
    VerificationPolicyRequirementOutcomeV1,
    VerificationPolicyRequirementV1,
    VerificationPolicyV1,
    VerificationPolicyWorkflowV1,
)

_CHECK_ID_RE = re.compile(r"^[a-z][a-z0-9._:-]{0,159}$", re.ASCII)
_UUID_RE = re.compile(
    r"^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-"
    r"[89ab][a-f0-9]{3}-[a-f0-9]{12}$",
    re.IGNORECASE | re.ASCII,
)
_REPORT_KINDS = {
    "verification",
    "execution",
    "independent_standards",
    "public_triangulation",
    "authorized_dataset_triangulation",
    "authorized_ingest_triangulation",
    "execution_triangulation",
}
_EXECUTION_KINDS = {"execution", "independent_standards", "execution_triangulation"}
_NETWORK_SCOPED_KINDS = {
    "execution",
    "independent_standards",
    "public_triangulation",
    "authorized_dataset_triangulation",
    "authorized_ingest_triangulation",
    "execution_triangulation",
}
_SUBJECT_KINDS = {
    "artifact",
    "dataset",
    "ingest",
    "evidence_package",
    "merkle_anchor",
    "merkle_root",
    "merkle_leaf",
    "execution",
    "result",
}
_MISSING = object()


def _js_length(value: str) -> int:
    return len(value.encode("utf-16-le", "surrogatepass")) // 2


def _identifier(value: object, name: str, maximum: int = 160) -> str:
    if (
        not isinstance(value, str)
        or not value
        or _js_length(value) > maximum
        or value.strip() != value
    ):
        raise TypeError(f"Invalid {name}")
    try:
        value.encode("utf-16-le", "surrogatepass").decode("utf-16-le", "strict")
    except UnicodeDecodeError as exc:
        raise TypeError(f"Invalid {name}") from exc
    return value


def _checked_subject(value: object) -> VerificationSubject:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise TypeError("Invalid policy subject")
    if set(value) - {"kind", "id", "hedera_network"}:
        raise TypeError("Unknown policy subject field")

    kind = value.get("kind")
    if kind not in _SUBJECT_KINDS:
        raise TypeError("Invalid policy subject kind")

    subject_id = _identifier(value.get("id"), "policy subject ID", 256)
    network = value.get("hedera_network")
    if network is not None and network not in ("mainnet", "testnet"):
        raise TypeError("Invalid policy network")

    subject: VerificationSubject = {
        "kind": cast(VerificationSubjectKind, kind),
        "id": subject_id,
    }
    if network is not None:
        subject["hedera_network"] = cast(HederaNetwork, network)
    return subject


def _checked_string_list(value: object, name: str, maximum: int) -> tuple[str, ...]:
    if not isinstance(value, (tuple, list)) or not value or len(value) > maximum:
        raise TypeError(f"Invalid {name}")
    result = sorted(_identifier(item, name) for item in value)
    if any(item == result[index - 1] for index, item in enumerate(result) if index):
        raise TypeError(f"Duplicate {name}")
    return tuple(result)


def _checked_assurance(value: object) -> tuple[VerificationPolicyAssuranceV1, ...]:
    if value == ():
        return ()
    if not isinstance(value, (tuple, list)) or len(value) > 1:
        raise TypeError("Invalid required assurance")
    if not value:
        return ()
    if value[0] != "mirror_corroboration":
        raise TypeError("Unsupported assurance dimension")
    return ("mirror_corroboration",)


def _checked_execution_scope(value: object) -> VerificationPolicyExecutionScopeV1:
    if not isinstance(value, VerificationPolicyExecutionScopeV1):
        raise TypeError("Invalid policy execution scope")
    if value.profile not in ("execution-v1", "sage-standards-v1"):
        raise TypeError("Invalid policy execution profile")

    expected_program = value.expected_program
    if expected_program is not None:
        expected_program = _identifier(expected_program, "expected program", 128)
    if value.profile == "execution-v1" and expected_program is None:
        raise TypeError("Generic execution requires expected program")

    requested_result_id = value.requested_result_id
    if requested_result_id is not None and (
        not isinstance(requested_result_id, str)
        or _UUID_RE.fullmatch(requested_result_id) is None
    ):
        raise TypeError("Invalid expected result UUID")

    return VerificationPolicyExecutionScopeV1(
        profile=value.profile,
        expected_program=expected_program,
        requested_result_id=requested_result_id,
    )


def _checked_policy(value: VerificationPolicyV1) -> VerificationPolicyV1:
    if not isinstance(value, VerificationPolicyV1):
        raise TypeError("Invalid verification policy")
    if (
        value.schema_version != VERIFICATION_POLICY_SCHEMA_VERSION
        or value.report_kind not in _REPORT_KINDS
    ):
        raise TypeError("Unsupported verification policy contract")

    subject = _checked_subject(value.subject)
    if value.report_kind in _NETWORK_SCOPED_KINDS and "hedera_network" not in subject:
        raise TypeError("Network-scoped policy requires explicit Hedera network")

    checks = _checked_string_list(value.required_checks, "required check", 64)
    if any(_CHECK_ID_RE.fullmatch(check) is None for check in checks):
        raise TypeError("Invalid required check")

    assurance = _checked_assurance(value.required_assurance)
    if value.on_unresolved not in ("review", "deny"):
        raise TypeError("Invalid unresolved policy behavior")

    execution_kind = value.report_kind in _EXECUTION_KINDS
    if execution_kind != (value.execution_scope is not None):
        raise TypeError(
            "Execution policy requires exact execution scope; "
            "non-execution policy must omit it"
        )
    execution_scope = (
        _checked_execution_scope(value.execution_scope) if execution_kind else None
    )

    return VerificationPolicyV1(
        schema_version="va.verification-policy.v1",
        subject=subject,
        report_kind=value.report_kind,
        required_checks=checks,
        required_assurance=assurance,
        execution_scope=execution_scope,
        on_unresolved=value.on_unresolved,
    )


def _outcome(
    key: str,
    state: VerificationPolicyRequirementOutcomeV1,
    reason_code: str | None,
) -> VerificationPolicyRequirementV1:
    return VerificationPolicyRequirementV1(
        key=key,
        outcome=state,
        reason_code=reason_code,
    )


def _portable_row(value: object) -> Mapping[str, object]:
    if isinstance(value, PortableVerificationReportV1):
        return {
            "schema_version": value.schema_version,
            "kind": value.kind,
            "core_sha3_512": value.core_sha3_512,
            "report_sha3_512": value.report_sha3_512,
            "core": value.core,
            "context": value.context,
        }
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise TypeError("Invalid portable report")
    return cast(Mapping[str, object], value)


def _mapping(value: object, name: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise TypeError(f"Invalid {name}")
    return cast(Mapping[str, object], value)


def _sequence(value: object, name: str) -> tuple[object, ...]:
    if not isinstance(value, (tuple, list)):
        raise TypeError(f"Invalid {name}")
    return tuple(value)


def _core(report: Mapping[str, object]) -> Mapping[str, object]:
    return _mapping(report.get("core"), "portable core")


def _context(report: Mapping[str, object]) -> Mapping[str, object]:
    return _mapping(report.get("context"), "portable context")


def _finding(core: Mapping[str, object], check_id: str) -> Mapping[str, object] | None:
    for value in _sequence(core.get("findings"), "portable findings"):
        row = _mapping(value, "portable finding")
        if row.get("check_id") == check_id:
            return row
    return None


def _relationships(
    context: Mapping[str, object],
) -> tuple[Mapping[str, object], ...]:
    raw = context.get("relationships")
    if not isinstance(raw, (tuple, list)):
        return ()
    return tuple(_mapping(item, "portable relationship") for item in raw)


def _scope_matches(
    context: Mapping[str, object],
    expected: VerificationPolicyExecutionScopeV1,
) -> bool:
    raw = context.get("verification_scope")
    if not isinstance(raw, Mapping):
        return False
    return (
        raw.get("profile") == expected.profile
        and raw.get("expected_program") == expected.expected_program
        and raw.get("requested_result_id") == expected.requested_result_id
    )


def _assurance(
    report: Mapping[str, object],
    requirement: VerificationPolicyAssuranceV1,
) -> VerificationPolicyRequirementV1:
    context = _context(report)
    kind = report.get("kind")
    established = False

    if requirement == "mirror_corroboration":
        if kind == "independent_standards":
            standards = _mapping(
                context.get("independent_standards"),
                "independent standards",
            )
            established = (
                standards.get("status") == "verified"
                and standards.get("assurance") == "mirror_corroborated"
            )
        elif kind == "execution_triangulation":
            public = _mapping(context.get("public_execution"), "public execution")
            triangulation = context.get("triangulation")
            if isinstance(triangulation, Mapping):
                relationships = _relationships(
                    _mapping(triangulation, "execution triangulation")
                )
                established = public.get("mirror_status") == "resolved" and any(
                    relationship.get("id")
                    in ("provided_hedera", "public_record_hedera")
                    and relationship.get("status") == "consistent"
                    for relationship in relationships
                )
        elif kind in (
            "public_triangulation",
            "authorized_dataset_triangulation",
            "authorized_ingest_triangulation",
        ):
            resolution = _mapping(context.get("resolution"), "portable resolution")
            relationships = _relationships(context)
            relationship_id = (
                "public_record_hedera"
                if kind == "public_triangulation"
                else "authorized_hedera"
            )
            established = resolution.get("hedera_mirror") == "resolved" and any(
                relationship.get("id") == relationship_id
                and relationship.get("status") == "consistent"
                for relationship in relationships
            )

    return _outcome(
        f"assurance.{requirement}",
        "pass" if established else "unresolved",
        None if established else "POLICY_ASSURANCE_NOT_ESTABLISHED",
    )


def _public_evidence(
    report: Mapping[str, object],
) -> VerificationPolicyRequirementV1 | None:
    kind = report.get("kind")
    context = _context(report)

    if kind == "public_triangulation":
        resolution = _mapping(context.get("resolution"), "public resolution")
        relationships = _relationships(context)
        statuses = (
            resolution.get("public_record"),
            resolution.get("publication_disclosure"),
            resolution.get("hedera_mirror"),
        )
        conflicting = context.get("consistency") == "conflict" or any(
            status in ("conflict", "invalid") for status in statuses
        )
        complete = (
            context.get("consistency") == "consistent"
            and all(status == "resolved" for status in statuses)
            and all(
                any(
                    relationship.get("id") == relationship_id
                    and relationship.get("status") == "consistent"
                    for relationship in relationships
                )
                for relationship_id in (
                    "provided_public_record",
                    "public_record_hedera",
                )
            )
        )
    elif kind == "execution_triangulation":
        public = _mapping(context.get("public_execution"), "public execution")
        triangulation = context.get("triangulation")
        tri = (
            _mapping(triangulation, "execution triangulation")
            if isinstance(triangulation, Mapping)
            else None
        )
        relationships = _relationships(tri) if tri is not None else ()
        conflicting = (
            public.get("status") in ("conflict", "invalid")
            or (tri is not None and tri.get("consistency") == "conflict")
        )
        complete = (
            public.get("status") == "resolved"
            and public.get("public_record_acquisition") == "resolved"
            and public.get("mirror_status") == "resolved"
            and tri is not None
            and tri.get("consistency") == "consistent"
            and any(
                relationship.get("id")
                in ("provided_hedera", "public_record_hedera")
                and relationship.get("status") == "consistent"
                for relationship in relationships
            )
        )
    else:
        return None

    return _outcome(
        "verification.public_evidence",
        "fail" if conflicting else "pass" if complete else "unresolved",
        (
            "POLICY_PUBLIC_EVIDENCE_CONFLICT"
            if conflicting
            else None
            if complete
            else "POLICY_PUBLIC_EVIDENCE_INCOMPLETE"
        ),
    )


def _authorized_evidence(
    report: Mapping[str, object],
) -> VerificationPolicyRequirementV1 | None:
    kind = report.get("kind")
    if kind not in (
        "authorized_dataset_triangulation",
        "authorized_ingest_triangulation",
    ):
        return None

    context = _context(report)
    resolution = _mapping(context.get("resolution"), "authorized resolution")
    relationships = _relationships(context)
    profile_status = (
        resolution.get("dataset_registry_event")
        if kind == "authorized_dataset_triangulation"
        else resolution.get("ingest_receipt")
    )
    conflicting = (
        context.get("consistency") == "conflict"
        or resolution.get("authorized_core") == "invalid"
        or resolution.get("hedera_mirror") in ("invalid", "conflict")
        or profile_status in ("invalid", "conflict")
    )
    complete = (
        context.get("consistency") == "consistent"
        and resolution.get("authorized_core") == "resolved"
        and resolution.get("hedera_mirror") == "resolved"
        and profile_status == "resolved"
        and all(
            any(
                relationship.get("id") == relationship_id
                and relationship.get("status") == "consistent"
                for relationship in relationships
            )
            for relationship_id in ("provided_authorized", "authorized_hedera")
        )
    )

    return _outcome(
        "verification.authorized_evidence",
        "fail" if conflicting else "pass" if complete else "unresolved",
        (
            "POLICY_AUTHORIZED_EVIDENCE_CONFLICT"
            if conflicting
            else None
            if complete
            else "POLICY_AUTHORIZED_EVIDENCE_INCOMPLETE"
        ),
    )


def _has_local_support(
    report: Mapping[str, object],
    required_checks: tuple[str, ...],
) -> bool:
    core = _core(report)
    observations = {
        str(row.get("id")): row
        for row in (
            _mapping(value, "portable observation")
            for value in _sequence(core.get("observations"), "portable observations")
        )
    }

    for key in required_checks:
        check = _finding(core, key)
        if check is None or check.get("outcome") != "pass":
            continue

        observation_ids = _sequence(
            check.get("observation_ids"),
            "finding observation IDs",
        )
        if any(
            (observation := observations.get(str(observation_id))) is not None
            and observation.get("source") == "local_computation"
            for observation_id in observation_ids
        ):
            return True

    return False


def _has_failed_finding(core: Mapping[str, object]) -> bool:
    return any(
        _mapping(value, "portable finding").get("outcome") == "fail"
        for value in _sequence(core.get("findings"), "portable findings")
    )


def _decide(
    report_value: object,
    value: VerificationPolicyV1,
    authority: VerificationPolicyAuthorityV1,
) -> VerificationPolicyDecisionV1:
    policy = _checked_policy(value)
    validity = validate_portable_verification_report_v1(report_value)

    if validity.status != "valid":
        return VerificationPolicyDecisionV1(
            decision="deny",
            report_sha3_512=None,
            authority=authority,
            requirements=(
                _outcome("report.integrity", "fail", validity.reason_code),
            ),
            reason_codes=("POLICY_REPORT_INVALID",),
        )

    report = _portable_row(report_value)
    core = _core(report)
    context = _context(report)
    intent = _mapping(core.get("intent"), "portable intent")
    subject = _mapping(intent.get("subject"), "portable subject")
    expected = policy.subject
    same_subject = (
        subject.get("kind") == expected["kind"]
        and subject.get("id") == expected["id"]
        and subject.get("hedera_network") == expected.get("hedera_network")
    )

    requirements: list[VerificationPolicyRequirementV1] = [
        _outcome(
            "intent.subject",
            "pass" if same_subject else "fail",
            None if same_subject else "POLICY_SUBJECT_MISMATCH",
        ),
        _outcome(
            "report.kind",
            "pass" if report.get("kind") == policy.report_kind else "fail",
            None
            if report.get("kind") == policy.report_kind
            else "POLICY_PROFILE_MISMATCH",
        ),
    ]

    if policy.execution_scope is not None:
        matched = (
            report.get("kind") == policy.report_kind
            and _scope_matches(context, policy.execution_scope)
        )
        requirements.append(
            _outcome(
                "execution.scope",
                "pass" if matched else "fail",
                None if matched else "POLICY_EXECUTION_SCOPE_MISMATCH",
            )
        )

    intent_finding = _finding(core, "intent.subject")
    intent_outcome = None if intent_finding is None else intent_finding.get("outcome")
    requirements.append(
        _outcome(
            "verification.intent.subject",
            (
                "pass"
                if intent_outcome == "pass"
                else "fail"
                if intent_outcome == "fail"
                else "unresolved"
            ),
            (
                None
                if intent_outcome == "pass"
                else "POLICY_INTENT_FAILED"
                if intent_outcome == "fail"
                else "POLICY_INTENT_UNRESOLVED"
            ),
        )
    )

    for check_id in policy.required_checks:
        finding = _finding(core, check_id)
        finding_outcome = None if finding is None else finding.get("outcome")
        requirements.append(
            _outcome(
                f"check.{check_id}",
                (
                    "pass"
                    if finding_outcome == "pass"
                    else "fail"
                    if finding_outcome == "fail"
                    else "unresolved"
                ),
                (
                    None
                    if finding_outcome == "pass"
                    else "POLICY_REQUIRED_CHECK_FAILED"
                    if finding_outcome == "fail"
                    else "POLICY_REQUIRED_CHECK_UNRESOLVED"
                ),
            )
        )

    for assurance in policy.required_assurance:
        requirements.append(_assurance(report, assurance))

    public_requirement = _public_evidence(report)
    if public_requirement is not None:
        requirements.append(public_requirement)

    authorized_requirement = _authorized_evidence(report)
    if authorized_requirement is not None:
        requirements.append(authorized_requirement)

    if authority == "sdk_verification" and not _has_local_support(
        report,
        policy.required_checks,
    ):
        requirements.append(
            _outcome(
                "verification.local_support",
                "unresolved",
                "POLICY_LOCAL_VERIFICATION_NOT_ESTABLISHED",
            )
        )

    if _has_failed_finding(core):
        requirements.append(
            _outcome(
                "verification.conflict",
                "fail",
                "POLICY_VERIFICATION_CONFLICT",
            )
        )

    failed = any(requirement.outcome == "fail" for requirement in requirements)
    unresolved = any(
        requirement.outcome == "unresolved" for requirement in requirements
    )
    can_allow = authority == "sdk_verification"

    decision: VerificationPolicyDecisionStatusV1
    if failed or (unresolved and policy.on_unresolved == "deny"):
        decision = "deny"
    elif unresolved or not can_allow:
        decision = "review"
    else:
        decision = "allow"

    reason_codes = {
        requirement.reason_code
        for requirement in requirements
        if requirement.reason_code is not None
    }
    if not failed and not unresolved and not can_allow:
        reason_codes.add("POLICY_REPORT_NOT_AUTHENTICATED")

    report_digest = report.get("report_sha3_512")
    if not isinstance(report_digest, str):
        raise TypeError("Invalid portable report digest")

    return VerificationPolicyDecisionV1(
        decision=decision,
        report_sha3_512=report_digest,
        authority=authority,
        requirements=tuple(requirements),
        reason_codes=tuple(sorted(reason_codes)),
    )


def assess_portable_verification_policy_v1(
    report: object,
    policy: VerificationPolicyV1,
) -> VerificationPolicyDecisionV1:
    """Assess saved claims without granting fresh verification authority."""
    return _decide(report, policy, "unauthenticated_report")


def _intent_subject(intent: object) -> Mapping[str, object] | None:
    if not isinstance(intent, Mapping):
        return None
    subject = intent.get("subject")
    if not isinstance(subject, Mapping):
        return None
    return cast(Mapping[str, object], subject)


def _checked_network_workflow_policy(
    intent: object,
    policy: VerificationPolicyV1,
    *,
    report_kind: Literal[
        "public_triangulation",
        "authorized_dataset_triangulation",
        "authorized_ingest_triangulation",
        "execution_triangulation",
    ],
    subject_kind: Literal["dataset", "ingest", "execution"],
    error_message: str,
) -> VerificationPolicyV1:
    checked = _checked_policy(policy)
    actual = _intent_subject(intent)
    expected = checked.subject

    if (
        checked.report_kind != report_kind
        or actual is None
        or actual.get("kind") != subject_kind
        or expected["kind"] != subject_kind
        or actual.get("id") != expected["id"]
        or actual.get("hedera_network") not in ("mainnet", "testnet")
        or actual.get("hedera_network") != expected.get("hedera_network")
    ):
        raise TypeError(error_message)

    return checked


async def verify_dataset_with_policy_v1(
    *,
    bundle: object,
    files: list[SourceV1File],
    intent: object,
    policy: VerificationPolicyV1,
    receipt: object = _MISSING,
    limits: SourceV1Limits | None = None,
) -> VerificationPolicyWorkflowV1:
    """Run SDK-owned Dataset verification and apply relying-party policy."""
    checked = _checked_policy(policy)

    if receipt is _MISSING:
        result = await verify_dataset_v1_with_intent(
            bundle=bundle,
            files=files,
            intent=intent,
            limits=limits,
        )
    else:
        result = await verify_dataset_v1_with_intent(
            bundle=bundle,
            files=files,
            intent=intent,
            receipt=receipt,
            limits=limits,
        )

    report = create_portable_verification_report_v1(
        PortableVerificationReportV1Input(
            kind="verification",
            result=result,
        )
    )
    return VerificationPolicyWorkflowV1(
        report=report,
        policy=_decide(report, checked, "sdk_verification"),
    )


async def verify_ingest_with_policy_v1(
    *,
    bundle: object,
    material: object,
    intent: object,
    policy: VerificationPolicyV1,
    receipt: object = _MISSING,
    limits: SourceV1Limits | None = None,
) -> VerificationPolicyWorkflowV1:
    """Run SDK-owned Ingest verification and apply relying-party policy."""
    checked = _checked_policy(policy)

    if receipt is _MISSING:
        result = await verify_ingest_v1_with_intent(
            bundle=bundle,
            material=material,
            intent=intent,
            limits=limits,
        )
    else:
        result = await verify_ingest_v1_with_intent(
            bundle=bundle,
            material=material,
            intent=intent,
            receipt=receipt,
            limits=limits,
        )

    report = create_portable_verification_report_v1(
        PortableVerificationReportV1Input(
            kind="verification",
            result=result,
        )
    )
    return VerificationPolicyWorkflowV1(
        report=report,
        policy=_decide(report, checked, "sdk_verification"),
    )


def verify_execution_with_policy_v1(
    input: ExecutionV1Input,
    policy: VerificationPolicyV1,
) -> VerificationPolicyWorkflowV1:
    """Run SDK-owned offline execution verification under exact policy intent."""
    checked = _checked_policy(policy)
    result = verify_execution_v1_with_intent(input)
    report = create_portable_verification_report_v1(
        PortableVerificationReportV1Input(
            kind="execution",
            result=result,
        )
    )
    return VerificationPolicyWorkflowV1(
        report=report,
        policy=_decide(report, checked, "sdk_verification"),
    )


async def triangulate_dataset_with_policy_v1(
    config: PublicTriangulationV1Config,
    *,
    bundle: object,
    files: list[SourceV1File],
    intent: object,
    policy: VerificationPolicyV1,
    receipt: object = _MISSING,
    limits: SourceV1Limits | None = None,
) -> VerificationPolicyWorkflowV1:
    """Run public Dataset triangulation under exact relying-party intent."""
    checked = _checked_network_workflow_policy(
        intent,
        policy,
        report_kind="public_triangulation",
        subject_kind="dataset",
        error_message=(
            "Public verification request does not match relying-party policy intent"
        ),
    )

    if receipt is _MISSING:
        result = await triangulate_dataset_v1(
            config,
            bundle=bundle,
            files=files,
            intent=intent,
            limits=limits,
        )
    else:
        result = await triangulate_dataset_v1(
            config,
            bundle=bundle,
            files=files,
            intent=intent,
            receipt=receipt,
            limits=limits,
        )

    report = create_portable_verification_report_v1(
        PortableVerificationReportV1Input(
            kind="public_triangulation",
            result=result,
        )
    )
    return VerificationPolicyWorkflowV1(
        report=report,
        policy=_decide(report, checked, "sdk_verification"),
    )


async def triangulate_ingest_with_policy_v1(
    config: PublicTriangulationV1Config,
    *,
    bundle: object,
    material: object,
    intent: object,
    anchor_request_id: str,
    policy: VerificationPolicyV1,
    receipt: object = _MISSING,
    limits: SourceV1Limits | None = None,
) -> VerificationPolicyWorkflowV1:
    """Run public Ingest triangulation under exact relying-party intent."""
    checked = _checked_network_workflow_policy(
        intent,
        policy,
        report_kind="public_triangulation",
        subject_kind="ingest",
        error_message=(
            "Public verification request does not match relying-party policy intent"
        ),
    )

    if receipt is _MISSING:
        result = await triangulate_ingest_v1(
            config,
            bundle=bundle,
            material=material,
            intent=intent,
            anchor_request_id=anchor_request_id,
            limits=limits,
        )
    else:
        result = await triangulate_ingest_v1(
            config,
            bundle=bundle,
            material=material,
            intent=intent,
            anchor_request_id=anchor_request_id,
            receipt=receipt,
            limits=limits,
        )

    report = create_portable_verification_report_v1(
        PortableVerificationReportV1Input(
            kind="public_triangulation",
            result=result,
        )
    )
    return VerificationPolicyWorkflowV1(
        report=report,
        policy=_decide(report, checked, "sdk_verification"),
    )


async def triangulate_execution_with_policy_v1(
    config: PublicExecutionTriangulationV1Config,
    input: ExecutionV1Input,
    policy: VerificationPolicyV1,
) -> VerificationPolicyWorkflowV1:
    """Run public execution acquisition, Mirror resolution, and policy evaluation."""
    checked = _checked_network_workflow_policy(
        input.get("intent"),
        policy,
        report_kind="execution_triangulation",
        subject_kind="execution",
        error_message=(
            "Public verification request does not match relying-party policy intent"
        ),
    )

    result = await triangulate_public_execution_v1(config, input)
    source_report = (
        None
        if result.plan is not None
        else verify_execution_v1_with_intent(input)
    )
    report = create_portable_verification_report_v1(
        PortableVerificationReportV1Input(
            kind="execution_triangulation",
            result=result,
            source_report=source_report,
        )
    )
    return VerificationPolicyWorkflowV1(
        report=report,
        policy=_decide(report, checked, "sdk_verification"),
    )


async def verify_execution_standards_with_policy_v1(
    config: Hcs1MirrorV1Config,
    input: ExecutionV1Input,
    decode_options: Hcs1V1ContentOptions | None,
    policy: VerificationPolicyV1,
) -> VerificationPolicyWorkflowV1:
    """Resolve pinned independent HCS standards under exact policy intent."""
    checked = _checked_policy(policy)
    actual = _intent_subject(input.get("intent"))
    expected = checked.subject

    if (
        checked.report_kind != "independent_standards"
        or actual is None
        or actual.get("kind") != "execution"
        or expected["kind"] != "execution"
        or actual.get("id") != expected["id"]
        or actual.get("hedera_network") not in ("mainnet", "testnet")
        or actual.get("hedera_network") != expected.get("hedera_network")
        or checked.execution_scope is None
        or checked.execution_scope.profile != "sage-standards-v1"
        or input.get("profile") != "sage-standards-v1"
    ):
        raise TypeError(
            "Independent standards request does not match relying-party policy intent"
        )

    result = await verify_execution_with_independent_standards_v1(
        config,
        input,
        decode_options,
    )
    report = create_portable_verification_report_v1(
        PortableVerificationReportV1Input(
            kind="independent_standards",
            result=result,
        )
    )
    return VerificationPolicyWorkflowV1(
        report=report,
        policy=_decide(report, checked, "sdk_verification"),
    )


async def triangulate_authorized_dataset_with_policy_v1(
    config: AuthorizedDatasetTriangulationV1Config,
    input: AuthorizedDatasetTriangulationV1Input,
    policy: VerificationPolicyV1,
) -> VerificationPolicyWorkflowV1:
    """Run authenticated Dataset verification under exact policy intent."""
    checked = _checked_network_workflow_policy(
        input["intent"],
        policy,
        report_kind="authorized_dataset_triangulation",
        subject_kind="dataset",
        error_message=(
            "Authorized Dataset verification request does not match "
            "relying-party policy intent"
        ),
    )

    result = await triangulate_authorized_dataset_v1(config, input)
    report = create_portable_verification_report_v1(
        PortableVerificationReportV1Input(
            kind="authorized_dataset_triangulation",
            result=result,
        )
    )
    return VerificationPolicyWorkflowV1(
        report=report,
        policy=_decide(report, checked, "sdk_verification"),
    )


async def triangulate_authorized_ingest_with_policy_v1(
    config: AuthorizedIngestTriangulationV1Config,
    input: AuthorizedIngestTriangulationV1Input,
    policy: VerificationPolicyV1,
) -> VerificationPolicyWorkflowV1:
    """Run authenticated Ingest verification under exact policy intent."""
    checked = _checked_network_workflow_policy(
        input["intent"],
        policy,
        report_kind="authorized_ingest_triangulation",
        subject_kind="ingest",
        error_message=(
            "Authorized Ingest verification request does not match "
            "relying-party policy intent"
        ),
    )

    result = await triangulate_authorized_ingest_v1(config, input)
    report = create_portable_verification_report_v1(
        PortableVerificationReportV1Input(
            kind="authorized_ingest_triangulation",
            result=result,
        )
    )
    return VerificationPolicyWorkflowV1(
        report=report,
        policy=_decide(report, checked, "sdk_verification"),
    )


__all__ = [
    "assess_portable_verification_policy_v1",
    "triangulate_authorized_dataset_with_policy_v1",
    "triangulate_authorized_ingest_with_policy_v1",
    "triangulate_dataset_with_policy_v1",
    "triangulate_execution_with_policy_v1",
    "triangulate_ingest_with_policy_v1",
    "verify_dataset_with_policy_v1",
    "verify_execution_standards_with_policy_v1",
    "verify_execution_with_policy_v1",
    "verify_ingest_with_policy_v1",
]