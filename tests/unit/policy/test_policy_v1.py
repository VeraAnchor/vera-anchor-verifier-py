import asyncio
from dataclasses import replace
from types import SimpleNamespace
from typing import Literal, cast

import pytest

import vera_anchor_verifier.policy.evaluate_v1 as module
from vera_anchor_verifier.contracts import (
    VerificationFinding,
    VerificationIntent,
    VerificationObservation,
    VerificationReport,
    VerificationSubject,
)
from vera_anchor_verifier.policy.contract_v1 import (
    VERIFICATION_POLICY_SCHEMA_VERSION,
    VerificationPolicyExecutionScopeV1,
    VerificationPolicyV1,
)
from vera_anchor_verifier.policy.evaluate_v1 import (
    assess_portable_verification_policy_v1,
    triangulate_authorized_ingest_with_policy_v1,
    triangulate_execution_with_policy_v1,
    verify_dataset_with_policy_v1,
    verify_execution_standards_with_policy_v1,
    verify_execution_with_policy_v1,
)
from vera_anchor_verifier.profiles.execution.independent_standards_v1 import (
    IndependentStandardsV1Item,
    IndependentStandardsV1Report,
    IndependentStandardsV1Summary,
)
from vera_anchor_verifier.profiles.execution.verification_v1 import (
    ExecutionV1Input,
    ExecutionV1Report,
    ExecutionV1VerificationScope,
)
from vera_anchor_verifier.reports.portable_v1 import (
    PortableVerificationReportV1Input,
    create_portable_verification_report_v1,
)
from vera_anchor_verifier.resolvers.hcs1_mirror_v1 import Hcs1MirrorV1Config
from vera_anchor_verifier.triangulation.authorized_ingest_v1 import (
    AuthorizedIngestTriangulationResolutionV1,
    AuthorizedIngestTriangulationV1Config,
    AuthorizedIngestTriangulationV1Input,
    AuthorizedIngestTriangulationV1Result,
)
from vera_anchor_verifier.triangulation.compare_v1 import (
    TriangulationFactResultV1,
    TriangulationRelationshipResultV1,
)
from vera_anchor_verifier.triangulation.execution_plan_v1 import ExecutionHederaTargetV1
from vera_anchor_verifier.triangulation.execution_public_v1 import (
    PublicExecutionTriangulationV1Config,
    PublicExecutionTriangulationV1Result,
)

JOB = "11111111-1111-4111-8111-111111111111"

DATASET = cast(
    VerificationSubject,
    {"kind": "dataset", "id": "dataset-1", "hedera_network": "testnet"},
)
INGEST = cast(
    VerificationSubject,
    {"kind": "ingest", "id": "research.ingest", "hedera_network": "testnet"},
)
EXECUTION = cast(
    VerificationSubject,
    {"kind": "execution", "id": JOB, "hedera_network": "testnet"},
)


def run[T](coro) -> T:
    return asyncio.run(coro)


def dataset_report() -> VerificationReport:
    observation = VerificationObservation(
        id="dataset.source",
        subject=DATASET,
        source="local_computation",
        facts=(),
    )
    return VerificationReport(
        intent=cast(VerificationIntent, {"subject": DATASET, "expected": []}),
        observations=(observation,),
        findings=(
            VerificationFinding(
                check_id="intent.subject",
                outcome="pass",
                reason_code=None,
                observation_ids=("dataset.source",),
            ),
            VerificationFinding(
                check_id="dataset.source_binding",
                outcome="pass",
                reason_code=None,
                observation_ids=("dataset.source",),
            ),
            VerificationFinding(
                check_id="dataset.bundle_consistency",
                outcome="pass",
                reason_code=None,
                observation_ids=("dataset.source",),
            ),
        ),
    )


def execution_report() -> ExecutionV1Report:
    observation = VerificationObservation(
        id="execution.recomputed",
        subject=EXECUTION,
        source="local_computation",
        facts=(),
    )
    return ExecutionV1Report(
        intent=cast(VerificationIntent, {"subject": EXECUTION, "expected": []}),
        findings=(
            VerificationFinding(
                check_id="intent.subject",
                outcome="pass",
                reason_code=None,
                observation_ids=("execution.recomputed",),
            ),
            VerificationFinding(
                check_id="acceptance.digest_recomputed",
                outcome="pass",
                reason_code=None,
                observation_ids=("execution.recomputed",),
            ),
            VerificationFinding(
                check_id="profile.program_scope",
                outcome="pass",
                reason_code=None,
                observation_ids=("execution.recomputed",),
            ),
        ),
        observations=(observation,),
        verification_scope=ExecutionV1VerificationScope(
            profile="sage-standards-v1",
            expected_program="sage",
            requested_result_id=None,
        ),
    )


def independent_standards_report() -> IndependentStandardsV1Report:
    base = execution_report()
    mirror = VerificationObservation(
        id="standards.mirror.0",
        subject=EXECUTION,
        source="hedera_mirror",
        facts=(),
    )
    item = IndependentStandardsV1Item(
        key="agent:requester",
        standard="HCS-11",
        reference="hcs://1/0.0.100",
        status="resolved",
        reason_code=None,
        resolver_id="hedera.mirror-rest.hcs11.v1",
        historical_consensus_timestamps_exact=("1792000000.000000001",),
        current_topic_or_account_memo_observed=True,
        content_sha256="a" * 64,
        assurance="mirror_corroborated",
    )
    return IndependentStandardsV1Report(
        intent=base.intent,
        findings=(
            *base.findings,
            VerificationFinding(
                check_id="standards.reference.0",
                outcome="pass",
                reason_code=None,
                observation_ids=("standards.mirror.0",),
            ),
            VerificationFinding(
                check_id="standards.references_resolved",
                outcome="pass",
                reason_code=None,
                observation_ids=("standards.mirror.0",),
            ),
        ),
        observations=(*base.observations, mirror),
        verification_scope=base.verification_scope,
        independent_standards=IndependentStandardsV1Summary(
            network="testnet",
            status="verified",
            assurance="mirror_corroborated",
            items=(item,),
        ),
    )


def dataset_policy(
    *, on_unresolved: Literal["review", "deny"] = "review"
) -> VerificationPolicyV1:
    return VerificationPolicyV1(
        schema_version=VERIFICATION_POLICY_SCHEMA_VERSION,
        subject=DATASET,
        report_kind="verification",
        required_checks=("dataset.source_binding", "dataset.bundle_consistency"),
        on_unresolved=on_unresolved,
    )


def execution_policy(
    report_kind: Literal[
        "execution", "independent_standards", "execution_triangulation"
    ],
    *,
    required_checks: tuple[str, ...] = ("acceptance.digest_recomputed",),
    required_assurance: tuple[Literal["mirror_corroboration"], ...] = (),
    expected_program: str | None = "sage",
) -> VerificationPolicyV1:
    return VerificationPolicyV1(
        schema_version=VERIFICATION_POLICY_SCHEMA_VERSION,
        subject=EXECUTION,
        report_kind=report_kind,
        required_checks=required_checks,
        required_assurance=required_assurance,
        execution_scope=VerificationPolicyExecutionScopeV1(
            profile="sage-standards-v1",
            expected_program=expected_program,
            requested_result_id=None,
        ),
    )


def execution_input() -> ExecutionV1Input:
    return cast(
        ExecutionV1Input,
        {
            "profile": "sage-standards-v1",
            "intent": {"subject": EXECUTION, "expected": []},
            "evidence": {},
        },
    )


def authorized_relationship(
    relationship_id: Literal["authorized_hedera", "provided_authorized"],
    *,
    status: Literal["consistent", "conflict", "incomplete"] = "consistent",
    outcome: Literal["pass", "fail", "indeterminate"] = "pass",
) -> TriangulationRelationshipResultV1:
    key = (
        "message_sha3_512"
        if relationship_id == "authorized_hedera"
        else "merkle_root"
    )
    return TriangulationRelationshipResultV1(
        id=relationship_id,
        status=status,
        fact_comparisons=(
            TriangulationFactResultV1(
                key=key,
                outcome=outcome,
                reason_code=None if outcome == "pass" else "FACT_UNAVAILABLE",
            ),
        ),
    )


def authorized_ingest_result(
    *,
    mirror: Literal["resolved", "unavailable"] = "resolved",
    receipt: Literal["resolved", "conflict"] = "resolved",
) -> AuthorizedIngestTriangulationV1Result:
    mirror_outcome = "pass" if mirror == "resolved" else "indeterminate"
    mirror_relationship = "consistent" if mirror == "resolved" else "incomplete"
    receipt_outcome = "pass" if receipt == "resolved" else "indeterminate"
    receipt_relationship = "consistent" if receipt == "resolved" else "incomplete"
    consistency = (
        "conflict"
        if receipt == "conflict"
        else "consistent"
        if mirror == "resolved"
        else "incomplete"
    )

    observations = (
        VerificationObservation(
            id="ingest.source",
            subject=INGEST,
            source="local_computation",
            facts=(),
        ),
        VerificationObservation(
            id="ingest.authorized_core",
            subject=INGEST,
            source="authorized_service",
            facts=(),
        ),
        VerificationObservation(
            id="ingest.receipt",
            subject=INGEST,
            source="authorized_service",
            facts=(),
        ),
        *(
            (
                VerificationObservation(
                    id="ingest.hedera_mirror",
                    subject=INGEST,
                    source="hedera_mirror",
                    facts=(),
                ),
            )
            if mirror == "resolved"
            else ()
        ),
    )

    findings = (
        VerificationFinding(
            check_id="intent.subject",
            outcome="pass",
            reason_code=None,
            observation_ids=("ingest.source",),
        ),
        VerificationFinding(
            check_id="ingest.source_binding",
            outcome="pass",
            reason_code=None,
            observation_ids=("ingest.source",),
        ),
        VerificationFinding(
            check_id="triangulation.authorized_hedera.message_sha3_512",
            outcome=mirror_outcome,
            reason_code=None if mirror_outcome == "pass" else "FACT_UNAVAILABLE",
            observation_ids=(
                ("ingest.authorized_core", "ingest.hedera_mirror")
                if mirror == "resolved"
                else ("ingest.authorized_core",)
            ),
        ),
        VerificationFinding(
            check_id="triangulation.provided_authorized.merkle_root",
            outcome=receipt_outcome,
            reason_code=None if receipt_outcome == "pass" else "FACT_UNAVAILABLE",
            observation_ids=("ingest.source", "ingest.receipt"),
        ),
        VerificationFinding(
            check_id="triangulation.authorized_ingest.receipt_profile",
            outcome="pass" if receipt == "resolved" else "fail",
            reason_code=(
                None
                if receipt == "resolved"
                else "AUTHORIZED_INGEST_RECEIPT_CONFLICT"
            ),
            observation_ids=("ingest.receipt",) if receipt == "resolved" else (),
        ),
    )

    report = VerificationReport(
        intent=cast(VerificationIntent, {"subject": INGEST, "expected": []}),
        observations=observations,
        findings=findings,
    )
    return AuthorizedIngestTriangulationV1Result(
        consistency=consistency,
        relationships=(
            authorized_relationship(
                "authorized_hedera",
                status=mirror_relationship,
                outcome=mirror_outcome,
            ),
            authorized_relationship(
                "provided_authorized",
                status=receipt_relationship,
                outcome=receipt_outcome,
            ),
        ),
        report=report,
        resolution=AuthorizedIngestTriangulationResolutionV1(
            authorized_core="resolved",
            hedera_mirror=mirror,
            ingest_receipt=receipt,
        ),
    )


def authorized_ingest_policy() -> VerificationPolicyV1:
    return VerificationPolicyV1(
        schema_version=VERIFICATION_POLICY_SCHEMA_VERSION,
        subject=INGEST,
        report_kind="authorized_ingest_triangulation",
        required_checks=(
            "ingest.source_binding",
            "triangulation.provided_authorized.merkle_root",
        ),
        required_assurance=("mirror_corroboration",),
    )


def authorized_ingest_input() -> AuthorizedIngestTriangulationV1Input:
    return {
        "bundle": {},
        "material": {"kind": "json", "value": {}},
        "intent": {"subject": INGEST, "expected": []},
        "hcs_reference": {"message_id": "7@0.0.12345"},
    }


def resolved_execution() -> PublicExecutionTriangulationV1Result:
    source = execution_report()
    relation = TriangulationRelationshipResultV1(
        id="provided_hedera",
        status="consistent",
        fact_comparisons=(
            TriangulationFactResultV1(
                key="transaction_id",
                outcome="pass",
                reason_code=None,
            ),
        ),
    )
    compared = replace(
        source,
        findings=(
            *source.findings,
            VerificationFinding(
                check_id="triangulation.provided_hedera.transaction_id",
                outcome="pass",
                reason_code=None,
                observation_ids=("execution.recomputed",),
            ),
        ),
    )
    target = ExecutionHederaTargetV1(
        source="provided_evidence",
        role="acceptance_anchor",
        network="testnet",
        transaction_id="0.0.123@1792000000.000000001",
        topic_id=None,
        sequence_number=None,
        observation_fact_prefix="ledger.provided_evidence.acceptance_anchor",
    )
    plan = SimpleNamespace(
        stage="unresolved_authority_plan",
        public_record_acquisition="not_checked",
        hedera_resolution="not_checked",
        source_report=source,
        hedera_targets=(target,),
        triangulation=SimpleNamespace(
            source_report=source,
            observations=(),
            relationships=(),
        ),
    )
    return PublicExecutionTriangulationV1Result(
        status="resolved",
        reason_code=None,
        public_record_acquisition="resolved",
        hedera_resolution="resolved",
        plan=plan,
        mirror=SimpleNamespace(
            status="resolved",
            reason_code=None,
        ),
        comparison=SimpleNamespace(
            consistency="consistent",
            relationships=(relation,),
            report=compared,
        ),
    )


def test_saved_report_cannot_grant_allow() -> None:
    portable = create_portable_verification_report_v1(
        PortableVerificationReportV1Input(
            kind="verification",
            result=dataset_report(),
        )
    )
    decision = assess_portable_verification_policy_v1(
        portable,
        dataset_policy(),
    )

    assert decision.decision == "review"
    assert decision.authority == "unauthenticated_report"
    assert decision.reason_codes == ("POLICY_REPORT_NOT_AUTHENTICATED",)


def test_unrequired_verifier_conflict_denies() -> None:
    source = dataset_report()
    conflicted = replace(
        source,
        findings=(
            *source.findings,
            VerificationFinding(
                check_id="dataset.receipt_binding",
                outcome="fail",
                reason_code="MISMATCH",
                observation_ids=("dataset.source",),
            ),
        ),
    )
    portable = create_portable_verification_report_v1(
        PortableVerificationReportV1Input(
            kind="verification",
            result=conflicted,
        )
    )
    decision = assess_portable_verification_policy_v1(
        portable,
        dataset_policy(),
    )

    assert decision.decision == "deny"
    assert "POLICY_VERIFICATION_CONFLICT" in decision.reason_codes


def test_subject_and_report_kind_substitution_fail_closed() -> None:
    portable = create_portable_verification_report_v1(
        PortableVerificationReportV1Input(
            kind="verification",
            result=dataset_report(),
        )
    )
    wrong_subject = replace(
        dataset_policy(),
        subject=cast(
            VerificationSubject,
            {**DATASET, "id": "other"},
        ),
    )
    wrong_kind = replace(
        dataset_policy(),
        report_kind="public_triangulation",
    )

    assert (
        assess_portable_verification_policy_v1(
            portable,
            wrong_subject,
        ).decision
        == "deny"
    )
    assert (
        assess_portable_verification_policy_v1(
            portable,
            wrong_kind,
        ).decision
        == "deny"
    )


def test_unresolved_required_check_respects_policy() -> None:
    source = dataset_report()
    unresolved = replace(
        source,
        findings=tuple(
            replace(
                finding,
                outcome="indeterminate",
                reason_code="NOT_VERIFIED",
            )
            if finding.check_id == "dataset.source_binding"
            else finding
            for finding in source.findings
        ),
    )
    portable = create_portable_verification_report_v1(
        PortableVerificationReportV1Input(
            kind="verification",
            result=unresolved,
        )
    )

    assert (
        assess_portable_verification_policy_v1(
            portable,
            dataset_policy(),
        ).decision
        == "review"
    )
    assert (
        assess_portable_verification_policy_v1(
            portable,
            dataset_policy(on_unresolved="deny"),
        ).decision
        == "deny"
    )


def test_fresh_sdk_verification_can_allow(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fake_verify(**kwargs):
        del kwargs
        return dataset_report()

    monkeypatch.setattr(
        module,
        "verify_dataset_v1_with_intent",
        fake_verify,
    )
    workflow = run(
        verify_dataset_with_policy_v1(
            bundle={},
            files=[],
            intent={"subject": DATASET, "expected": []},
            policy=dataset_policy(),
        )
    )

    assert workflow.policy.decision == "allow"
    assert workflow.policy.authority == "sdk_verification"


def test_execution_scope_is_required_and_exact() -> None:
    portable = create_portable_verification_report_v1(
        PortableVerificationReportV1Input(
            kind="execution",
            result=execution_report(),
        )
    )
    matched = assess_portable_verification_policy_v1(
        portable,
        execution_policy("execution"),
    )
    mismatched = assess_portable_verification_policy_v1(
        portable,
        execution_policy(
            "execution",
            expected_program="other",
        ),
    )

    assert matched.decision == "review"
    assert mismatched.decision == "deny"
    assert "POLICY_EXECUTION_SCOPE_MISMATCH" in mismatched.reason_codes

    with pytest.raises(
        TypeError,
        match="exact execution scope",
    ):
        assess_portable_verification_policy_v1(
            portable,
            replace(
                execution_policy("execution"),
                execution_scope=None,
            ),
        )


def test_fresh_execution_verification_can_allow(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        module,
        "verify_execution_v1_with_intent",
        lambda input: execution_report(),
    )
    workflow = verify_execution_with_policy_v1(
        execution_input(),
        execution_policy("execution"),
    )

    assert workflow.policy.decision == "allow"
    assert workflow.policy.authority == "sdk_verification"
    assert (
        assess_portable_verification_policy_v1(
            workflow.report,
            execution_policy("execution"),
        ).decision
        == "review"
    )


def test_public_execution_resolved_mirror_can_allow(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fake_triangulate(config, input):
        del config, input
        return resolved_execution()

    monkeypatch.setattr(
        module,
        "triangulate_public_execution_v1",
        fake_triangulate,
    )
    workflow = run(
        triangulate_execution_with_policy_v1(
            cast(PublicExecutionTriangulationV1Config, object()),
            execution_input(),
            execution_policy(
                "execution_triangulation",
                required_assurance=("mirror_corroboration",),
            ),
        )
    )

    assert workflow.policy.decision == "allow"
    assert any(
        requirement.key == "assurance.mirror_corroboration"
        and requirement.outcome == "pass"
        for requirement in workflow.policy.requirements
    )
    assert any(
        requirement.key == "verification.public_evidence"
        and requirement.outcome == "pass"
        for requirement in workflow.policy.requirements
    )


def test_public_execution_unresolved_stays_non_authorizing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fake_triangulate(config, input):
        del config, input
        return PublicExecutionTriangulationV1Result(
            status="not_found",
            reason_code="EXECUTION_NOT_FOUND",
            public_record_acquisition="not_found",
            hedera_resolution="not_checked",
            plan=None,
            mirror=None,
            comparison=None,
        )

    monkeypatch.setattr(
        module,
        "triangulate_public_execution_v1",
        fake_triangulate,
    )
    monkeypatch.setattr(
        module,
        "verify_execution_v1_with_intent",
        lambda input: execution_report(),
    )
    workflow = run(
        triangulate_execution_with_policy_v1(
            cast(PublicExecutionTriangulationV1Config, object()),
            execution_input(),
            execution_policy("execution_triangulation"),
        )
    )

    assert workflow.policy.decision == "review"
    assert "POLICY_PUBLIC_EVIDENCE_INCOMPLETE" in workflow.policy.reason_codes


def test_execution_policy_rejects_removed_assurance_before_io(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    called = False

    async def fake_triangulate(config, input):
        nonlocal called
        called = True
        del config, input
        return resolved_execution()

    monkeypatch.setattr(
        module,
        "triangulate_public_execution_v1",
        fake_triangulate,
    )
    policy = replace(
        execution_policy("execution_triangulation"),
        required_assurance=cast(
            tuple[Literal["mirror_corroboration"], ...],
            ("publication_payload_binding",),
        ),
    )

    with pytest.raises(
        TypeError,
        match="Unsupported assurance dimension",
    ):
        run(
            triangulate_execution_with_policy_v1(
                cast(PublicExecutionTriangulationV1Config, object()),
                execution_input(),
                policy,
            )
        )

    assert not called


def test_independent_standards_policy_boundary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0

    async def fake_standards(config, input, decode_options=None):
        nonlocal calls
        calls += 1
        del config, input, decode_options
        return independent_standards_report()

    monkeypatch.setattr(
        module,
        "verify_execution_with_independent_standards_v1",
        fake_standards,
    )
    config = Hcs1MirrorV1Config()
    policy = execution_policy(
        "independent_standards",
        required_assurance=("mirror_corroboration",),
    )
    wrong = replace(
        policy,
        subject=cast(
            VerificationSubject,
            {**EXECUTION, "hedera_network": "mainnet"},
        ),
    )

    with pytest.raises(
        TypeError,
        match="policy intent",
    ):
        run(
            verify_execution_standards_with_policy_v1(
                config,
                execution_input(),
                None,
                wrong,
            )
        )

    assert calls == 0

    workflow = run(
        verify_execution_standards_with_policy_v1(
            config,
            execution_input(),
            None,
            policy,
        )
    )

    assert calls == 1
    assert workflow.policy.decision == "allow"
    assert any(
        requirement.key == "assurance.mirror_corroboration"
        and requirement.outcome == "pass"
        for requirement in workflow.policy.requirements
    )
    assert (
        assess_portable_verification_policy_v1(
            workflow.report,
            policy,
        ).decision
        == "review"
    )


def test_authorized_ingest_requires_private_and_mirror_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    current = authorized_ingest_result()

    async def fake_triangulate(config, input):
        del config, input
        return current

    monkeypatch.setattr(
        module,
        "triangulate_authorized_ingest_v1",
        fake_triangulate,
    )
    workflow = run(
        triangulate_authorized_ingest_with_policy_v1(
            cast(AuthorizedIngestTriangulationV1Config, object()),
            authorized_ingest_input(),
            authorized_ingest_policy(),
        )
    )

    assert workflow.policy.decision == "allow"
    assert any(
        requirement.key == "verification.authorized_evidence"
        and requirement.outcome == "pass"
        for requirement in workflow.policy.requirements
    )
    assert any(
        requirement.key == "assurance.mirror_corroboration"
        and requirement.outcome == "pass"
        for requirement in workflow.policy.requirements
    )

    saved = assess_portable_verification_policy_v1(
        workflow.report,
        authorized_ingest_policy(),
    )
    assert saved.decision == "review"
    assert saved.authority == "unauthenticated_report"


def test_authorized_ingest_unavailable_and_conflicting_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    current = authorized_ingest_result(
        mirror="unavailable",
    )

    async def fake_triangulate(config, input):
        del config, input
        return current

    monkeypatch.setattr(
        module,
        "triangulate_authorized_ingest_v1",
        fake_triangulate,
    )
    incomplete = run(
        triangulate_authorized_ingest_with_policy_v1(
            cast(AuthorizedIngestTriangulationV1Config, object()),
            authorized_ingest_input(),
            authorized_ingest_policy(),
        )
    )

    assert incomplete.policy.decision == "review"
    assert "POLICY_AUTHORIZED_EVIDENCE_INCOMPLETE" in incomplete.policy.reason_codes

    current = authorized_ingest_result(
        receipt="conflict",
    )
    denied = run(
        triangulate_authorized_ingest_with_policy_v1(
            cast(AuthorizedIngestTriangulationV1Config, object()),
            authorized_ingest_input(),
            authorized_ingest_policy(),
        )
    )

    assert denied.policy.decision == "deny"
    assert "POLICY_AUTHORIZED_EVIDENCE_CONFLICT" in denied.policy.reason_codes


def test_rejects_invalid_policy_contracts() -> None:
    portable = create_portable_verification_report_v1(
        PortableVerificationReportV1Input(
            kind="verification",
            result=dataset_report(),
        )
    )

    with pytest.raises(
        TypeError,
        match="Duplicate required check",
    ):
        assess_portable_verification_policy_v1(
            portable,
            replace(
                dataset_policy(),
                required_checks=(
                    "dataset.source_binding",
                    "dataset.source_binding",
                ),
            ),
        )

    with pytest.raises(
        TypeError,
        match="explicit Hedera network",
    ):
        assess_portable_verification_policy_v1(
            portable,
            VerificationPolicyV1(
                schema_version=VERIFICATION_POLICY_SCHEMA_VERSION,
                subject=cast(
                    VerificationSubject,
                    {
                        "kind": "dataset",
                        "id": "dataset-1",
                    },
                ),
                report_kind="public_triangulation",
                required_checks=("dataset.source_binding",),
            ),
        )