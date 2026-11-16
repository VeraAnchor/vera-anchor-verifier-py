import json
from dataclasses import replace
from types import SimpleNamespace
from typing import Literal, cast

import pytest

from vera_anchor_verifier.contracts import (
    VerificationFinding,
    VerificationIntent,
    VerificationReport,
    VerificationSubject,
)
from vera_anchor_verifier.profiles.execution.independent_standards_v1 import (
    IndependentStandardsV1Item,
    IndependentStandardsV1Report,
    IndependentStandardsV1Summary,
)
from vera_anchor_verifier.profiles.execution.verification_v1 import (
    ExecutionV1Report,
    ExecutionV1VerificationScope,
)
from vera_anchor_verifier.reports.portable_v1 import (
    PortableVerificationReportV1Input,
    canonicalize_portable_verification_report_v1,
    create_portable_verification_report_v1,
)
from vera_anchor_verifier.reports.validation_v1 import (
    compare_portable_verification_reports_v1,
    validate_portable_verification_report_v1,
)
from vera_anchor_verifier.triangulation.authorized_ingest_v1 import (
    AuthorizedIngestTriangulationResolutionV1,
    AuthorizedIngestTriangulationV1Result,
)
from vera_anchor_verifier.triangulation.compare_v1 import (
    TriangulationFactResultV1,
    TriangulationRelationshipResultV1,
)
from vera_anchor_verifier.triangulation.execution_plan_v1 import (
    ExecutionHederaTargetV1,
)
from vera_anchor_verifier.triangulation.execution_public_v1 import (
    PublicExecutionTriangulationV1Result,
)

JOB = "11111111-1111-4111-8111-111111111111"
RESULT = "22222222-2222-4222-8222-222222222222"


def report(
    kind: Literal["dataset", "ingest"] = "dataset",
) -> VerificationReport:
    subject = cast(
        VerificationSubject,
        {
            "kind": kind,
            "id": (
                "research.dataset"
                if kind == "dataset"
                else "research.ingest"
            ),
            "hedera_network": "testnet",
        },
    )
    return VerificationReport(
        intent=cast(
            VerificationIntent,
            {
                "subject": subject,
                "expected": [],
            },
        ),
        findings=(),
        observations=(),
    )


def execution_report() -> ExecutionV1Report:
    subject = cast(
        VerificationSubject,
        {
            "kind": "execution",
            "id": JOB,
            "hedera_network": "testnet",
        },
    )
    return ExecutionV1Report(
        intent=cast(
            VerificationIntent,
            {
                "subject": subject,
                "expected": [],
            },
        ),
        findings=(
            VerificationFinding(
                check_id="intent.result",
                outcome="pass",
                reason_code=None,
                observation_ids=(),
            ),
        ),
        observations=(),
        verification_scope=ExecutionV1VerificationScope(
            profile="sage-standards-v1",
            expected_program="sage",
            requested_result_id=RESULT,
        ),
    )


def independent_standards_report() -> IndependentStandardsV1Report:
    source = execution_report()
    item = IndependentStandardsV1Item(
        key="agent:requester",
        standard="HCS-11",
        reference="hcs://1/0.0.100",
        status="resolved",
        reason_code=None,
        resolver_id="hedera.mirror-rest.hcs11.v1",
        historical_consensus_timestamps_exact=(
            "1792000000.000000001",
        ),
        current_topic_or_account_memo_observed=True,
        content_sha256="a" * 64,
        assurance="mirror_corroborated",
    )
    return IndependentStandardsV1Report(
        intent=source.intent,
        findings=(
            *source.findings,
            VerificationFinding(
                check_id="standards.reference.0",
                outcome="pass",
                reason_code=None,
                observation_ids=(),
            ),
            VerificationFinding(
                check_id="standards.references_resolved",
                outcome="pass",
                reason_code=None,
                observation_ids=(),
            ),
        ),
        observations=source.observations,
        verification_scope=source.verification_scope,
        independent_standards=IndependentStandardsV1Summary(
            network="testnet",
            status="verified",
            assurance="mirror_corroborated",
            items=(item,),
        ),
    )


def relationship(
    relationship_id: Literal[
        "provided_authorized",
        "authorized_hedera",
    ],
    key: str,
) -> TriangulationRelationshipResultV1:
    return TriangulationRelationshipResultV1(
        id=relationship_id,
        status="consistent",
        fact_comparisons=(
            TriangulationFactResultV1(
                key=key,
                outcome="pass",
                reason_code=None,
            ),
        ),
    )


def authorized_ingest() -> AuthorizedIngestTriangulationV1Result:
    relationships = (
        relationship(
            "authorized_hedera",
            "message_sha3_512",
        ),
        relationship(
            "provided_authorized",
            "merkle_root",
        ),
    )
    source = replace(
        report("ingest"),
        findings=(
            VerificationFinding(
                check_id=(
                    "triangulation.authorized_hedera."
                    "message_sha3_512"
                ),
                outcome="pass",
                reason_code=None,
                observation_ids=(),
            ),
            VerificationFinding(
                check_id=(
                    "triangulation.provided_authorized."
                    "merkle_root"
                ),
                outcome="pass",
                reason_code=None,
                observation_ids=(),
            ),
            VerificationFinding(
                check_id=(
                    "triangulation.authorized_ingest."
                    "receipt_profile"
                ),
                outcome="pass",
                reason_code=None,
                observation_ids=(),
            ),
        ),
    )
    return AuthorizedIngestTriangulationV1Result(
        consistency="consistent",
        relationships=relationships,
        report=source,
        resolution=(
            AuthorizedIngestTriangulationResolutionV1(
                authorized_core="resolved",
                hedera_mirror="resolved",
                ingest_receipt="resolved",
            )
        ),
    )


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
                check_id=(
                    "triangulation.provided_hedera."
                    "transaction_id"
                ),
                outcome="pass",
                reason_code=None,
                observation_ids=(),
            ),
        ),
    )
    target = ExecutionHederaTargetV1(
        source="provided_evidence",
        role="acceptance_anchor",
        network="testnet",
        transaction_id=(
            "0.0.123@1792000000.000000001"
        ),
        topic_id=None,
        sequence_number=None,
        observation_fact_prefix=(
            "ledger.provided_evidence."
            "acceptance_anchor"
        ),
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


def serialized(
    input: PortableVerificationReportV1Input,
) -> dict[str, object]:
    return cast(
        dict[str, object],
        json.loads(
            canonicalize_portable_verification_report_v1(
                input
            )
        ),
    )


def test_validates_sdk_object_and_serialized_mapping() -> None:
    input = PortableVerificationReportV1Input(
        kind="verification",
        result=report(),
    )
    portable = create_portable_verification_report_v1(
        input
    )
    direct = validate_portable_verification_report_v1(
        portable
    )
    saved = validate_portable_verification_report_v1(
        serialized(input)
    )

    assert direct.status == "valid"
    assert direct.reason_code is None
    assert direct.authenticity == "not_checked"
    assert (
        direct.evidence_recomputation
        == "not_performed"
    )
    assert saved == direct


def test_validates_execution_and_independent_standards_contexts() -> None:
    for input in (
        PortableVerificationReportV1Input(
            kind="execution",
            result=execution_report(),
        ),
        PortableVerificationReportV1Input(
            kind="independent_standards",
            result=independent_standards_report(),
        ),
    ):
        result = validate_portable_verification_report_v1(
            create_portable_verification_report_v1(
                input
            )
        )
        assert result.status == "valid"


def test_validates_resolved_and_unresolved_execution_triangulation() -> None:
    resolved = PortableVerificationReportV1Input(
        kind="execution_triangulation",
        result=resolved_execution(),
    )
    unresolved = PortableVerificationReportV1Input(
        kind="execution_triangulation",
        result=PublicExecutionTriangulationV1Result(
            status="not_found",
            reason_code="EXECUTION_NOT_FOUND",
            public_record_acquisition="not_found",
            hedera_resolution="not_checked",
            plan=None,
            mirror=None,
            comparison=None,
        ),
        source_report=execution_report(),
    )

    for input in (resolved, unresolved):
        result = validate_portable_verification_report_v1(
            create_portable_verification_report_v1(
                input
            )
        )
        assert result.status == "valid"


def test_rejects_semantically_invalid_execution_context() -> None:
    value = serialized(
        PortableVerificationReportV1Input(
            kind="execution_triangulation",
            result=resolved_execution(),
        )
    )
    context = cast(
        dict[str, object],
        value["context"],
    )
    triangulation = cast(
        dict[str, object],
        context["triangulation"],
    )
    targets = cast(
        list[dict[str, object]],
        triangulation["targets"],
    )
    targets[0]["network"] = "mainnet"

    result = validate_portable_verification_report_v1(
        value
    )
    assert result.status == "invalid"
    assert (
        result.reason_code
        == "PORTABLE_REPORT_INVALID"
    )


def test_distinguishes_core_and_envelope_digest_tampering() -> None:
    input = PortableVerificationReportV1Input(
        kind="verification",
        result=report(),
    )

    core_tampered = serialized(input)
    core_tampered["core_sha3_512"] = "f" * 128
    core_result = validate_portable_verification_report_v1(
        core_tampered
    )
    assert core_result.status == "invalid"
    assert (
        core_result.reason_code
        == "PORTABLE_CORE_DIGEST_MISMATCH"
    )

    envelope_tampered = serialized(input)
    envelope_tampered["report_sha3_512"] = "f" * 128
    envelope_result = (
        validate_portable_verification_report_v1(
            envelope_tampered
        )
    )
    assert envelope_result.status == "invalid"
    assert (
        envelope_result.reason_code
        == "PORTABLE_REPORT_DIGEST_MISMATCH"
    )


def test_rejects_noncanonical_or_malformed_saved_report() -> None:
    input = PortableVerificationReportV1Input(
        kind="verification",
        result=report(),
    )
    malformed = serialized(input)
    malformed["unexpected"] = True

    result = validate_portable_verification_report_v1(
        malformed
    )
    assert result.status == "invalid"
    assert (
        result.reason_code
        == "PORTABLE_REPORT_INVALID"
    )


def test_validates_authorized_ingest_context() -> None:
    input = PortableVerificationReportV1Input(
        kind="authorized_ingest_triangulation",
        result=authorized_ingest(),
    )
    result = validate_portable_verification_report_v1(
        create_portable_verification_report_v1(
            input
        )
    )

    assert result.status == "valid"
    assert result.reason_code is None


def test_rejects_semantically_invalid_authorized_context() -> None:
    input = PortableVerificationReportV1Input(
        kind="authorized_ingest_triangulation",
        result=authorized_ingest(),
    )
    value = serialized(input)
    context = cast(
        dict[str, object],
        value["context"],
    )
    relationships = cast(
        list[object],
        context["relationships"],
    )
    context["relationships"] = [
        entry
        for entry in relationships
        if (
            isinstance(entry, dict)
            and entry.get("id")
            != "authorized_hedera"
        )
    ]

    result = validate_portable_verification_report_v1(
        value
    )
    assert result.status == "invalid"
    assert (
        result.reason_code
        == "PORTABLE_REPORT_INVALID"
    )


def test_compares_equivalent_saved_forms() -> None:
    input = PortableVerificationReportV1Input(
        kind="verification",
        result=report(),
    )
    portable = create_portable_verification_report_v1(
        input
    )
    result = compare_portable_verification_reports_v1(
        portable,
        serialized(input),
    )

    assert result.status == "equivalent"
    assert result.differences == ()
    assert result.authenticity == "not_checked"
    assert (
        result.evidence_recomputation
        == "not_performed"
    )


def test_comparison_identifies_material_core_difference() -> None:
    first_report = report()
    second_report = replace(
        first_report,
        findings=(
            VerificationFinding(
                check_id="dataset.source_binding",
                outcome="fail",
                reason_code="SOURCE_MISMATCH",
                observation_ids=(),
            ),
        ),
    )
    first = create_portable_verification_report_v1(
        PortableVerificationReportV1Input(
            kind="verification",
            result=first_report,
        )
    )
    second = create_portable_verification_report_v1(
        PortableVerificationReportV1Input(
            kind="verification",
            result=second_report,
        )
    )
    result = compare_portable_verification_reports_v1(
        first,
        second,
    )

    assert result.status == "different"
    assert result.differences == (
        "findings",
    )


def test_comparison_rejects_invalid_input() -> None:
    input = PortableVerificationReportV1Input(
        kind="verification",
        result=report(),
    )
    invalid = serialized(input)
    invalid["report_sha3_512"] = "f" * 128

    with pytest.raises(
        Exception,
        match="PORTABLE_REPORT_DIGEST_MISMATCH",
    ):
        compare_portable_verification_reports_v1(
            invalid,
            serialized(input),
        )