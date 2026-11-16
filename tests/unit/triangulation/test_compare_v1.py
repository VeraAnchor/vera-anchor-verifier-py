import math

import pytest

from vera_anchor_verifier import (
    VerificationFact,
    VerificationFactState,
    VerificationFactValue,
    VerificationFinding,
    VerificationObservation,
    VerificationObservationSource,
    VerificationReport,
    VerificationSubject,
)
from vera_anchor_verifier.triangulation import (
    TriangulationFactPlanV1,
    TriangulationRelationshipPlanV1,
    TriangulationV1Input,
    TriangulationV1Result,
    compare_evidence_triangulation_v1,
)


def subject(
    *,
    network: bool = True,
    subject_id: str = "dataset.alpha",
) -> VerificationSubject:
    value: VerificationSubject = {
        "kind": "dataset",
        "id": subject_id,
    }
    if network:
        value["hedera_network"] = "testnet"
    return value


def fact(
    value: VerificationFactValue = 7,
    *,
    state: VerificationFactState = "available",
    reason: str | None = None,
) -> VerificationFact:
    return VerificationFact(
        key="value",
        state=state,
        value=value,
        reason_code=reason,
    )


def observation(
    observation_id: str,
    source: VerificationObservationSource,
    value: VerificationFactValue = 7,
    *,
    network: bool = True,
    state: VerificationFactState = "available",
    reason: str | None = None,
    subject_id: str = "dataset.alpha",
) -> VerificationObservation:
    return VerificationObservation(
        id=observation_id,
        subject=subject(
            network=network,
            subject_id=subject_id,
        ),
        source=source,
        facts=(
            fact(
                value,
                state=state,
                reason=reason,
            ),
        ),
    )


def source_report(
    *,
    source_value: VerificationFactValue = 7,
    source_failure: bool = False,
) -> VerificationReport:
    findings = (
        VerificationFinding(
            check_id="dataset.source_binding",
            outcome="fail" if source_failure else "pass",
            reason_code=None,
            observation_ids=(),
        ),
        VerificationFinding(
            check_id="dataset.bundle_consistency",
            outcome="pass",
            reason_code=None,
            observation_ids=(),
        ),
        VerificationFinding(
            check_id="intent.subject",
            outcome="pass",
            reason_code=None,
            observation_ids=(),
        ),
    )

    return VerificationReport(
        intent={
            "subject": subject(),
            "expected": [],
        },
        findings=findings,
        observations=(
            observation(
                "dataset.local",
                "local_computation",
                source_value,
                network=False,
            ),
        ),
    )


def relationship(
    *,
    right_id: str = "public.record",
) -> TriangulationRelationshipPlanV1:
    return TriangulationRelationshipPlanV1(
        id="provided_public_record",
        left_observation_id="dataset.local",
        right_observation_id=right_id,
        comparisons=(
            TriangulationFactPlanV1(
                key="value",
                left_key="value",
                right_key="value",
            ),
        ),
    )


def compare(
    public: VerificationObservation,
    *,
    report: VerificationReport | None = None,
    plan: TriangulationRelationshipPlanV1 | None = None,
) -> TriangulationV1Result:
    return compare_evidence_triangulation_v1(
        TriangulationV1Input(
            source_report=report or source_report(),
            observations=(public,),
            relationships=(plan or relationship(),),
        )
    )


def test_matching_relationship_is_consistent() -> None:
    result = compare(
        observation(
            "public.record",
            "public_record",
        )
    )
    check = result.relationships[0].fact_comparisons[0]

    assert result.consistency == "consistent"
    assert result.relationships[0].status == "consistent"
    assert (check.outcome, check.reason_code) == (
        "pass",
        None,
    )


def test_fact_mismatch_is_conflict() -> None:
    result = compare(
        observation(
            "public.record",
            "public_record",
            8,
        )
    )
    check = result.relationships[0].fact_comparisons[0]

    assert result.consistency == "conflict"
    assert (check.outcome, check.reason_code) == (
        "fail",
        "FACT_MISMATCH",
    )


def test_unavailable_and_not_applicable_remain_distinct() -> None:
    unavailable = compare(
        observation(
            "public.record",
            "public_record",
            state="unavailable",
            reason="PUBLIC_UNAVAILABLE",
        )
    )
    check = unavailable.relationships[0].fact_comparisons[0]

    assert unavailable.consistency == "incomplete"
    assert check.reason_code == "PUBLIC_UNAVAILABLE"

    skipped = compare(
        observation(
            "public.record",
            "public_record",
            state="not_applicable",
        )
    )
    check = skipped.relationships[0].fact_comparisons[0]

    assert skipped.relationships[0].status == "not_applicable"
    assert (check.outcome, check.reason_code) == (
        "skipped",
        "FACT_NOT_APPLICABLE",
    )


def test_missing_observation_is_indeterminate() -> None:
    result = compare_evidence_triangulation_v1(
        TriangulationV1Input(
            source_report=source_report(),
            observations=(),
            relationships=(
                relationship(
                    right_id="public.missing",
                ),
            ),
        )
    )
    check = result.relationships[0].fact_comparisons[0]

    assert result.consistency == "incomplete"
    assert (check.outcome, check.reason_code) == (
        "indeterminate",
        "OBSERVATION_UNAVAILABLE",
    )
    assert result.report.findings[-1].observation_ids == (
        "dataset.local",
    )


def test_external_network_scope_is_required() -> None:
    result = compare(
        observation(
            "public.record",
            "public_record",
            network=False,
        )
    )
    check = result.relationships[0].fact_comparisons[0]

    assert (check.outcome, check.reason_code) == (
        "indeterminate",
        "NETWORK_SCOPE_UNAVAILABLE",
    )


def test_subject_and_network_mismatch_are_conflicts() -> None:
    wrong_subject = compare(
        observation(
            "public.record",
            "public_record",
            subject_id="dataset.other",
        )
    )
    check = wrong_subject.relationships[0].fact_comparisons[0]

    assert check.reason_code == "OBSERVATION_SUBJECT_MISMATCH"

    public = observation(
        "public.record",
        "public_record",
    )
    public = VerificationObservation(
        id=public.id,
        subject={
            **public.subject,
            "hedera_network": "mainnet",
        },
        source=public.source,
        facts=public.facts,
    )

    wrong_network = compare(public)
    check = wrong_network.relationships[0].fact_comparisons[0]

    assert check.reason_code == "OBSERVATION_NETWORK_MISMATCH"


def test_object_is_numeric_semantics_are_preserved() -> None:
    negative_zero = compare(
        observation(
            "public.record",
            "public_record",
            -0.0,
        ),
        report=source_report(
            source_value=0,
        ),
    )
    assert negative_zero.consistency == "conflict"

    boolean = compare(
        observation(
            "public.record",
            "public_record",
            True,
        ),
        report=source_report(
            source_value=1,
        ),
    )
    assert boolean.consistency == "conflict"


def test_source_failure_forces_conflict() -> None:
    result = compare(
        observation(
            "public.record",
            "public_record",
        ),
        report=source_report(
            source_failure=True,
        ),
    )

    assert result.consistency == "conflict"


def test_no_relationships_is_incomplete() -> None:
    result = compare_evidence_triangulation_v1(
        TriangulationV1Input(
            source_report=source_report(),
            observations=(),
            relationships=(),
        )
    )

    assert result.consistency == "incomplete"


def test_relationship_roles_and_external_local_fail_closed() -> None:
    with pytest.raises(
        TypeError,
        match="relationship roles",
    ):
        compare(
            observation(
                "public.record",
                "hedera_mirror",
            )
        )

    with pytest.raises(
        TypeError,
        match="cannot assert local computation",
    ):
        compare_evidence_triangulation_v1(
            TriangulationV1Input(
                source_report=source_report(),
                observations=(
                    observation(
                        "external.local",
                        "local_computation",
                    ),
                ),
                relationships=(),
            )
        )


def test_duplicate_observation_and_comparison_fail_closed() -> None:
    duplicate = observation(
        "dataset.local",
        "public_record",
    )

    with pytest.raises(
        TypeError,
        match="Duplicate triangulation observation",
    ):
        compare_evidence_triangulation_v1(
            TriangulationV1Input(
                source_report=source_report(),
                observations=(duplicate,),
                relationships=(),
            )
        )

    duplicate_plan = TriangulationRelationshipPlanV1(
        id="provided_public_record",
        left_observation_id="dataset.local",
        right_observation_id="public.record",
        comparisons=(
            TriangulationFactPlanV1(
                "value",
                "value",
                "value",
            ),
            TriangulationFactPlanV1(
                "value",
                "value",
                "value",
            ),
        ),
    )

    with pytest.raises(
        TypeError,
        match="Duplicate triangulation comparison",
    ):
        compare(
            observation(
                "public.record",
                "public_record",
            ),
            plan=duplicate_plan,
        )


def test_invalid_fact_values_are_rejected() -> None:
    nonfinite = VerificationObservation(
        id="public.record",
        subject=subject(),
        source="public_record",
        facts=(
            VerificationFact(
                key="value",
                state="available",
                value=math.inf,
            ),
        ),
    )

    with pytest.raises(
        TypeError,
        match="Invalid available fact",
    ):
        compare(nonfinite)