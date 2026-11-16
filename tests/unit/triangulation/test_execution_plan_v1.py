from typing import cast

import pytest

from vera_anchor_verifier.contracts import VerificationIntent
from vera_anchor_verifier.profiles.execution.contract_v1 import (
    PublicExecutionStandardsEvidence,
)
from vera_anchor_verifier.profiles.execution.verification_v1 import (
    ExecutionV1Input,
)
from vera_anchor_verifier.triangulation.compare_v1 import (
    compare_evidence_triangulation_v1,
)
from vera_anchor_verifier.triangulation.execution_plan_v1 import (
    EXECUTION_HEDERA_OBSERVATION_V1_ID,
    ExecutionTriangulationPlanV1,
    prepare_execution_triangulation_v1,
)

JOB = "11111111-1111-4111-8111-111111111111"
OTHER = "22222222-2222-4222-8222-222222222222"
RESULT = "33333333-3333-4333-8333-333333333333"
H1 = "a" * 128
H2 = "b" * 128


def evidence() -> dict[str, object]:
    return {
        "available": True,
        "contract_version": "1.0.0",
        "execution": {
            "job_id": JOB,
            "program": "sage",
            "proof_date": "2026-10-15",
            "hedera_network": "testnet",
            "pipeline_hash": H1,
        },
        "acceptance": {
            "digest": H1,
            "hcs": {
                "transaction_id": "0.0.11@1792033594.1",
                "topic_id": "0.0.22",
                "sequence_number": 3,
                "message_id": "3@0.0.22",
                "data_hash_sha3_512": H2,
            },
        },
    }


def execution_input(
    provided: object,
    result_id: str | None = None,
) -> ExecutionV1Input:
    raw: dict[str, object] = {
        "evidence": provided,
        "intent": cast(
            VerificationIntent,
            {
                "subject": {
                    "kind": "execution",
                    "id": JOB,
                    "hedera_network": "testnet",
                },
                "expected": [],
            },
        ),
    }

    if result_id is not None:
        raw["result_id"] = result_id

    return cast(ExecutionV1Input, raw)


def setup(
    provided: object | None = None,
    public: object | None = None,
    result_id: str | None = None,
) -> ExecutionTriangulationPlanV1:
    provided_value = (
        evidence()
        if provided is None
        else provided
    )
    public_value = (
        evidence()
        if public is None
        else public
    )

    return prepare_execution_triangulation_v1(
        execution_input(
            provided_value,
            result_id,
        ),
        cast(
            PublicExecutionStandardsEvidence,
            public_value,
        ),
    )


def comparison(
    plan: ExecutionTriangulationPlanV1,
    key: str,
):
    result = compare_evidence_triangulation_v1(
        plan.triangulation
    )

    return next(
        (
            item
            for item in result.relationships[0]
            .fact_comparisons
            if item.key == key
        ),
        None,
    )


def test_creates_job_scoped_three_way_authority_plan() -> None:
    plan = setup()

    assert plan.stage == "unresolved_authority_plan"
    assert plan.hedera_resolution == "not_checked"
    assert [
        relationship.id
        for relationship in plan.triangulation.relationships
    ] == [
        "provided_public_record",
        "public_record_hedera",
        "provided_hedera",
    ]

    assert (
        plan.triangulation.relationships[1]
        .right_observation_id
        == EXECUTION_HEDERA_OBSERVATION_V1_ID
    )
    assert not any(
        observation.source == "hedera_mirror"
        for observation in plan.triangulation.observations
    )

    assert len(plan.hedera_targets) == 2

    target = plan.hedera_targets[0]
    assert target.source == "public_record"
    assert target.role == "acceptance_anchor"
    assert (
        target.transaction_id
        == "0.0.11@1792033594.000000001"
    )
    assert target.topic_id == "0.0.22"
    assert target.sequence_number == 3

    assert [
        item.key
        for item in plan.triangulation.relationships[1]
        .comparisons
    ] == [
        "acceptance_anchor.transaction_id",
        "acceptance_anchor.topic_id",
        "acceptance_anchor.sequence_number",
    ]

    result = comparison(
        plan,
        "acceptance_anchor.transaction_id",
    )
    assert result is not None
    assert result.outcome == "pass"


def test_detects_provided_public_commitment_disagreement() -> None:
    public = evidence()
    execution = cast(
        dict[str, object],
        public["execution"],
    )
    execution["pipeline_hash"] = H2

    result = comparison(
        setup(evidence(), public),
        "execution.pipeline_hash",
    )

    assert result is not None
    assert result.outcome == "fail"
    assert result.reason_code == "FACT_MISMATCH"


def test_detects_substituted_acceptance_transaction() -> None:
    public = evidence()
    acceptance = cast(
        dict[str, object],
        public["acceptance"],
    )
    hcs = cast(
        dict[str, object],
        acceptance["hcs"],
    )
    hcs["transaction_id"] = (
        "0.0.12@1792033594.1"
    )

    result = comparison(
        setup(evidence(), public),
        "acceptance_anchor.transaction_id",
    )

    assert result is not None
    assert result.outcome == "fail"


def test_absent_public_acceptance_locator_never_passes() -> None:
    public = evidence()
    acceptance = cast(
        dict[str, object],
        public["acceptance"],
    )
    acceptance["hcs"] = None

    result = comparison(
        setup(evidence(), public),
        "acceptance_anchor.transaction_id",
    )

    assert result is not None
    assert result.outcome == "indeterminate"


def test_rejects_public_job_or_network_substitution() -> None:
    wrong_job = evidence()
    wrong_job_execution = cast(
        dict[str, object],
        wrong_job["execution"],
    )
    wrong_job_execution["job_id"] = OTHER

    with pytest.raises(
        TypeError,
        match="scope mismatch",
    ):
        setup(evidence(), wrong_job)

    wrong_network = evidence()
    wrong_network_execution = cast(
        dict[str, object],
        wrong_network["execution"],
    )
    wrong_network_execution["hedera_network"] = (
        "mainnet"
    )

    with pytest.raises(
        TypeError,
        match="scope mismatch",
    ):
        setup(evidence(), wrong_network)


def test_requested_result_scope_rejects_substitution() -> None:
    public = evidence()
    public["result_evidence"] = {
        "result_id": OTHER,
        "digest": H1,
    }

    with pytest.raises(
        TypeError,
        match="result scope mismatch",
    ):
        setup(
            evidence(),
            public,
            RESULT,
        )

    good = evidence()
    good["result_evidence"] = {
        "result_id": RESULT,
        "digest": H1,
        "hcs": {
            "transaction_id": (
                "0.0.15@1792033599.2"
            ),
        },
    }

    plan = setup(
        good,
        good,
        RESULT,
    )

    assert len(
        [
            target
            for target in plan.hedera_targets
            if target.role
            == "result_evidence_anchor"
        ]
    ) == 2

    assert any(
        item.key
        == "result_evidence_anchor.transaction_id"
        for item in plan.triangulation
        .relationships[1].comparisons
    )

    without_result_scope = setup(
        good,
        good,
    )

    assert len(
        without_result_scope.hedera_targets
    ) == 2
    assert not any(
        "result_evidence" in item.key
        for item in without_result_scope
        .triangulation.relationships[1]
        .comparisons
    )


def test_rejects_inconsistent_message_locator() -> None:
    value = evidence()
    acceptance = cast(
        dict[str, object],
        value["acceptance"],
    )
    hcs = cast(
        dict[str, object],
        acceptance["hcs"],
    )
    hcs["message_id"] = "4@0.0.22"

    with pytest.raises(
        TypeError,
        match="locator conflict",
    ):
        setup(value)


def test_does_not_fabricate_sequence_from_topic_and_tx() -> None:
    value = evidence()
    acceptance = cast(
        dict[str, object],
        value["acceptance"],
    )
    acceptance["hcs"] = {
        "topic_id": "0.0.22",
        "transaction_id": (
            "0.0.11@1792033594.1"
        ),
    }

    target = setup(
        value,
        value,
    ).hedera_targets[0]

    assert target.topic_id is None
    assert target.sequence_number is None
    assert (
        target.transaction_id
        == "0.0.11@1792033594.000000001"
    )


def test_never_promotes_producer_data_hash_to_mirror_proof() -> None:
    plan = setup()
    comparisons = [
        item
        for relationship in plan.triangulation.relationships
        for item in relationship.comparisons
    ]

    assert not any(
        "data_hash" in item.key
        or "data_hash" in item.right_key
        for item in comparisons
    )
    assert not any(
        "mirror_message_sha3_512" in item.key
        for item in comparisons
    )


def test_rejects_unsafe_or_unavailable_evidence() -> None:
    with pytest.raises(
        TypeError,
        match="structural bounds",
    ):
        setup(
            {
                "malicious": lambda: 0,
            }
        )

    with pytest.raises(
        TypeError,
        match="unavailable",
    ):
        setup(
            evidence(),
            {
                "available": False,
            },
        )