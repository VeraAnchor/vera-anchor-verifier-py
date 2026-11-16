from typing import cast

import pytest

from vera_anchor_verifier.contracts import (
    VerificationFact,
    VerificationIntent,
)
from vera_anchor_verifier.profiles.execution.contract_v1 import (
    PublicExecutionStandardsEvidence,
)
from vera_anchor_verifier.profiles.execution.recomputation_v1 import (
    compute_execution_domain_separated_sha3_512,
)
from vera_anchor_verifier.profiles.execution.standards_plan_v1 import (
    build_standards_resolution_plan,
)
from vera_anchor_verifier.profiles.execution.verification_v1 import (
    ExecutionV1Input,
    ExecutionV1Report,
    verify_execution_v1_with_intent,
)

JOB = (
    "11111111-1111-4111-8111-111111111111"
)
OTHER_JOB = (
    "22222222-2222-4222-8222-222222222222"
)
RESULT = (
    "33333333-3333-4333-8333-333333333333"
)
HASH = "a" * 128


def evidence(
    *,
    program: str = "sage",
) -> dict[str, object]:
    return {
        "available": True,
        "contract_version": "1.0.0",
        "execution": {
            "job_id": JOB,
            "program": program,
            "proof_date": "2026-10-15",
            "hedera_network": "testnet",
            "pipeline_hash": HASH,
        },
    }


def intent(
    job_id: str = JOB,
    network: str = "testnet",
) -> VerificationIntent:
    return cast(
        VerificationIntent,
        {
            "subject": {
                "kind": "execution",
                "id": job_id,
                "hedera_network": network,
            },
            "expected": [],
        },
    )


def finding(
    report: ExecutionV1Report,
    check_id: str,
):
    return next(
        item
        for item
        in report.findings
        if item.check_id == check_id
    )


def observation(
    report: ExecutionV1Report,
    observation_id: str,
):
    return next(
        item
        for item
        in report.observations
        if item.id == observation_id
    )


def test_defaults_to_sage_and_preserves_caller_scope() -> None:
    report = (
        verify_execution_v1_with_intent(
            {
                "evidence": evidence(),
                "intent": intent(),
                "expected_program": "sage",
            }
        )
    )

    assert (
        finding(
            report,
            "execution.identity",
        ).outcome
        == "pass"
    )
    assert (
        finding(
            report,
            "profile.program_scope",
        ).outcome
        == "pass"
    )
    assert (
        finding(
            report,
            "intent.subject",
        ).outcome
        == "pass"
    )
    assert (
        finding(
            report,
            "intent.program",
        ).outcome
        == "pass"
    )

    standards = finding(
        report,
        "standards.references_resolved",
    )

    assert standards.outcome == "indeterminate"
    assert standards.reason_code == (
        "STANDARDS_RESOLUTION_"
        "NOT_INDEPENDENTLY_VERIFIED"
    )

    assert report.verification_scope.profile == (
        "sage-standards-v1"
    )
    assert (
        report.verification_scope.expected_program
        == "sage"
    )
    assert (
        report.verification_scope.requested_result_id
        is None
    )


def test_distinguishes_generic_execution_from_sage() -> None:
    generic = (
        verify_execution_v1_with_intent(
            {
                "profile": "execution-v1",
                "evidence": evidence(
                    program="other-compute"
                ),
                "intent": intent(),
                "expected_program": (
                    "other-compute"
                ),
                "result_id": RESULT,
            }
        )
    )

    assert (
        finding(
            generic,
            "profile.program_scope",
        ).outcome
        == "pass"
    )
    assert (
        finding(
            generic,
            "profile.standards_scope",
        ).outcome
        == "skipped"
    )
    assert (
        finding(
            generic,
            "intent.program",
        ).outcome
        == "pass"
    )
    assert not any(
        item.check_id
        == "standards.baseline_reference"
        for item in generic.findings
    )

    assert (
        generic.verification_scope.profile
        == "execution-v1"
    )
    assert (
        generic.verification_scope.expected_program
        == "other-compute"
    )
    assert (
        generic.verification_scope.requested_result_id
        == RESULT
    )

    sage = (
        verify_execution_v1_with_intent(
            {
                "profile": (
                    "sage-standards-v1"
                ),
                "evidence": evidence(),
                "intent": intent(),
            }
        )
    )

    assert any(
        item.check_id
        == "standards.baseline_reference"
        for item in sage.findings
    )


def test_rejects_profile_downgrades() -> None:
    downgraded = (
        verify_execution_v1_with_intent(
            {
                "profile": "execution-v1",
                "evidence": evidence(),
                "intent": intent(),
                "expected_program": (
                    "other-compute"
                ),
            }
        )
    )

    profile = finding(
        downgraded,
        "profile.program_scope",
    )

    assert profile.outcome == "fail"
    assert profile.reason_code == (
        "EXECUTION_PROFILE_PROGRAM_MISMATCH"
    )

    wrong_profile = (
        verify_execution_v1_with_intent(
            {
                "profile": (
                    "sage-standards-v1"
                ),
                "evidence": evidence(
                    program="other-compute"
                ),
                "intent": intent(),
            }
        )
    )

    assert (
        finding(
            wrong_profile,
            "profile.program_scope",
        ).outcome
        == "fail"
    )

    with pytest.raises(
        TypeError,
        match="independently supplied expected_program",
    ):
        verify_execution_v1_with_intent(
            cast(
                ExecutionV1Input,
                {
                    "profile": "execution-v1",
                    "evidence": evidence(),
                    "intent": intent(),
                },
            )
        )

    with pytest.raises(
        TypeError,
        match="SAGE requires sage-standards-v1",
    ):
        verify_execution_v1_with_intent(
            {
                "profile": "execution-v1",
                "evidence": evidence(),
                "intent": intent(),
                "expected_program": "sage",
            }
        )

    with pytest.raises(
        TypeError,
        match="Unsupported execution verification profile",
    ):
        verify_execution_v1_with_intent(
            cast(
                ExecutionV1Input,
                {
                    "profile": "bogus",
                    "evidence": evidence(),
                    "intent": intent(),
                },
            )
        )


def test_fails_independent_subject_network_and_program_mismatches() -> None:
    report = (
        verify_execution_v1_with_intent(
            {
                "evidence": evidence(),
                "intent": intent(
                    OTHER_JOB,
                    "mainnet",
                ),
                "expected_program": "cipher",
            }
        )
    )

    assert (
        finding(
            report,
            "intent.subject",
        ).outcome
        == "fail"
    )
    assert (
        finding(
            report,
            "execution.network_scope",
        ).outcome
        == "fail"
    )
    assert (
        finding(
            report,
            "intent.program",
        ).outcome
        == "fail"
    )


def test_invalid_bounded_input_remains_a_reported_failure() -> None:
    report = (
        verify_execution_v1_with_intent(
            cast(
                ExecutionV1Input,
                {
                    "evidence": [],
                    "intent": intent(),
                },
            )
        )
    )

    bounds = finding(
        report,
        "input.bounds",
    )

    assert bounds.outcome == "fail"
    assert bounds.reason_code == (
        "INPUT_STRUCTURE_INVALID"
    )
    assert bounds.observation_ids == ()

    assert (
        finding(
            report,
            "profile.program_scope",
        ).outcome
        == "indeterminate"
    )
    assert (
        finding(
            report,
            "intent.subject",
        ).outcome
        == "indeterminate"
    )

    provided = observation(
        report,
        "execution.provided",
    )

    assert provided.facts == (
        VerificationFact(
            key="hedera_network",
            state="available",
            value="testnet",
            reason_code=None,
        ),
    )


def test_recomputed_checks_get_independent_local_observation() -> None:
    value = evidence()

    payload = {
        "job_id": JOB,
        "proof_date": "2026-10-15",
    }

    digest = (
        compute_execution_domain_separated_sha3_512(
            (
                "vera-anchor:"
                "execution-binding:v1"
            ),
            payload,
        )
    )

    value["binding"] = {
        "schema": "ExecutionBindingV1",
        "digest": digest,
        "digest_payload": payload,
        "canonicalization": "RFC8785-JCS",
        "digest_algorithm": "SHA3-512",
        "domain_separator": (
            "vera-anchor:"
            "execution-binding:v1"
        ),
        "finalized_at": (
            "2026-10-15T00:00:00.000Z"
        ),
    }

    report = (
        verify_execution_v1_with_intent(
            {
                "evidence": value,
                "intent": intent(),
            }
        )
    )

    computed = observation(
        report,
        "execution.recomputed",
    )

    assert any(
        fact.key
        == "check.binding.digest_recomputed"
        and fact.value is True
        for fact in computed.facts
    )

    binding = finding(
        report,
        "binding.digest_recomputed",
    )

    assert binding.outcome == "pass"
    assert binding.observation_ids == (
        "execution.provided",
        "execution.recomputed",
    )


def test_supplied_standards_resolution_never_becomes_independent_proof() -> None:
    value = cast(
        dict[str, object],
        evidence(),
    )

    plan = build_standards_resolution_plan(
        cast(
            PublicExecutionStandardsEvidence,
            value,
        )
    )

    material = {
        "standards_resolution": {
            "schema_version": (
                "vera.standards-resolution.v1"
            ),
            "hedera_network": "testnet",
            "state": "verified",
            "items": [
                {
                    "key": item.key,
                    "standard": item.standard,
                    "reference": (
                        item.reference
                    ),
                    "state": "verified",
                }
                for item in plan
            ],
        },
    }

    report = (
        verify_execution_v1_with_intent(
            cast(
                ExecutionV1Input,
                {
                    "evidence": value,
                    "intent": intent(),
                    "verification_material": (
                        material
                    ),
                },
            )
        )
    )

    resolved = finding(
        report,
        "standards.references_resolved",
    )

    assert resolved.outcome == "indeterminate"
    assert resolved.reason_code == (
        "STANDARDS_RESOLUTION_"
        "NOT_INDEPENDENTLY_VERIFIED"
    )


def test_rejects_unsupported_generic_commitments_and_bad_scope() -> None:
    with pytest.raises(
        TypeError,
        match="does not support generic expected commitments",
    ):
        verify_execution_v1_with_intent(
            cast(
                ExecutionV1Input,
                {
                    "evidence": evidence(),
                    "intent": {
                        "subject": {
                            "kind": "execution",
                            "id": JOB,
                            "hedera_network": "testnet",
                        },
                        "expected": [
                            {
                                "key": "digest",
                            }
                        ],
                    },
                },
            )
        )

    with pytest.raises(
        TypeError,
        match="Requested result_id must be a UUID",
    ):
        verify_execution_v1_with_intent(
            cast(
                ExecutionV1Input,
                {
                    "evidence": evidence(),
                    "intent": intent(),
                    "result_id": "not-a-uuid",
                },
            )
        )

    with pytest.raises(
        TypeError,
        match="bounded canonical string",
    ):
        verify_execution_v1_with_intent(
            cast(
                ExecutionV1Input,
                {
                    "evidence": evidence(),
                    "intent": intent(),
                    "expected_program": (
                        " sage "
                    ),
                },
            )
        )