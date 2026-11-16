from copy import deepcopy
from typing import cast

from vera_anchor_verifier.profiles.execution.contract_v1 import (
    SUPPORTED_PUBLIC_STANDARDS_CONTRACT_VERSIONS,
    ExecutionVerificationContext,
    PublicExecutionStandardsEvidence,
    PublicExecutionVerificationMaterial,
)
from vera_anchor_verifier.profiles.execution.reason_codes_v1 import (
    EXECUTION_VERIFICATION_REASON_CODES as REASONS,
)
from vera_anchor_verifier.profiles.execution.recomputation_v1 import (
    compute_execution_domain_separated_sha3_512,
)
from vera_anchor_verifier.profiles.execution.rules_v1 import (
    COMMON_EXECUTION_VERIFICATION_RULES,
    EXECUTION_VERIFICATION_RULES,
)
from vera_anchor_verifier.profiles.execution.standards_plan_v1 import (
    build_standards_resolution_plan,
)

JOB_ID = (
    "11111111-1111-4111-8111-111111111111"
)
RESULT_ID = (
    "22222222-2222-4222-8222-222222222222"
)
PROOF_DATE = "2026-10-05"
NETWORK = "mainnet"
PIPELINE_HASH = "a" * 128
SHA256_A = "d" * 64
SHA256_B = "e" * 64
GIT_COMMIT = "f" * 40

PARAM_HCS13_REF = (
    "hcs://13/0.0.7001#1"
)
PARAM_PAYLOAD = {
    "min_cluster_size": 3,
    "metric": "cosine",
}

ACCEPTED_AT = (
    "2026-10-05T10:00:00.000Z"
)
STARTED_AT = (
    "2026-10-05T10:05:00.000Z"
)

CONSENSUS_EXACT = (
    "1791194420.123456789"
)
EXECUTION_START_EXACT = (
    "1791194700.123456789"
)

EXPECTED_RULE_IDS = (
    "public_evidence.available",
    "public_evidence.contract_version",
    "execution.identity",
    "execution.network_scope",
    "execution.dataset_commitment",
    "standards.baseline_reference",
    "standards.requester_reference",
    "standards.executor_reference",
    "standards.capability_reference",
    "standards.schema_references",
    "standards.reference_summary",
    "standards.references_resolved",
    "binding.contract_metadata",
    "binding.digest_recomputed",
    "acceptance.contract_metadata",
    "acceptance.digest_recomputed",
    "acceptance.binding_link",
    "acceptance.state_confirmed",
    "acceptance.hcs_confirmation",
    "acceptance.precedes_execution",
    "software.pipeline_link",
    "parameters.commitment_matches",
    "result_evidence.scope",
    "result_evidence.contract_metadata",
    "result_evidence.sealed",
    "result_evidence.binding_link",
    "result_evidence.acceptance_link",
    "result_evidence.pipeline_link",
    "result_evidence.hcs_receipt",
    "result_evidence.digest_recomputed",
)


def schema(
    index: int = 0,
) -> dict[str, object]:
    role = (
        "parameters"
        if index == 0
        else f"schema_{index}"
    )
    topic = 7001 + index
    sequence = index + 1

    hcs13_ref = (
        f"hcs://13/0.0.{topic}"
        f"#{sequence}"
    )

    payload = (
        PARAM_PAYLOAD
        if index == 0
        else {
            "index": index,
            "role": role,
        }
    )

    digest = (
        compute_execution_domain_separated_sha3_512(
            "vera-anchor:hcs13-instance:v1",
            {
                "role": role,
                "hcs13_ref": hcs13_ref,
                "payload": payload,
            },
        )
    )

    return {
        "role": role,
        "ordinal": index,
        "schema_uid": (
            f"vera.schema.{role}.v1"
        ),
        "display_name": role,
        "semantic_version": "1.0.0",
        "registry_topic_id": (
            f"0.0.{topic}"
        ),
        "registry_sequence_number": (
            sequence
        ),
        "hcs13_ref": hcs13_ref,
        "schema_checksum_sha256": (
            SHA256_A
        ),
        "instance_digest_sha3_512": (
            digest
        ),
    }


def evidence(
) -> PublicExecutionStandardsEvidence:
    binding_payload = {
        "record_type": (
            "vera_anchor.execution_binding"
        ),
        "job_id": JOB_ID,
        "proof_date": PROOF_DATE,
        "hedera_network": NETWORK,
    }

    binding_digest = (
        compute_execution_domain_separated_sha3_512(
            (
                "vera-anchor:"
                "execution-binding:v1"
            ),
            binding_payload,
        )
    )

    acceptance_payload = {
        "record_type": (
            "vera_anchor.execution_acceptance"
        ),
        "acceptance_schema": (
            "ExecutionAcceptanceV1"
        ),
        "binding_digest_sha3_512": (
            binding_digest
        ),
        "job_id": JOB_ID,
        "proof_date": PROOF_DATE,
        "hedera_network": NETWORK,
        "admission_policy": {
            "policy_id": "sage-default",
            (
                "require_hcs_confirmation_"
                "before_execution"
            ): True,
        },
        "accepted_at": ACCEPTED_AT,
    }

    acceptance_digest = (
        compute_execution_domain_separated_sha3_512(
            (
                "vera-anchor:"
                "execution-acceptance:v1"
            ),
            acceptance_payload,
        )
    )

    result_payload = {
        "record_type": (
            "vera_anchor.result_evidence"
        ),
        "result_id": RESULT_ID,
        "binding_digest_sha3_512": (
            binding_digest
        ),
        "acceptance_digest_sha3_512": (
            acceptance_digest
        ),
        "pipeline_hash_sha3_512": (
            PIPELINE_HASH
        ),
    }

    result_digest = (
        compute_execution_domain_separated_sha3_512(
            (
                "vera-anchor:"
                "result-evidence:v1"
            ),
            result_payload,
        )
    )

    return cast(
        PublicExecutionStandardsEvidence,
        {
            "available": True,
            "contract_version": "1.0.0",
            "execution": {
                "job_id": JOB_ID,
                "result_id": RESULT_ID,
                "proof_date": PROOF_DATE,
                "program": "sage",
                "status": "completed",
                "hedera_network": NETWORK,
                "pipeline_hash": (
                    PIPELINE_HASH
                ),
                "dataset": {
                    "dataset_key": (
                        "public-dataset"
                    ),
                    "dataset_version": 1,
                    (
                        "dataset_fingerprint_"
                        "sha3_512"
                    ): "b" * 128,
                    (
                        "dataset_manifest_"
                        "sha3_512"
                    ): "c" * 128,
                },
            },
            "standards": {
                "baseline": {
                    "baseline_id": (
                        "VA-SAGE-HCS-"
                        "BASELINE-001"
                    ),
                    "source_commit": (
                        GIT_COMMIT
                    ),
                    "source_documents": [
                        {
                            "standard": (
                                "HCS-11"
                            ),
                            "version": "1.1",
                            "path": (
                                "standards/"
                                "hcs-11.json"
                            ),
                            "sha256": (
                                SHA256_A
                            ),
                        }
                    ],
                },
                "schemas": [
                    schema()
                ],
                "reference_complete": True,
                "publicly_resolvable": True,
            },
            "agents": {
                "requester": {
                    "logical_id": (
                        "requester"
                    ),
                    "hcs14_uaid": (
                        "uaid:did:requester"
                    ),
                    "hcs11": {
                        "account_id": (
                            "0.0.1001"
                        ),
                        (
                            "profile_registry_"
                            "topic_id"
                        ): "0.0.2001",
                        (
                            "profile_registry_"
                            "sequence"
                        ): 11,
                        "profile_hcs1_ref": (
                            "hcs://1/"
                            "0.0.2001/11"
                        ),
                        (
                            "profile_checksum_"
                            "sha256"
                        ): SHA256_A,
                    },
                },
                "executor": {
                    "logical_id": (
                        "executor"
                    ),
                    "hcs14_uaid": (
                        "uaid:did:executor"
                    ),
                    "hcs11": {
                        "account_id": (
                            "0.0.1002"
                        ),
                        (
                            "profile_registry_"
                            "topic_id"
                        ): "0.0.2002",
                        (
                            "profile_registry_"
                            "sequence"
                        ): 12,
                        "profile_hcs1_ref": (
                            "hcs://1/"
                            "0.0.2002/12"
                        ),
                        (
                            "profile_checksum_"
                            "sha256"
                        ): SHA256_B,
                    },
                },
            },
            "capability": {
                "standard": "HCS-26",
                (
                    "discovery_registry_"
                    "topic_id"
                ): "0.0.3001",
                "skill_uid": (
                    "expression_clustering_v1"
                ),
                "skill_version": "1.0.0",
                (
                    "version_registry_"
                    "topic_id"
                ): "0.0.3002",
                (
                    "version_sequence_number"
                ): 21,
                "manifest_hcs1_ref": (
                    "hcs://1/0.0.3002/21"
                ),
                (
                    "manifest_checksum_sha256"
                ): SHA256_A,
                "repository_uri": (
                    "https://example.test/repo"
                ),
                "repository_commit": (
                    GIT_COMMIT
                ),
            },
            "software_release": {
                "repository_uri": (
                    "https://example.test/repo"
                ),
                "git_commit": GIT_COMMIT,
                "pipeline_hash_sha3_512": (
                    PIPELINE_HASH
                ),
            },
            "binding": {
                "schema": (
                    "ExecutionBindingV1"
                ),
                "digest": binding_digest,
                "digest_payload": (
                    binding_payload
                ),
                "canonicalization": (
                    "RFC8785-JCS"
                ),
                "digest_algorithm": (
                    "SHA3-512"
                ),
                "domain_separator": (
                    "vera-anchor:"
                    "execution-binding:v1"
                ),
                "finalized_at": (
                    "2026-10-05"
                    "T09:59:00.000Z"
                ),
            },
            "acceptance": {
                "schema": (
                    "ExecutionAcceptanceV1"
                ),
                "digest": acceptance_digest,
                "digest_payload": (
                    acceptance_payload
                ),
                "canonicalization": (
                    "RFC8785-JCS"
                ),
                "digest_algorithm": (
                    "SHA3-512"
                ),
                "domain_separator": (
                    "vera-anchor:"
                    "execution-acceptance:v1"
                ),
                "state": "confirmed",
                "admission_policy_id": (
                    "sage-default"
                ),
                (
                    "requires_hcs_confirmation"
                ): True,
                "binding_digest": (
                    binding_digest
                ),
                "accepted_at": ACCEPTED_AT,
                "hcs": {
                    "topic_id": (
                        "0.0.5001"
                    ),
                    "transaction_id": (
                        "0.0.5001@"
                        "1760000000.123456789"
                    ),
                    "message_id": (
                        "0.0.5001@"
                        "1760000000.123456789"
                    ),
                    "sequence_number": 41,
                    (
                        "consensus_timestamp_"
                        "exact"
                    ): CONSENSUS_EXACT,
                },
            },
            "result_evidence": {
                "result_id": RESULT_ID,
                "schema": (
                    "ResultEvidenceV1"
                ),
                "digest": result_digest,
                "digest_payload": (
                    result_payload
                ),
                "canonicalization": (
                    "RFC8785-JCS"
                ),
                "digest_algorithm": (
                    "SHA3-512"
                ),
                "domain_separator": (
                    "vera-anchor:"
                    "result-evidence:v1"
                ),
                "binding_digest": (
                    binding_digest
                ),
                "acceptance_digest": (
                    acceptance_digest
                ),
                "pipeline_hash": (
                    PIPELINE_HASH
                ),
                "sealed_at": (
                    "2026-10-05"
                    "T10:10:00.000Z"
                ),
                "hcs": {
                    "transaction_id": (
                        "0.0.5002@"
                        "1760000100.123456789"
                    ),
                    "topic_id": (
                        "0.0.5002"
                    ),
                },
            },
        },
    )


def material(
    value: PublicExecutionStandardsEvidence,
) -> PublicExecutionVerificationMaterial:
    plan = (
        build_standards_resolution_plan(
            value
        )
    )

    return cast(
        PublicExecutionVerificationMaterial,
        {
            "parameter_instance": {
                "role": "parameters",
                "hcs13_ref": (
                    PARAM_HCS13_REF
                ),
                "domain_separator": (
                    "vera-anchor:"
                    "hcs13-instance:v1"
                ),
                "payload": (
                    PARAM_PAYLOAD
                ),
            },
            "execution_start": {
                "started_at": (
                    STARTED_AT
                ),
                "hcs_transaction_id": (
                    "0.0.5003@"
                    "1791194699.123456789"
                ),
                "hcs_topic_id": (
                    "0.0.5003"
                ),
                (
                    "consensus_timestamp_"
                    "exact"
                ): EXECUTION_START_EXACT,
            },
            "standards_resolution": {
                "schema_version": (
                    "vera.standards-"
                    "resolution.v1"
                ),
                "hedera_network": (
                    NETWORK
                ),
                "state": "verified",
                "items": [
                    {
                        "key": item.key,
                        "standard": (
                            item.standard
                        ),
                        "reference": (
                            item.reference
                        ),
                        "state": (
                            "verified"
                        ),
                    }
                    for item in plan
                ],
            },
        },
    )


_MISSING = object()


def context(
    *,
    evidence_value: (
        PublicExecutionStandardsEvidence
        | None
    ) = None,
    material_value: object = _MISSING,
    network: str = NETWORK,
    result_id: str = RESULT_ID,
) -> ExecutionVerificationContext:
    current = (
        evidence()
        if evidence_value is None
        else evidence_value
    )

    current_material = (
        material(current)
        if material_value is _MISSING
        else cast(
            (
                PublicExecutionVerificationMaterial
                | None
            ),
            material_value,
        )
    )

    return ExecutionVerificationContext(
        evidence=current,
        verification_material=(
            current_material
        ),
        expected_network=cast(
            object,
            network,
        ),
        requested_result_id=(
            result_id
        ),
        supported_contract_versions=(
            SUPPORTED_PUBLIC_STANDARDS_CONTRACT_VERSIONS
        ),
    )


def rule(
    rule_id: str,
):
    return next(
        item
        for item
        in EXECUTION_VERIFICATION_RULES
        if item.id == rule_id
    )


def assert_rule(
    rule_id: str,
    current: ExecutionVerificationContext,
    status: str,
    reason: str,
) -> None:
    result = rule(
        rule_id
    ).evaluate(
        current
    )

    assert result.status == status
    assert (
        result.reason_code
        == reason
    )


def test_pins_order_and_common_profile_boundary() -> None:
    assert tuple(
        item.id
        for item
        in EXECUTION_VERIFICATION_RULES
    ) == EXPECTED_RULE_IDS

    assert len(
        set(
            EXPECTED_RULE_IDS
        )
    ) == len(
        EXPECTED_RULE_IDS
    )

    assert all(
        item.group != "standards"
        for item
        in COMMON_EXECUTION_VERIFICATION_RULES
    )

    assert tuple(
        item
        for item
        in EXECUTION_VERIFICATION_RULES
        if item.group != "standards"
    ) == (
        COMMON_EXECUTION_VERIFICATION_RULES
    )


def test_valid_result_scoped_evidence_passes_every_rule() -> None:
    results = tuple(
        item.evaluate(
            context()
        )
        for item
        in EXECUTION_VERIFICATION_RULES
    )

    assert all(
        result.status == "pass"
        for result in results
    )

    assert all(
        result.reason_code
        == REASONS.CHECK_PASSED
        for result in results
    )


def test_execution_scope_and_malformed_nested_shapes_fail_closed() -> None:
    value = evidence()

    value["execution"] = cast(
        object,
        [],
    )

    assert_rule(
        "execution.identity",
        context(
            evidence_value=value
        ),
        "fail",
        REASONS.MALFORMED_EVIDENCE,
    )

    assert_rule(
        "execution.network_scope",
        context(
            network="testnet"
        ),
        "fail",
        REASONS.NETWORK_SCOPE_MISMATCH,
    )

    value = evidence()

    execution = value[
        "execution"
    ]
    assert execution is not None

    dataset = execution[
        "dataset"
    ]
    assert dataset is not None

    dataset[
        "dataset_version"
    ] = 0

    assert_rule(
        "execution.dataset_commitment",
        context(
            evidence_value=value
        ),
        "fail",
        REASONS.MALFORMED_EVIDENCE,
    )


def test_standards_resolution_rejects_duplicate_incomplete_and_cross_network_material() -> None:
    value = evidence()
    current_material = material(
        value
    )

    resolution = current_material[
        "standards_resolution"
    ]
    assert resolution is not None

    items = resolution[
        "items"
    ]
    assert items is not None

    items.append(
        deepcopy(
            items[0]
        )
    )

    assert_rule(
        "standards.references_resolved",
        context(
            evidence_value=value,
            material_value=current_material,
        ),
        "fail",
        REASONS.MALFORMED_EVIDENCE,
    )

    current_material = material(
        value
    )
    resolution = current_material[
        "standards_resolution"
    ]
    assert resolution is not None

    items = resolution[
        "items"
    ]
    assert items is not None

    items.pop()

    assert_rule(
        "standards.references_resolved",
        context(
            evidence_value=value,
            material_value=current_material,
        ),
        "fail",
        REASONS.REFERENCE_SET_INCOMPLETE,
    )

    current_material = material(
        value
    )
    resolution = current_material[
        "standards_resolution"
    ]
    assert resolution is not None

    resolution[
        "hedera_network"
    ] = "testnet"

    assert_rule(
        "standards.references_resolved",
        context(
            evidence_value=value,
            material_value=current_material,
        ),
        "fail",
        REASONS.NETWORK_SCOPE_MISMATCH,
    )


def test_binding_acceptance_and_result_digests_are_independently_recomputed() -> None:
    for (
        rule_id,
        record_name,
        reason,
    ) in (
        (
            "binding.digest_recomputed",
            "binding",
            REASONS.BINDING_DIGEST_MISMATCH,
        ),
        (
            "result_evidence.digest_recomputed",
            "result_evidence",
            (
                REASONS.RESULT_EVIDENCE_DIGEST_MISMATCH
            ),
        ),
    ):
        value = evidence()

        record = value[
            record_name
        ]
        assert record is not None

        record["digest"] = (
            "9" * 128
        )

        assert_rule(
            rule_id,
            context(
                evidence_value=value
            ),
            "fail",
            reason,
        )

    value = evidence()

    acceptance = value[
        "acceptance"
    ]
    assert acceptance is not None

    acceptance[
        "digest"
    ] = "9" * 128

    assert_rule(
        "acceptance.digest_recomputed",
        context(
            evidence_value=value
        ),
        "fail",
        REASONS.ACCEPTANCE_RECOMPUTATION_MISMATCH,
    )

    value = evidence()

    binding = value[
        "binding"
    ]
    assert binding is not None

    binding[
        "digest_payload"
    ] = cast(
        dict[str, object],
        {
            "bad": "\ud800",
        },
    )

    assert_rule(
        "binding.digest_recomputed",
        context(
            evidence_value=value
        ),
        "fail",
        REASONS.MALFORMED_EVIDENCE,
    )


def test_hcs_acceptance_order_is_strict_at_nanosecond_precision() -> None:
    value = evidence()
    current_material = material(
        value
    )

    start = current_material[
        "execution_start"
    ]
    assert start is not None

    start[
        "consensus_timestamp_exact"
    ] = "1791194420.123456790"

    assert_rule(
        "acceptance.precedes_execution",
        context(
            evidence_value=value,
            material_value=current_material,
        ),
        "pass",
        REASONS.CHECK_PASSED,
    )

    start[
        "consensus_timestamp_exact"
    ] = CONSENSUS_EXACT

    assert_rule(
        "acceptance.precedes_execution",
        context(
            evidence_value=value,
            material_value=current_material,
        ),
        "fail",
        REASONS.ACCEPTANCE_AFTER_EXECUTION_START,
    )

    start[
        "consensus_timestamp_exact"
    ] = "1791194420.123456788"

    assert_rule(
        "acceptance.precedes_execution",
        context(
            evidence_value=value,
            material_value=current_material,
        ),
        "fail",
        REASONS.ACCEPTANCE_AFTER_EXECUTION_START,
    )

    acceptance = value[
        "acceptance"
    ]
    assert acceptance is not None

    hcs = acceptance[
        "hcs"
    ]
    assert hcs is not None

    hcs[
        "consensus_timestamp_exact"
    ] = None

    assert_rule(
        "acceptance.hcs_confirmation",
        context(
            evidence_value=value
        ),
        "unavailable",
        REASONS.HCS_CONFIRMATION_REQUIRED,
    )


def test_non_hcs_acceptance_uses_exact_utc_times_without_treating_equality_as_ordered() -> None:
    value = evidence()

    acceptance = value[
        "acceptance"
    ]
    assert acceptance is not None

    acceptance[
        "requires_hcs_confirmation"
    ] = False

    current_material = material(
        value
    )
    start = current_material[
        "execution_start"
    ]
    assert start is not None

    start[
        "consensus_timestamp_exact"
    ] = None
    start[
        "hcs_transaction_id"
    ] = None
    start[
        "hcs_topic_id"
    ] = None

    assert_rule(
        "acceptance.precedes_execution",
        context(
            evidence_value=value,
            material_value=current_material,
        ),
        "pass",
        REASONS.CHECK_PASSED,
    )

    acceptance[
        "accepted_at"
    ] = STARTED_AT

    assert_rule(
        "acceptance.precedes_execution",
        context(
            evidence_value=value,
            material_value=current_material,
        ),
        "unavailable",
        REASONS.AUTHORITATIVE_EXECUTION_TIME_UNAVAILABLE,
    )


def test_parameter_commitment_and_result_scope_fail_closed() -> None:
    value = evidence()
    current_material = material(
        value
    )

    parameter = current_material[
        "parameter_instance"
    ]
    assert parameter is not None

    parameter[
        "payload"
    ] = {
        "tampered": True,
    }

    assert_rule(
        "parameters.commitment_matches",
        context(
            evidence_value=value,
            material_value=current_material,
        ),
        "fail",
        REASONS.PARAMETER_COMMITMENT_MISMATCH,
    )

    assert_rule(
        "result_evidence.scope",
        context(
            result_id=(
                "77777777-7777-4777-"
                "8777-777777777777"
            )
        ),
        "fail",
        REASONS.RESULT_SCOPE_MISMATCH,
    )


def test_job_level_verification_keeps_all_result_rules_not_applicable() -> None:
    current = context(
        result_id=""
    )

    result_rules = tuple(
        item
        for item
        in EXECUTION_VERIFICATION_RULES
        if item.id.startswith(
            "result_evidence."
        )
    )

    assert len(
        result_rules
    ) == 8

    assert all(
        item.evaluate(
            current
        ).status
        == "not_applicable"
        for item in result_rules
    )

    assert all(
        item.evaluate(
            current
        ).reason_code
        == REASONS.NOT_APPLICABLE
        for item in result_rules
    )


def test_large_bounded_schema_set_remains_deterministic() -> None:
    value = evidence()

    standards = value[
        "standards"
    ]
    assert standards is not None

    standards[
        "schemas"
    ] = cast(
        list,
        [
            schema(index)
            for index in range(
                200
            )
        ],
    )
    standards[
        "reference_complete"
    ] = True

    current_material = material(
        value
    )

    current = context(
        evidence_value=value,
        material_value=current_material,
        result_id="",
    )

    assert_rule(
        "standards.schema_references",
        current,
        "pass",
        REASONS.CHECK_PASSED,
    )
    assert_rule(
        "standards.reference_summary",
        current,
        "pass",
        REASONS.CHECK_PASSED,
    )
    assert_rule(
        "standards.references_resolved",
        current,
        "pass",
        REASONS.CHECK_PASSED,
    )