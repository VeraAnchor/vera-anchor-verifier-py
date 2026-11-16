"""Ordered deterministic execution verification rules."""

import math
from collections.abc import Callable, Mapping
from typing import cast

from .contract_v1 import (
    ExecutionVerificationContext,
    ExecutionVerificationRequirement,
    ExecutionVerificationRule,
    ExecutionVerificationRuleResult,
    PublicExecutionStandardsEvidence,
    clean_string,
    has_timestamp,
    is_git_commit,
    is_hcs1_ref,
    is_hcs13_ref,
    is_hcs_transaction_id,
    is_hedera_id,
    is_plain_object,
    is_positive_safe_integer,
    is_sha3_512,
    is_sha256,
    is_supported_hedera_network,
    is_uuid,
    is_valid_date,
    normalize_identifier,
    rule_fail,
    rule_not_applicable,
    rule_pass,
    rule_unavailable,
    same_identifier,
)
from .reason_codes_v1 import EXECUTION_VERIFICATION_REASON_CODES as REASONS
from .reason_codes_v1 import ExecutionVerificationReasonCode
from .recomputation_v1 import (
    compute_execution_domain_separated_sha3_512,
    execution_timestamp_iso,
    execution_timestamp_nanos,
    hedera_consensus_timestamp_nanos,
)
from .standards_plan_v1 import build_standards_resolution_plan


def _row(value: object) -> Mapping[str, object]:
    if isinstance(value, Mapping):
        return cast(Mapping[str, object], value)
    return {}


def _field(value: object, key: str) -> object:
    return _row(value).get(key)


def _present(value: object) -> bool:
    return bool(clean_string(value))


def _js_number(value: object) -> float:
    if value is None:
        return 0.0
    if value is True:
        return 1.0
    if value is False:
        return 0.0
    if isinstance(value, (int, float)):
        try:
            return float(value)
        except OverflowError:
            return math.inf if value > 0 else -math.inf
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return 0.0
        try:
            lower = text.lower()
            if lower.startswith("0x"):
                return float(int(text, 16))
            if lower.startswith("0b"):
                return float(int(text, 2))
            if lower.startswith("0o"):
                return float(int(text, 8))
            return float(text)
        except (ValueError, OverflowError):
            return math.nan
    return math.nan


def _valid_source_document(document: object) -> bool:
    return bool(
        _present(_field(document, "standard"))
        and _present(_field(document, "path"))
        and is_sha256(_field(document, "sha256"))
    )


def _valid_agent_reference(agent: object) -> bool:
    hcs11 = _field(agent, "hcs11")
    return bool(
        agent is not None
        and _present(_field(agent, "logical_id"))
        and clean_string(_field(agent, "hcs14_uaid")).startswith("uaid:")
        and is_hedera_id(_field(hcs11, "account_id"))
        and is_hedera_id(_field(hcs11, "profile_registry_topic_id"))
        and is_positive_safe_integer(_field(hcs11, "profile_registry_sequence"))
        and is_hcs1_ref(_field(hcs11, "profile_hcs1_ref"))
        and is_sha256(_field(hcs11, "profile_checksum_sha256"))
    )


def _valid_capability_reference(capability: object) -> bool:
    return bool(
        capability is not None
        and clean_string(_field(capability, "standard")) == "HCS-26"
        and is_hedera_id(_field(capability, "discovery_registry_topic_id"))
        and _present(_field(capability, "skill_uid"))
        and _present(_field(capability, "skill_version"))
        and is_hedera_id(_field(capability, "version_registry_topic_id"))
        and is_positive_safe_integer(_field(capability, "version_sequence_number"))
        and is_hcs1_ref(_field(capability, "manifest_hcs1_ref"))
        and is_sha256(_field(capability, "manifest_checksum_sha256"))
        and _present(_field(capability, "repository_uri"))
        and is_git_commit(_field(capability, "repository_commit"))
    )


def _valid_schema_reference(schema: object) -> bool:
    return bool(
        schema is not None
        and _present(_field(schema, "role"))
        and is_hedera_id(_field(schema, "registry_topic_id"))
        and is_positive_safe_integer(_js_number(_field(schema, "registry_sequence_number")))
        and is_hcs13_ref(_field(schema, "hcs13_ref"))
        and is_sha256(_field(schema, "schema_checksum_sha256"))
        and (
            not _present(_field(schema, "instance_digest_sha3_512"))
            or is_sha3_512(_field(schema, "instance_digest_sha3_512"))
        )
    )


def _reference_complete(evidence: PublicExecutionStandardsEvidence) -> bool:
    standards = _field(evidence, "standards")
    baseline = _field(standards, "baseline")
    documents = _field(baseline, "source_documents")
    schemas = _field(standards, "schemas")
    agents = _field(evidence, "agents")
    return bool(
        baseline is not None
        and _present(_field(baseline, "baseline_id"))
        and is_git_commit(_field(baseline, "source_commit"))
        and isinstance(documents, list)
        and len(documents) > 0
        and all(_valid_source_document(item) for item in documents)
        and _valid_agent_reference(_field(agents, "requester"))
        and _valid_agent_reference(_field(agents, "executor"))
        and _valid_capability_reference(_field(evidence, "capability"))
        and isinstance(schemas, list)
        and len(schemas) > 0
        and all(_valid_schema_reference(item) for item in schemas)
    )


def _expected_resolution_items(
    evidence: PublicExecutionStandardsEvidence,
) -> dict[str, tuple[str, str]] | None:
    expected: dict[str, tuple[str, str]] = {}
    for item in build_standards_resolution_plan(evidence):
        if not item.key or item.key in expected:
            return None
        expected[item.key] = (item.standard, item.reference)
    return expected


def _evaluate_standards_resolution(
    context: ExecutionVerificationContext,
) -> ExecutionVerificationRuleResult:
    material = _field(context.verification_material, "standards_resolution")
    if material is None:
        return rule_unavailable(REASONS.STANDARDS_RESOLUTION_UNAVAILABLE)
    items = _field(material, "items")
    if (
        clean_string(_field(material, "schema_version")) != "vera.standards-resolution.v1"
        or not is_supported_hedera_network(_field(material, "hedera_network"))
        or not isinstance(items, list)
    ):
        return rule_fail(REASONS.MALFORMED_EVIDENCE)
    if (
        context.expected_network
        and normalize_identifier(_field(material, "hedera_network")) != context.expected_network
    ):
        return rule_fail(REASONS.NETWORK_SCOPE_MISMATCH)
    expected = _expected_resolution_items(context.evidence)
    if expected is None:
        return rule_fail(REASONS.MALFORMED_EVIDENCE)
    if len(items) == 0:
        if _field(material, "state") == "unavailable":
            return rule_unavailable(REASONS.STANDARDS_RESOLUTION_UNAVAILABLE)
        return rule_fail(REASONS.MALFORMED_EVIDENCE)
    observed: dict[str, object] = {}
    for item in items:
        key = clean_string(_field(item, "key"))
        if not key or key in observed:
            return rule_fail(REASONS.MALFORMED_EVIDENCE)
        observed[key] = item
    if len(observed) != len(expected):
        return rule_fail(REASONS.REFERENCE_SET_INCOMPLETE)
    has_unavailable = False
    has_failed = False
    for (key, expected_item) in expected.items():
        item = observed.get(key)
        if item is None:
            return rule_fail(REASONS.REFERENCE_SET_INCOMPLETE)
        if (
            clean_string(_field(item, "standard")) != expected_item[0]
            or clean_string(_field(item, "reference")) != expected_item[1]
        ):
            return rule_fail(REASONS.MALFORMED_EVIDENCE)
        state = _field(item, "state")
        if state == "failed":
            has_failed = True
        elif state == "unavailable":
            has_unavailable = True
        elif state != "verified":
            return rule_fail(REASONS.MALFORMED_EVIDENCE)
    derived_state = "failed" if has_failed else "unavailable" if has_unavailable else "verified"
    if _field(material, "state") != derived_state:
        return rule_fail(REASONS.MALFORMED_EVIDENCE)
    if derived_state == "failed":
        return rule_fail(REASONS.MALFORMED_EVIDENCE)
    if derived_state == "unavailable":
        return rule_unavailable(REASONS.STANDARDS_RESOLUTION_UNAVAILABLE)
    return rule_pass()


def _result_applies(context: ExecutionVerificationContext) -> bool:
    return bool(context.requested_result_id)


def _missing_or_malformed_digest(value: object) -> ExecutionVerificationRuleResult | None:
    if not _present(value):
        return rule_unavailable()
    if not is_sha3_512(value):
        return rule_fail(REASONS.MALFORMED_EVIDENCE)
    return None


def _exact_metadata(
    record: object,
    *,
    schema: str,
    canonicalization: str,
    digest_algorithm: str,
    domain_separator: str,
) -> ExecutionVerificationRuleResult:
    if record is None:
        return rule_unavailable()
    required = (
        ("schema", schema),
        ("canonicalization", canonicalization),
        ("digest_algorithm", digest_algorithm),
        ("domain_separator", domain_separator),
    )
    for (field, expected) in required:
        actual = _field(record, field)
        if not _present(actual):
            return rule_unavailable()
        if actual != expected:
            return rule_fail(REASONS.MALFORMED_EVIDENCE)
    digest_state = _missing_or_malformed_digest(_field(record, "digest"))
    return digest_state or rule_pass()


def _js_falsy(value: object) -> bool:
    if value is None or value is False:
        return True
    if isinstance(value, (int, float)) and (not isinstance(value, bool)):
        return value == 0 or (isinstance(value, float) and math.isnan(value))
    return isinstance(value, str) and value == ""


def _recompute_contract_digest(
    record: object,
    *,
    domain_separator: str,
    unavailable_reason: ExecutionVerificationReasonCode,
    mismatch_reason: ExecutionVerificationReasonCode,
) -> ExecutionVerificationRuleResult:
    payload = _field(record, "digest_payload")
    if _js_falsy(payload):
        return rule_unavailable(unavailable_reason)
    if not is_plain_object(payload):
        return rule_fail(REASONS.MALFORMED_EVIDENCE)
    digest = _field(record, "digest")
    digest_state = _missing_or_malformed_digest(digest)
    if digest_state:
        return digest_state
    try:
        computed = compute_execution_domain_separated_sha3_512(domain_separator, payload)
    except (TypeError, ValueError, OverflowError):
        return rule_fail(REASONS.MALFORMED_EVIDENCE)
    if computed == digest:
        return rule_pass()
    return rule_fail(mismatch_reason)


def _dataset_rule(context: ExecutionVerificationContext) -> ExecutionVerificationRuleResult:
    dataset = _field(_field(context.evidence, "execution"), "dataset")
    if dataset is None:
        return rule_not_applicable()
    values = (
        _field(dataset, "dataset_key"),
        _field(dataset, "dataset_version"),
        _field(dataset, "dataset_fingerprint_sha3_512"),
        _field(dataset, "dataset_manifest_sha3_512"),
    )
    if all(value is None or value == "" for value in values):
        return rule_not_applicable()
    if (
        not _present(_field(dataset, "dataset_key"))
        or not is_positive_safe_integer(_field(dataset, "dataset_version"))
        or not is_sha3_512(_field(dataset, "dataset_fingerprint_sha3_512"))
        or not is_sha3_512(_field(dataset, "dataset_manifest_sha3_512"))
    ):
        return rule_fail(REASONS.MALFORMED_EVIDENCE)
    return rule_pass()


def _public_available(context: ExecutionVerificationContext) -> ExecutionVerificationRuleResult:
    if _field(context.evidence, "available") is True:
        return rule_pass()
    return rule_unavailable(REASONS.REQUIRED_EVIDENCE_MISSING)


def _public_contract_version(
    context: ExecutionVerificationContext,
) -> ExecutionVerificationRuleResult:
    version = clean_string(_field(context.evidence, "contract_version"))
    if not version:
        return rule_unavailable()
    if version in context.supported_contract_versions:
        return rule_pass()
    return rule_fail(REASONS.PUBLIC_CONTRACT_UNSUPPORTED)


def _execution_identity(context: ExecutionVerificationContext) -> ExecutionVerificationRuleResult:
    execution = _field(context.evidence, "execution")
    if execution is None:
        return rule_unavailable()
    if (
        not is_uuid(_field(execution, "job_id"))
        or not _present(_field(execution, "program"))
        or not is_valid_date(_field(execution, "proof_date"))
        or not is_supported_hedera_network(_field(execution, "hedera_network"))
    ):
        return rule_fail(REASONS.MALFORMED_EVIDENCE)
    return rule_pass()


def _execution_network(context: ExecutionVerificationContext) -> ExecutionVerificationRuleResult:
    network = normalize_identifier(_field(_field(context.evidence, "execution"), "hedera_network"))
    if not network:
        return rule_unavailable()
    if not is_supported_hedera_network(network):
        return rule_fail(REASONS.MALFORMED_EVIDENCE)
    if context.expected_network and network != context.expected_network:
        return rule_fail(REASONS.NETWORK_SCOPE_MISMATCH)
    return rule_pass()


def _baseline_reference(context: ExecutionVerificationContext) -> ExecutionVerificationRuleResult:
    baseline = _field(_field(context.evidence, "standards"), "baseline")
    if baseline is None:
        return rule_unavailable()
    documents = _field(baseline, "source_documents")
    if (
        not _present(_field(baseline, "baseline_id"))
        or not is_git_commit(_field(baseline, "source_commit"))
        or not isinstance(documents, list)
        or len(documents) == 0
        or not all(_valid_source_document(item) for item in documents)
    ):
        return rule_fail(REASONS.REFERENCE_SET_INCOMPLETE)
    return rule_pass()


def _agent_reference(
    context: ExecutionVerificationContext,
    role: str,
) -> ExecutionVerificationRuleResult:
    agent = _field(_field(context.evidence, "agents"), role)
    if agent is None:
        return rule_unavailable()
    if _valid_agent_reference(agent):
        return rule_pass()
    return rule_fail(REASONS.REFERENCE_SET_INCOMPLETE)


def _requester_reference(context: ExecutionVerificationContext) -> ExecutionVerificationRuleResult:
    return _agent_reference(context, "requester")


def _executor_reference(context: ExecutionVerificationContext) -> ExecutionVerificationRuleResult:
    return _agent_reference(context, "executor")


def _capability_reference(context: ExecutionVerificationContext) -> ExecutionVerificationRuleResult:
    capability = _field(context.evidence, "capability")
    if capability is None:
        return rule_unavailable()
    if _valid_capability_reference(capability):
        return rule_pass()
    return rule_fail(REASONS.REFERENCE_SET_INCOMPLETE)


def _schema_references(context: ExecutionVerificationContext) -> ExecutionVerificationRuleResult:
    schemas = _field(_field(context.evidence, "standards"), "schemas")
    if not isinstance(schemas, list) or len(schemas) == 0:
        return rule_unavailable()
    if all(_valid_schema_reference(item) for item in schemas):
        return rule_pass()
    return rule_fail(REASONS.REFERENCE_SET_INCOMPLETE)


def _reference_summary(context: ExecutionVerificationContext) -> ExecutionVerificationRuleResult:
    reported = _field(_field(context.evidence, "standards"), "reference_complete")
    if not isinstance(reported, bool):
        return rule_unavailable()
    if reported == _reference_complete(context.evidence):
        return rule_pass()
    return rule_fail(REASONS.REFERENCE_SUMMARY_MISMATCH)


def _binding_metadata(context: ExecutionVerificationContext) -> ExecutionVerificationRuleResult:
    binding = _field(context.evidence, "binding")
    result = _exact_metadata(
        binding,
        schema="ExecutionBindingV1",
        canonicalization="RFC8785-JCS",
        digest_algorithm="SHA3-512",
        domain_separator="vera-anchor:execution-binding:v1",
    )
    if result.status != "pass":
        return result
    if has_timestamp(_field(binding, "finalized_at")):
        return rule_pass()
    return rule_unavailable()


def _binding_digest(context: ExecutionVerificationContext) -> ExecutionVerificationRuleResult:
    return _recompute_contract_digest(
        _field(context.evidence, "binding"),
        domain_separator="vera-anchor:execution-binding:v1",
        unavailable_reason=REASONS.BINDING_RECOMPUTATION_UNAVAILABLE,
        mismatch_reason=REASONS.BINDING_DIGEST_MISMATCH,
    )


def _acceptance_metadata(context: ExecutionVerificationContext) -> ExecutionVerificationRuleResult:
    return _exact_metadata(
        _field(context.evidence, "acceptance"),
        schema="ExecutionAcceptanceV1",
        canonicalization="RFC8785-JCS",
        digest_algorithm="SHA3-512",
        domain_separator="vera-anchor:execution-acceptance:v1",
    )


def _acceptance_digest(context: ExecutionVerificationContext) -> ExecutionVerificationRuleResult:
    execution = _field(context.evidence, "execution")
    binding = _field(context.evidence, "binding")
    acceptance = _field(context.evidence, "acceptance")
    if execution is None or binding is None or acceptance is None:
        return rule_unavailable()
    accepted_at = execution_timestamp_iso(_field(acceptance, "accepted_at"))
    requires_hcs = _field(acceptance, "requires_hcs_confirmation")
    if (
        not is_uuid(_field(execution, "job_id"))
        or not is_valid_date(_field(execution, "proof_date"))
        or not is_supported_hedera_network(_field(execution, "hedera_network"))
        or not is_sha3_512(_field(binding, "digest"))
        or not is_sha3_512(_field(acceptance, "digest"))
        or not _present(_field(acceptance, "admission_policy_id"))
        or not isinstance(requires_hcs, bool)
        or not accepted_at
    ):
        return rule_fail(REASONS.MALFORMED_EVIDENCE)
    try:
        computed = compute_execution_domain_separated_sha3_512(
            "vera-anchor:execution-acceptance:v1",
            {
                "record_type": "vera_anchor.execution_acceptance",
                "acceptance_schema": "ExecutionAcceptanceV1",
                "binding_digest_sha3_512": _field(binding, "digest"),
                "job_id": _field(execution, "job_id"),
                "proof_date": _field(execution, "proof_date"),
                "hedera_network": _field(execution, "hedera_network"),
                "admission_policy": {
                    "policy_id": _field(acceptance, "admission_policy_id"),
                    "require_hcs_confirmation_before_execution": requires_hcs,
                },
                "accepted_at": accepted_at,
            },
        )
    except (TypeError, ValueError, OverflowError):
        return rule_fail(REASONS.MALFORMED_EVIDENCE)
    if computed == _field(acceptance, "digest"):
        return rule_pass()
    return rule_fail(REASONS.ACCEPTANCE_RECOMPUTATION_MISMATCH)


def _acceptance_binding(context: ExecutionVerificationContext) -> ExecutionVerificationRuleResult:
    binding_digest = _field(_field(context.evidence, "binding"), "digest")
    acceptance_digest = _field(_field(context.evidence, "acceptance"), "binding_digest")
    state = _missing_or_malformed_digest(binding_digest)
    if state:
        return state
    state = _missing_or_malformed_digest(acceptance_digest)
    if state:
        return state
    if binding_digest == acceptance_digest:
        return rule_pass()
    return rule_fail(REASONS.BINDING_DIGEST_MISMATCH)


def _acceptance_state(context: ExecutionVerificationContext) -> ExecutionVerificationRuleResult:
    acceptance = _field(context.evidence, "acceptance")
    if acceptance is None or not _present(_field(acceptance, "state")):
        return rule_unavailable()
    if _field(acceptance, "state") == "confirmed":
        return rule_pass()
    return rule_fail(REASONS.ACCEPTANCE_NOT_CONFIRMED)


def _acceptance_hcs(context: ExecutionVerificationContext) -> ExecutionVerificationRuleResult:
    acceptance = _field(context.evidence, "acceptance")
    if acceptance is None:
        return rule_unavailable()
    if _field(acceptance, "requires_hcs_confirmation") is not True:
        return rule_not_applicable()
    hcs = _field(acceptance, "hcs")
    if hcs is None:
        return rule_unavailable(REASONS.HCS_CONFIRMATION_REQUIRED)
    if (
        not is_hedera_id(_field(hcs, "topic_id"))
        or not is_hcs_transaction_id(_field(hcs, "transaction_id"))
        or not _present(_field(hcs, "message_id"))
        or not is_positive_safe_integer(_field(hcs, "sequence_number"))
    ):
        return rule_fail(REASONS.HCS_CONFIRMATION_REQUIRED)
    exact = _field(hcs, "consensus_timestamp_exact")
    if not _present(exact):
        return rule_unavailable(REASONS.HCS_CONFIRMATION_REQUIRED)
    if hedera_consensus_timestamp_nanos(exact) is not None:
        return rule_pass()
    return rule_fail(REASONS.MALFORMED_EVIDENCE)


def _acceptance_precedes_execution(
    context: ExecutionVerificationContext,
) -> ExecutionVerificationRuleResult:
    acceptance = _field(context.evidence, "acceptance")
    execution_start = _field(context.verification_material, "execution_start")
    if acceptance is None or execution_start is None:
        return rule_unavailable(REASONS.AUTHORITATIVE_EXECUTION_TIME_UNAVAILABLE)
    if _field(acceptance, "requires_hcs_confirmation") is True:
        acceptance_exact = _field(_field(acceptance, "hcs"), "consensus_timestamp_exact")
        execution_exact = _field(execution_start, "consensus_timestamp_exact")
        if not _present(acceptance_exact):
            return rule_unavailable(REASONS.HCS_CONFIRMATION_REQUIRED)
        if (
            not _present(_field(execution_start, "hcs_transaction_id"))
            or not _present(_field(execution_start, "hcs_topic_id"))
            or not _present(execution_exact)
        ):
            return rule_unavailable(REASONS.AUTHORITATIVE_EXECUTION_TIME_UNAVAILABLE)
        if (
            not is_hcs_transaction_id(_field(execution_start, "hcs_transaction_id"))
            or not is_hedera_id(_field(execution_start, "hcs_topic_id"))
        ):
            return rule_fail(REASONS.MALFORMED_EVIDENCE)
        acceptance_nanos = hedera_consensus_timestamp_nanos(acceptance_exact)
        execution_nanos = hedera_consensus_timestamp_nanos(execution_exact)
        if acceptance_nanos is None or execution_nanos is None:
            return rule_fail(REASONS.MALFORMED_EVIDENCE)
        if acceptance_nanos < execution_nanos:
            return rule_pass()
        return rule_fail(REASONS.ACCEPTANCE_AFTER_EXECUTION_START)
    accepted_nanos = execution_timestamp_nanos(_field(acceptance, "accepted_at"))
    started_nanos = execution_timestamp_nanos(_field(execution_start, "started_at"))
    if accepted_nanos is None:
        return rule_fail(REASONS.MALFORMED_EVIDENCE)
    if started_nanos is None:
        return rule_unavailable(REASONS.AUTHORITATIVE_EXECUTION_TIME_UNAVAILABLE)
    if accepted_nanos == started_nanos:
        return rule_unavailable(REASONS.AUTHORITATIVE_EXECUTION_TIME_UNAVAILABLE)
    if accepted_nanos < started_nanos:
        return rule_pass()
    return rule_fail(REASONS.ACCEPTANCE_AFTER_EXECUTION_START)


def _software_pipeline(context: ExecutionVerificationContext) -> ExecutionVerificationRuleResult:
    release = _field(context.evidence, "software_release")
    pipeline = _field(_field(context.evidence, "execution"), "pipeline_hash")
    if release is None or not _present(pipeline):
        return rule_unavailable()
    if (
        not _present(_field(release, "repository_uri"))
        or not is_git_commit(_field(release, "git_commit"))
        or not is_sha3_512(_field(release, "pipeline_hash_sha3_512"))
        or not is_sha3_512(pipeline)
    ):
        return rule_fail(REASONS.MALFORMED_EVIDENCE)
    if _field(release, "pipeline_hash_sha3_512") == pipeline:
        return rule_pass()
    return rule_fail(REASONS.PIPELINE_HASH_MISMATCH)


def _parameter_commitment(context: ExecutionVerificationContext) -> ExecutionVerificationRuleResult:
    material = _field(context.verification_material, "parameter_instance")
    if material is None:
        return rule_unavailable(REASONS.PARAMETER_COMPARISON_UNAVAILABLE)
    role = clean_string(_field(material, "role"))
    hcs13_ref = clean_string(_field(material, "hcs13_ref"))
    domain = clean_string(_field(material, "domain_separator"))
    schemas = _field(_field(context.evidence, "standards"), "schemas")
    schema: object = None
    if isinstance(schemas, list):
        for candidate in schemas:
            if clean_string(_field(candidate, "role")) == role:
                schema = candidate
                break
    payload = _field(material, "payload")
    if (
        not role
        or not is_hcs13_ref(hcs13_ref)
        or domain != "vera-anchor:hcs13-instance:v1"
        or payload is None
        or schema is None
    ):
        return rule_fail(REASONS.MALFORMED_EVIDENCE)
    expected = _field(schema, "instance_digest_sha3_512")
    if not _present(expected):
        return rule_unavailable(REASONS.PARAMETER_COMPARISON_UNAVAILABLE)
    if not is_sha3_512(expected) or clean_string(_field(schema, "hcs13_ref")) != hcs13_ref:
        return rule_fail(REASONS.MALFORMED_EVIDENCE)
    try:
        computed = compute_execution_domain_separated_sha3_512(
            domain,
            {"role": role, "hcs13_ref": hcs13_ref, "payload": payload},
        )
    except (TypeError, ValueError, OverflowError):
        return rule_fail(REASONS.MALFORMED_EVIDENCE)
    if computed == expected:
        return rule_pass()
    return rule_fail(REASONS.PARAMETER_COMMITMENT_MISMATCH)


def _result_scope(context: ExecutionVerificationContext) -> ExecutionVerificationRuleResult:
    if not _result_applies(context):
        return rule_not_applicable()
    result = _field(context.evidence, "result_evidence")
    if result is None:
        return rule_unavailable()
    actual = clean_string(_field(result, "result_id"))
    if not actual or not is_uuid(actual):
        return rule_fail(REASONS.MALFORMED_EVIDENCE)
    if context.requested_result_id and (not same_identifier(actual, context.requested_result_id)):
        return rule_fail(REASONS.RESULT_SCOPE_MISMATCH)
    return rule_pass()


def _result_metadata(context: ExecutionVerificationContext) -> ExecutionVerificationRuleResult:
    if not _result_applies(context):
        return rule_not_applicable()
    return _exact_metadata(
        _field(context.evidence, "result_evidence"),
        schema="ResultEvidenceV1",
        canonicalization="RFC8785-JCS",
        digest_algorithm="SHA3-512",
        domain_separator="vera-anchor:result-evidence:v1",
    )


def _result_sealed(context: ExecutionVerificationContext) -> ExecutionVerificationRuleResult:
    if not _result_applies(context):
        return rule_not_applicable()
    result = _field(context.evidence, "result_evidence")
    if result is None:
        return rule_unavailable()
    if has_timestamp(_field(result, "sealed_at")):
        return rule_pass()
    return rule_fail(REASONS.RESULT_EVIDENCE_UNSEALED)


def _result_binding(context: ExecutionVerificationContext) -> ExecutionVerificationRuleResult:
    if not _result_applies(context):
        return rule_not_applicable()
    binding_digest = _field(_field(context.evidence, "binding"), "digest")
    result_digest = _field(_field(context.evidence, "result_evidence"), "binding_digest")
    state = _missing_or_malformed_digest(binding_digest)
    if state:
        return state
    state = _missing_or_malformed_digest(result_digest)
    if state:
        return state
    if binding_digest == result_digest:
        return rule_pass()
    return rule_fail(REASONS.BINDING_DIGEST_MISMATCH)


def _result_acceptance(context: ExecutionVerificationContext) -> ExecutionVerificationRuleResult:
    if not _result_applies(context):
        return rule_not_applicable()
    acceptance_digest = _field(_field(context.evidence, "acceptance"), "digest")
    result_digest = _field(_field(context.evidence, "result_evidence"), "acceptance_digest")
    state = _missing_or_malformed_digest(acceptance_digest)
    if state:
        return state
    state = _missing_or_malformed_digest(result_digest)
    if state:
        return state
    if acceptance_digest == result_digest:
        return rule_pass()
    return rule_fail(REASONS.ACCEPTANCE_DIGEST_MISMATCH)


def _result_pipeline(context: ExecutionVerificationContext) -> ExecutionVerificationRuleResult:
    if not _result_applies(context):
        return rule_not_applicable()
    execution_pipeline = _field(_field(context.evidence, "execution"), "pipeline_hash")
    result_pipeline = _field(_field(context.evidence, "result_evidence"), "pipeline_hash")
    if not _present(execution_pipeline) or not _present(result_pipeline):
        return rule_unavailable()
    if not is_sha3_512(execution_pipeline) or not is_sha3_512(result_pipeline):
        return rule_fail(REASONS.MALFORMED_EVIDENCE)
    if execution_pipeline == result_pipeline:
        return rule_pass()
    return rule_fail(REASONS.PIPELINE_HASH_MISMATCH)


def _result_hcs(context: ExecutionVerificationContext) -> ExecutionVerificationRuleResult:
    if not _result_applies(context):
        return rule_not_applicable()
    hcs = _field(_field(context.evidence, "result_evidence"), "hcs")
    if hcs is None:
        return rule_unavailable()
    if (
        is_hcs_transaction_id(_field(hcs, "transaction_id"))
        and is_hedera_id(_field(hcs, "topic_id"))
    ):
        return rule_pass()
    return rule_fail(REASONS.MALFORMED_EVIDENCE)


def _result_digest(context: ExecutionVerificationContext) -> ExecutionVerificationRuleResult:
    if not _result_applies(context):
        return rule_not_applicable()
    return _recompute_contract_digest(
        _field(context.evidence, "result_evidence"),
        domain_separator="vera-anchor:result-evidence:v1",
        unavailable_reason=REASONS.RESULT_EVIDENCE_RECOMPUTATION_UNAVAILABLE,
        mismatch_reason=REASONS.RESULT_EVIDENCE_DIGEST_MISMATCH,
    )


def _rule(
    id: str,
    group: str,
    label: str,
    requirement: ExecutionVerificationRequirement,
    evidence_refs: tuple[str, ...],
    evaluate: Callable[[ExecutionVerificationContext], ExecutionVerificationRuleResult],
) -> ExecutionVerificationRule:
    return ExecutionVerificationRule(
        id=id,
        group=group,
        label=label,
        requirement=requirement,
        evidence_refs=evidence_refs,
        evaluate=evaluate,
    )


EXECUTION_VERIFICATION_RULES = (
    _rule(
        "public_evidence.available",
        "contract",
        "Standards-backed evidence is available",
        "required",
        ("public_standards_evidence",),
        _public_available,
    ),
    _rule(
        "public_evidence.contract_version",
        "contract",
        "Public evidence contract version is supported",
        "required",
        ("public_standards_evidence",),
        _public_contract_version,
    ),
    _rule(
        "execution.identity",
        "execution",
        "Execution identity is structurally valid",
        "required",
        ("execution",),
        _execution_identity,
    ),
    _rule(
        "execution.network_scope",
        "execution",
        "Execution network matches the requested verification scope",
        "required",
        ("execution",),
        _execution_network,
    ),
    _rule(
        "execution.dataset_commitment",
        "execution",
        "Execution dataset commitment is structurally valid",
        "conditional",
        ("execution.dataset",),
        _dataset_rule,
    ),
    _rule(
        "standards.baseline_reference",
        "standards",
        "Frozen standards baseline is complete",
        "required",
        ("standards.baseline",),
        _baseline_reference,
    ),
    _rule(
        "standards.requester_reference",
        "standards",
        "Requester identity references are complete",
        "required",
        ("agents.requester",),
        _requester_reference,
    ),
    _rule(
        "standards.executor_reference",
        "standards",
        "Executor identity references are complete",
        "required",
        ("agents.executor",),
        _executor_reference,
    ),
    _rule(
        "standards.capability_reference",
        "standards",
        "HCS-26 capability reference is complete",
        "required",
        ("capability",),
        _capability_reference,
    ),
    _rule(
        "standards.schema_references",
        "standards",
        "HCS-13 schema references are complete",
        "required",
        ("standards.schemas",),
        _schema_references,
    ),
    _rule(
        "standards.reference_summary",
        "standards",
        "Reference completeness summary matches public evidence",
        "required",
        ("standards",),
        _reference_summary,
    ),
    _rule(
        "standards.references_resolved",
        "standards",
        "Standards references independently resolve",
        "optional",
        (
            "standards.baseline",
            "agents.requester",
            "agents.executor",
            "capability",
            "standards.schemas",
        ),
        _evaluate_standards_resolution,
    ),
    _rule(
        "binding.contract_metadata",
        "binding",
        "Execution binding contract metadata is valid",
        "required",
        ("binding",),
        _binding_metadata,
    ),
    _rule(
        "binding.digest_recomputed",
        "binding",
        "Execution binding digest is recomputed from canonical content",
        "conditional",
        ("binding.digest_payload", "binding.digest"),
        _binding_digest,
    ),
    _rule(
        "acceptance.contract_metadata",
        "acceptance",
        "Execution acceptance contract metadata is valid",
        "required",
        ("acceptance",),
        _acceptance_metadata,
    ),
    _rule(
        "acceptance.digest_recomputed",
        "acceptance",
        "Execution acceptance digest is recomputed from canonical content",
        "required",
        ("execution", "binding", "acceptance"),
        _acceptance_digest,
    ),
    _rule(
        "acceptance.binding_link",
        "acceptance",
        "Acceptance references the finalized execution binding",
        "required",
        ("binding", "acceptance"),
        _acceptance_binding,
    ),
    _rule(
        "acceptance.state_confirmed",
        "acceptance",
        "Pre-execution acceptance is confirmed",
        "required",
        ("acceptance",),
        _acceptance_state,
    ),
    _rule(
        "acceptance.hcs_confirmation",
        "acceptance",
        "Required acceptance HCS confirmation is present",
        "conditional",
        ("acceptance.hcs",),
        _acceptance_hcs,
    ),
    _rule(
        "acceptance.precedes_execution",
        "acceptance",
        "Acceptance precedes authoritative execution time",
        "optional",
        (
            "acceptance",
            "acceptance.hcs",
            "verification_material.execution_start",
        ),
        _acceptance_precedes_execution,
    ),
    _rule(
        "software.pipeline_link",
        "software",
        "Bound software release matches the execution pipeline",
        "required",
        ("software_release", "execution"),
        _software_pipeline,
    ),
    _rule(
        "parameters.commitment_matches",
        "execution",
        "Parameter instance commitment matches execution parameters",
        "optional",
        (
            "standards.schemas",
            "verification_material.parameter_instance",
        ),
        _parameter_commitment,
    ),
    _rule(
        "result_evidence.scope",
        "result",
        "Result evidence identifies the requested result",
        "conditional",
        ("execution", "result_evidence"),
        _result_scope,
    ),
    _rule(
        "result_evidence.contract_metadata",
        "result",
        "Result evidence contract metadata is valid",
        "conditional",
        ("result_evidence",),
        _result_metadata,
    ),
    _rule(
        "result_evidence.sealed",
        "result",
        "Result evidence is sealed",
        "conditional",
        ("result_evidence",),
        _result_sealed,
    ),
    _rule(
        "result_evidence.binding_link",
        "result",
        "Result evidence references the finalized execution binding",
        "conditional",
        ("binding", "result_evidence"),
        _result_binding,
    ),
    _rule(
        "result_evidence.acceptance_link",
        "result",
        "Result evidence references the confirmed acceptance",
        "conditional",
        ("acceptance", "result_evidence"),
        _result_acceptance,
    ),
    _rule(
        "result_evidence.pipeline_link",
        "result",
        "Result evidence references the executed software pipeline",
        "conditional",
        ("execution", "result_evidence"),
        _result_pipeline,
    ),
    _rule(
        "result_evidence.hcs_receipt",
        "result",
        "Result evidence includes an HCS receipt reference",
        "conditional",
        ("result_evidence.hcs",),
        _result_hcs,
    ),
    _rule(
        "result_evidence.digest_recomputed",
        "result",
        "Result evidence digest is recomputed from canonical content",
        "conditional",
        ("result_evidence.digest_payload", "result_evidence.digest"),
        _result_digest,
    ),
)
COMMON_EXECUTION_VERIFICATION_RULES = tuple(
    rule
    for rule in EXECUTION_VERIFICATION_RULES
    if rule.group != "standards"
)