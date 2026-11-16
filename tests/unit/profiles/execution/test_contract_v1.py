from dataclasses import replace
from datetime import UTC, datetime

import pytest

from vera_anchor_verifier.profiles.execution.contract_v1 import (
    EXECUTION_VERIFICATION_CHECK_STATUSES,
    EXECUTION_VERIFICATION_REQUIREMENTS,
    EXECUTION_VERIFICATION_SCHEMA_VERSION,
    EXECUTION_VERIFICATION_STATUSES,
    EXECUTION_VERIFIER_VERSION,
    SUPPORTED_PUBLIC_STANDARDS_CONTRACT_VERSIONS,
    ExecutionVerificationReport,
    ExecutionVerificationSubject,
    canonicalize_execution_verification_report,
    clean_string,
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
    make_verification_check,
    normalize_identifier,
    outcome_status,
    same_identifier,
    validate_execution_verification_input_bounds,
    verification_summary,
)
from vera_anchor_verifier.profiles.execution.reason_codes_v1 import (
    EXECUTION_VERIFICATION_REASON_CODES as REASONS,
)


def check(
    id: str,
    requirement,
    status,
):
    return make_verification_check(
        id=id,
        group="unit",
        label=f"Check {id}",
        requirement=requirement,
        status=status,
        reason_code=(
            REASONS.CHECK_PASSED
            if status == "pass"
            else (
                REASONS.NOT_APPLICABLE
                if status == "not_applicable"
                else REASONS.REQUIRED_EVIDENCE_MISSING
            )
        ),
    )


def report_fixture() -> ExecutionVerificationReport:
    checks = (
        make_verification_check(
            id="contract.available",
            group="contract",
            label="Contract evidence is available",
            requirement="required",
            status="pass",
            reason_code=REASONS.CHECK_PASSED,
            evidence_refs=(
                "execution.job_id",
            ),
        ),
    )

    return ExecutionVerificationReport(
        schema_version=(
            EXECUTION_VERIFICATION_SCHEMA_VERSION
        ),
        verifier_version=(
            EXECUTION_VERIFIER_VERSION
        ),
        subject=ExecutionVerificationSubject(
            hedera_network="testnet",
            program="sage",
            job_id=(
                "11111111-1111-4111-8111-"
                "111111111111"
            ),
            result_id=None,
        ),
        status="consistent",
        summary=verification_summary(
            checks
        ),
        checks=checks,
    )


def test_pins_contract_vocabularies() -> None:
    assert (
        EXECUTION_VERIFICATION_SCHEMA_VERSION
        == "vera.execution-verification.v1"
    )
    assert (
        EXECUTION_VERIFIER_VERSION
        == "1.0.0"
    )
    assert (
        SUPPORTED_PUBLIC_STANDARDS_CONTRACT_VERSIONS
        == ("1.0.0",)
    )
    assert EXECUTION_VERIFICATION_STATUSES == (
        "consistent",
        "incomplete",
        "failed",
    )
    assert (
        EXECUTION_VERIFICATION_CHECK_STATUSES
        == (
            "pass",
            "fail",
            "unavailable",
            "not_applicable",
        )
    )
    assert EXECUTION_VERIFICATION_REQUIREMENTS == (
        "required",
        "optional",
        "conditional",
    )


def test_normalizes_and_validates_identifiers() -> None:
    assert clean_string(
        "  Sage  "
    ) == "Sage"
    assert clean_string(
        "   "
    ) == ""
    assert clean_string(
        None
    ) == ""

    assert normalize_identifier(
        "  SAGE "
    ) == "sage"
    assert same_identifier(
        " Result-A ",
        "result-a",
    )
    assert not same_identifier(
        "",
        "",
    )

    assert is_uuid(
        "11111111-1111-4111-8111-111111111111"
    )
    assert not is_uuid(
        "11111111-1111-7111-8111-111111111111"
    )

    assert is_sha3_512(
        "a" * 128
    )
    assert not is_sha3_512(
        "A" * 128
    )
    assert is_sha256(
        "b" * 64
    )
    assert is_git_commit(
        "c" * 40
    )
    assert is_hedera_id(
        "0.0.12345"
    )
    assert is_hcs_transaction_id(
        "0.0.12345@1790923080.123456789"
    )
    assert is_hcs1_ref(
        "hcs://1/0.0.12345/profile.json"
    )
    assert is_hcs13_ref(
        "hcs://13/0.0.4001#31"
    )

    assert is_supported_hedera_network(
        " MAINNET "
    )
    assert not is_supported_hedera_network(
        "previewnet"
    )

    assert is_valid_date(
        "2024-02-29"
    )
    assert not is_valid_date(
        "2025-02-29"
    )

    assert is_positive_safe_integer(
        1
    )
    assert is_positive_safe_integer(
        float(1)
    )
    assert not is_positive_safe_integer(
        True
    )
    assert not is_positive_safe_integer(
        1 << 53
    )

    assert is_plain_object(
        {"a": 1}
    )
    assert not is_plain_object(
        []
    )


def test_enforces_exact_input_resource_boundaries() -> None:
    valid = {
        "available": True,
        "execution": {
            "job_id": (
                "11111111-1111-4111-8111-"
                "111111111111"
            ),
            "created_at": datetime(
                2026,
                10,
                6,
                12,
                tzinfo=UTC,
            ),
        },
        "text": "x" * 8192,
        "values": list(
            range(256)
        ),
    }

    result = (
        validate_execution_verification_input_bounds(
            valid
        )
    )

    assert result.ok is True
    assert (
        result.reason_code
        == REASONS.CHECK_PASSED
    )

    for invalid in (
        None,
        [],
        "evidence",
        1,
        True,
    ):
        result = (
            validate_execution_verification_input_bounds(
                invalid
            )
        )

        assert result.ok is False
        assert (
            result.reason_code
            == REASONS.INPUT_STRUCTURE_INVALID
        )

    for oversized in (
        {
            "value": "x" * 8193,
        },
        {
            "values": list(
                range(257)
            ),
        },
        {
            "k" * 257: "value",
        },
    ):
        result = (
            validate_execution_verification_input_bounds(
                oversized
            )
        )

        assert result.ok is False
        assert (
            result.reason_code
            == REASONS.INPUT_LIMIT_EXCEEDED
        )


def test_rejects_unsupported_graphs_and_excessive_depth() -> None:
    for value in (
        float("nan"),
        float("inf"),
        object(),
        lambda: True,
    ):
        result = (
            validate_execution_verification_input_bounds(
                {
                    "value": value,
                }
            )
        )

        assert result.ok is False
        assert (
            result.reason_code
            == REASONS.INPUT_STRUCTURE_INVALID
        )

    cyclic: dict[str, object] = {}
    cyclic["self"] = cyclic

    result = (
        validate_execution_verification_input_bounds(
            cyclic
        )
    )

    assert result.ok is False
    assert (
        result.reason_code
        == REASONS.INPUT_STRUCTURE_INVALID
    )

    root: dict[str, object] = {}
    cursor = root

    for _ in range(20):
        child: dict[str, object] = {}
        cursor["child"] = child
        cursor = child

    result = (
        validate_execution_verification_input_bounds(
            root
        )
    )

    assert result.ok is False
    assert (
        result.reason_code
        == REASONS.INPUT_LIMIT_EXCEEDED
    )


def test_normalizes_checks_and_applies_outcome_precedence() -> None:
    normalized = make_verification_check(
        id="  execution.network_scope  ",
        group="  execution  ",
        label=(
            "  Execution stays on the "
            "requested network  "
        ),
        requirement="required",
        status="pass",
        reason_code=REASONS.CHECK_PASSED,
        evidence_refs=(
            " execution.hedera_network ",
            "request.network",
            "execution.hedera_network",
            "",
        ),
    )

    assert normalized.id == (
        "execution.network_scope"
    )
    assert normalized.group == "execution"
    assert normalized.label == (
        "Execution stays on the requested network"
    )
    assert normalized.evidence_refs == (
        "execution.hedera_network",
        "request.network",
    )

    assert outcome_status(
        (
            check(
                "required.pass",
                "required",
                "pass",
            ),
            check(
                "conditional.fail",
                "conditional",
                "fail",
            ),
        )
    ) == "failed"

    assert outcome_status(
        (
            check(
                "required.pass",
                "required",
                "pass",
            ),
            check(
                "required.unavailable",
                "required",
                "unavailable",
            ),
        )
    ) == "incomplete"

    assert outcome_status(
        (
            check(
                "required.pass",
                "required",
                "pass",
            ),
            check(
                "optional.fail",
                "optional",
                "fail",
            ),
            check(
                "conditional.na",
                "conditional",
                "not_applicable",
            ),
        )
    ) == "consistent"


def test_counts_all_checks_but_only_outcome_relevant_checks() -> None:
    checks = (
        check(
            "required.pass",
            "required",
            "pass",
        ),
        check(
            "required.unavailable",
            "required",
            "unavailable",
        ),
        check(
            "optional.fail",
            "optional",
            "fail",
        ),
        check(
            "conditional.fail",
            "conditional",
            "fail",
        ),
        check(
            "conditional.na",
            "conditional",
            "not_applicable",
        ),
    )

    summary = verification_summary(
        checks
    )

    assert summary.total == 5
    assert summary.outcome_relevant == 3
    assert summary.passed == 1
    assert summary.failed == 2
    assert summary.unavailable == 1
    assert summary.not_applicable == 1


def test_canonical_report_representation_is_pinned() -> None:
    report = report_fixture()

    assert (
        canonicalize_execution_verification_report(
            report
        )
        == (
            '{"checks":[{"evidence_refs":'
            '["execution.job_id"],'
            '"group":"contract",'
            '"id":"contract.available",'
            '"label":"Contract evidence is available",'
            '"reason_code":"CHECK_PASSED",'
            '"requirement":"required",'
            '"status":"pass"}],'
            '"schema_version":'
            '"vera.execution-verification.v1",'
            '"status":"consistent",'
            '"subject":{"hedera_network":"testnet",'
            '"job_id":"11111111-1111-4111-8111-'
            '111111111111",'
            '"program":"sage","result_id":null},'
            '"summary":{"failed":0,'
            '"not_applicable":0,'
            '"outcome_relevant":1,'
            '"passed":1,"total":1,'
            '"unavailable":0},'
            '"verifier_version":"1.0.0"}'
        )
    )

    malformed = replace(
        report,
        subject=replace(
            report.subject,
            program="\ud800",
        ),
    )

    with pytest.raises(
        TypeError,
        match="Unpaired UTF-16 surrogate",
    ):
        canonicalize_execution_verification_report(
            malformed
        )