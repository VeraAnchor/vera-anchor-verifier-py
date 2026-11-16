import json
from dataclasses import replace
from pathlib import Path
from typing import cast

from vera_anchor_verifier.contracts import (
    VerificationFact,
    VerificationFinding,
    VerificationIntent,
    VerificationObservation,
    VerificationReport,
    VerificationSubject,
)
from vera_anchor_verifier.policy.contract_v1 import (
    VERIFICATION_POLICY_SCHEMA_VERSION,
    VerificationPolicyV1,
)
from vera_anchor_verifier.policy.evaluate_v1 import (
    assess_portable_verification_policy_v1,
)
from vera_anchor_verifier.profiles.dataset import (
    verify_dataset_v1_bundle,
    verify_dataset_v1_receipt,
)
from vera_anchor_verifier.profiles.execution.verification_v1 import (
    ExecutionV1Input,
    verify_execution_v1_with_intent,
)
from vera_anchor_verifier.profiles.ingest import (
    verify_ingest_v1_bundle,
    verify_ingest_v1_pair,
    verify_ingest_v1_receipt,
)
from vera_anchor_verifier.reports.core_v1 import (
    compute_verification_core_digest_v1,
)
from vera_anchor_verifier.reports.portable_v1 import (
    PortableVerificationReportV1Input,
    compute_portable_verification_report_digest_v1,
    create_portable_verification_report_v1,
)
from vera_anchor_verifier.reports.validation_v1 import (
    validate_portable_verification_report_v1,
)
from vera_anchor_verifier.standards.hcs.json_canonical_v1 import (
    canonical_hcs_json_v1,
)

TESTS = Path(__file__).parents[1]
FIXTURES = TESTS / "fixtures" / "conformance"
GOLDEN = json.loads(
    (FIXTURES / "js_v02_golden_v1.json").read_text(encoding="utf-8")
)


def load(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def core_report() -> VerificationReport:
    subject = cast(
        VerificationSubject,
        {
            "kind": "dataset",
            "id": "study-1",
            "hedera_network": "testnet",
        },
    )
    intent = cast(
        VerificationIntent,
        {
            "subject": subject,
            "expected": [],
        },
    )
    return VerificationReport(
        intent=intent,
        observations=(
            VerificationObservation(
                id="dataset.bundle",
                subject=subject,
                source="local_computation",
                facts=(
                    VerificationFact(
                        key="item_count",
                        state="available",
                        value=2,
                    ),
                    VerificationFact(
                        key="bundle_digest",
                        state="available",
                        value="a" * 128,
                    ),
                ),
            ),
            VerificationObservation(
                id="dataset.receipt",
                subject=subject,
                source="provided_evidence",
                facts=(
                    VerificationFact(
                        key="receipt_status",
                        state="unavailable",
                        reason_code="RECEIPT_NOT_SUPPLIED",
                    ),
                ),
            ),
        ),
        findings=(
            VerificationFinding(
                check_id="dataset.source_binding",
                outcome="pass",
                reason_code=None,
                observation_ids=("dataset.bundle",),
            ),
            VerificationFinding(
                check_id="dataset.receipt_binding",
                outcome="indeterminate",
                reason_code="RECEIPT_NOT_SUPPLIED",
                observation_ids=("dataset.receipt", "dataset.bundle"),
            ),
        ),
    )


def policy_report() -> VerificationReport:
    source = core_report()
    return replace(
        source,
        findings=(
            VerificationFinding(
                check_id="intent.subject",
                outcome="pass",
                reason_code=None,
                observation_ids=("dataset.bundle",),
            ),
            *source.findings,
        ),
    )


def test_canonical_json_matches_js_v02() -> None:
    vector = GOLDEN["canonical_json"]
    assert canonical_hcs_json_v1(vector["value"], 4096) == vector["expected"]


def test_dataset_matches_frozen_js_v02_fixture() -> None:
    vector = GOLDEN["dataset"]
    fixture = load(FIXTURES / vector["fixture"])

    assert fixture["reference_commit"] == vector["reference_commit"]

    bundle = verify_dataset_v1_bundle(fixture["bundle"])
    receipt = verify_dataset_v1_receipt(fixture["receipt"])
    expected = fixture["computed"]

    assert bundle.ok
    assert receipt.ok
    assert bundle.mismatches == ()
    assert receipt.mismatches == ()
    assert bundle.computed.bundle_digest == expected["bundle_digest"]
    assert bundle.computed.dataset_fingerprint == expected["dataset_fingerprint"]
    assert bundle.computed.merkle_root == expected["merkle_root"]
    assert bundle.computed.idempotency_key == expected["idempotency_key"]


def test_ingest_matches_frozen_js_mainnet_fixture() -> None:
    vector = GOLDEN["ingest"]
    root = TESTS / vector["fixture"]
    bundle = load(root / "bundle.json")
    receipt = load(root / "receipt.json")
    expected = vector["expected"]

    bundle_result = verify_ingest_v1_bundle(bundle)
    receipt_result = verify_ingest_v1_receipt(receipt)
    pair_result = verify_ingest_v1_pair(bundle=bundle, receipt=receipt)

    assert bundle_result.ok
    assert receipt_result.ok
    assert pair_result.ok
    assert bundle_result.mismatches == ()
    assert receipt_result.mismatches == ()
    assert pair_result.mismatches == ()
    assert bundle_result.computed.fingerprint == expected["fingerprint"]
    assert bundle_result.computed.bundle_digest == expected["bundle_digest"]
    assert bundle_result.computed.merkle_root == expected["merkle_root"]


def test_execution_matches_frozen_sage_fixture() -> None:
    vector = GOLDEN["execution"]
    root = TESTS / vector["fixture"]
    evidence = load(root / "standards.json")

    report = verify_execution_v1_with_intent(
        cast(
            ExecutionV1Input,
            {
                "profile": "sage-standards-v1",
                "expected_program": "sage",
                "evidence": evidence,
                "intent": {
                    "subject": {
                        "kind": "execution",
                        "id": vector["job_id"],
                        "hedera_network": "mainnet",
                    },
                    "expected": [],
                },
                "result_id": vector["result_id"],
            },
        )
    )
    findings = {item.check_id: item for item in report.findings}

    for check_id in vector["required_pass"]:
        assert findings[check_id].outcome == "pass"

    assert report.intent["subject"]["id"] == vector["job_id"]
    assert report.verification_scope.profile == "sage-standards-v1"
    assert report.verification_scope.expected_program == "sage"
    assert report.verification_scope.requested_result_id == vector["result_id"]


def test_core_and_portable_report_are_deterministically_bound() -> None:
    source = core_report()
    expected = GOLDEN["core"]["expected_digest"]

    assert compute_verification_core_digest_v1(source) == expected

    input = PortableVerificationReportV1Input(
        kind="verification",
        result=source,
    )
    first = create_portable_verification_report_v1(input)
    second = create_portable_verification_report_v1(input)

    assert first.core_sha3_512 == expected
    assert first.report_sha3_512 == second.report_sha3_512
    assert (
        compute_portable_verification_report_digest_v1(input)
        == first.report_sha3_512
    )
    assert validate_portable_verification_report_v1(first).status == "valid"


def test_saved_report_policy_matches_js_v02_boundary() -> None:
    source = policy_report()
    portable = create_portable_verification_report_v1(
        PortableVerificationReportV1Input(
            kind="verification",
            result=source,
        )
    )
    policy = VerificationPolicyV1(
        schema_version=VERIFICATION_POLICY_SCHEMA_VERSION,
        subject=source.intent["subject"],
        report_kind="verification",
        required_checks=("dataset.source_binding",),
    )

    decision = assess_portable_verification_policy_v1(portable, policy)
    expected = GOLDEN["policy"]["saved_report"]

    assert decision.decision == expected["decision"]
    assert decision.authority == expected["authority"]
    assert decision.reason_codes == tuple(expected["reason_codes"])