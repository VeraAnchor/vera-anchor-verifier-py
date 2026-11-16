import asyncio
import hashlib
import json
import os
from collections.abc import Mapping
from pathlib import Path
from typing import cast

import pytest

from vera_anchor_verifier.contracts import (
    VerificationFinding,
    VerificationObservation,
    VerificationSubject,
)
from vera_anchor_verifier.policy.contract_v1 import (
    VERIFICATION_POLICY_SCHEMA_VERSION,
    VerificationPolicyV1,
)
from vera_anchor_verifier.policy.evaluate_v1 import triangulate_ingest_with_policy_v1
from vera_anchor_verifier.profiles.ingest import (
    verify_ingest_v1_bundle,
    verify_ingest_v1_pair,
    verify_ingest_v1_receipt,
)
from vera_anchor_verifier.reports.portable_v1 import PortableVerificationReportV1
from vera_anchor_verifier.reports.validation_v1 import (
    validate_portable_verification_report_v1,
)
from vera_anchor_verifier.resolvers.explorer_public_v1 import (
    ExplorerIngestV1Request,
    resolve_explorer_ingest_v1,
)
from vera_anchor_verifier.resolvers.explorer_transport_v1 import (
    ExplorerPublicTransportV1,
)
from vera_anchor_verifier.resolvers.hedera_mirror_v1 import HederaMirrorV1Config
from vera_anchor_verifier.triangulation.public_v1 import PublicTriangulationV1Config
from vera_anchor_verifier.verification.source_intent_v1 import (
    verify_ingest_v1_with_intent,
)

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(
        os.getenv("VA_LIVE_TESTS") != "1",
        reason="set VA_LIVE_TESTS=1 to run live conformance",
    ),
]

OBJECT_KEY = "hf.first-ingest.demo"
ANCHOR_REQUEST_ID = "8c05a623-a217-44de-9f82-70b1190330e6"
ROOT_ANCHOR_ID = "6d76e547-7803-4d6e-9b6c-7e8cf1692caf"
ROOT_ID = "32acf859-0390-4a44-bd40-6798939be87a"
SOURCE_PATH = "vera_anchor_ingest_example.txt"
EXPECTED_BYTES = 71
EXPECTED_SHA3 = (
    "5a296115fa8ef838797d9168ada7d96ed0c824441fa1efd5b330ea37bb0bfa940"
    "0ce60cc437ab7b47b4d91033acde41d2c4294cc7ae6195e7378fd4ba27778d7"
)
EXPECTED_FINGERPRINT = (
    "7b3eb268ac387fa604335f32834349b81c61468e740230025ee652ad65e4280b5"
    "55f47f0d2db74556d95d48bbe26da16c7d8751b0e0f8b373ee33f170c5bb0f5"
)
EXPECTED_BUNDLE_DIGEST = (
    "a80892b2f77853074c8534146c95429a72ff96746e91a1daba73af5ee706f04bc"
    "7a4d93c27badeaf034bec1ccf19562dff0e1e10ee492cc8090c855d7649f542"
)
EXPECTED_ROOT = (
    "af689d911487c83afaa36cc16523790275b4664c94193d1e345e6fc68a5758070"
    "4d278998a89dcfade2b93f3aa4f0f5b884f4e3380395e353b561823df17542c"
)
EXPECTED_ROOT_HASH = (
    "8ce748ed52a162826cfa16b09a94dfe3e5a51aab10764994d64cc9847193ef554"
    "93c77a70b34f25b6ba69a4d7ae876bcc86ec09bc30cdecd1ba71690158d1b64"
)

EXPLORER = "https://explorer.veraanchor.com"
MIRROR = "https://mainnet-public.mirrornode.hedera.com/api/v1"
FIXTURE = (
    Path(__file__).parent
    / "fixtures"
    / "conformance"
    / "ingest"
    / "mainnet"
    / "2026-10-31"
)


def run[T](coro) -> T:
    return asyncio.run(coro)


def load(name: str) -> object:
    return json.loads((FIXTURE / name).read_text(encoding="utf-8-sig"))


def object_map(value: object) -> Mapping[str, object]:
    assert isinstance(value, Mapping)
    return cast(Mapping[str, object], value)


def sample() -> tuple[object, object, dict[str, object], dict[str, object], bytes]:
    bundle = load("bundle.json")
    receipt = load("receipt.json")
    source = (FIXTURE / "source" / SOURCE_PATH).read_bytes()
    material: dict[str, object] = {
        "kind": "file",
        "file": {
            "path_rel": SOURCE_PATH,
            "source": [source],
        },
    }
    intent: dict[str, object] = {
        "subject": {
            "kind": "ingest",
            "id": OBJECT_KEY,
            "hedera_network": "mainnet",
        },
        "expected": [],
    }
    return bundle, receipt, material, intent, source


def config() -> PublicTriangulationV1Config:
    return PublicTriangulationV1Config(
        explorer=ExplorerPublicTransportV1(
            base_url=EXPLORER,
            timeout_ms=15_000,
        ),
        mirror=HederaMirrorV1Config(
            base_urls={"mainnet": MIRROR},
            timeout_ms=15_000,
        ),
    )


def policy() -> VerificationPolicyV1:
    return VerificationPolicyV1(
        schema_version=VERIFICATION_POLICY_SCHEMA_VERSION,
        subject=cast(
            VerificationSubject,
            {
                "kind": "ingest",
                "id": OBJECT_KEY,
                "hedera_network": "mainnet",
            },
        ),
        report_kind="public_triangulation",
        required_checks=(
            "ingest.source_binding",
            "ingest.bundle_consistency",
            "ingest.receipt_binding",
            "intent.subject",
            "intent.declared_network",
            "triangulation.public_record_hedera.message_sha3_512",
        ),
        required_assurance=("mirror_corroboration",),
        on_unresolved="review",
    )


def finding(report, check_id: str) -> VerificationFinding:
    value = next(
        (entry for entry in report.findings if entry.check_id == check_id),
        None,
    )
    assert value is not None, f"missing finding: {check_id}"
    return value


def fact(observation: VerificationObservation | None, key: str) -> object:
    if observation is None:
        return None
    value = next((entry for entry in observation.facts if entry.key == key), None)
    return value.value if value is not None and value.state == "available" else None


def portable_finding(
    report: PortableVerificationReportV1,
    check_id: str,
) -> Mapping[str, object]:
    findings = report.core.get("findings")
    assert isinstance(findings, list)

    for value in findings:
        if isinstance(value, Mapping) and value.get("check_id") == check_id:
            return cast(Mapping[str, object], value)

    raise AssertionError(f"missing portable finding: {check_id}")


def test_live_ingest_fixture_and_local_recomputation() -> None:
    bundle, receipt, material, intent, source = sample()

    bundle_result = verify_ingest_v1_bundle(bundle)
    receipt_result = verify_ingest_v1_receipt(receipt)
    pair_result = verify_ingest_v1_pair(
        bundle=bundle,
        receipt=receipt,
    )

    assert bundle_result.ok, bundle_result.mismatches
    assert receipt_result.ok, receipt_result.mismatches
    assert pair_result.ok, pair_result.mismatches
    assert len(source) == EXPECTED_BYTES
    assert hashlib.sha3_512(source).hexdigest() == EXPECTED_SHA3

    bundle_map = object_map(bundle)
    identity = object_map(bundle_map["identity"])
    merkle = object_map(bundle_map["merkle"])

    receipt_map = object_map(receipt)
    evidence = object_map(receipt_map["evidence"])
    core = object_map(receipt_map["core"])
    receipt_anchor = object_map(core["receipt_anchor"])
    root_anchor = object_map(core["root_anchor"])

    assert identity["object_key"] == OBJECT_KEY
    assert merkle["root"] == EXPECTED_ROOT
    assert evidence["fingerprint"] == EXPECTED_FINGERPRINT
    assert evidence["bundle_digest"] == EXPECTED_BUNDLE_DIGEST
    assert receipt_anchor["id"] == ANCHOR_REQUEST_ID
    assert receipt_anchor["anchor_kind"] == "custom"
    assert receipt_anchor["hedera_network"] == "mainnet"
    assert root_anchor["id"] == ROOT_ANCHOR_ID
    assert root_anchor["root_id"] == ROOT_ID
    assert root_anchor["root_hash"] == EXPECTED_ROOT_HASH

    report = run(
        verify_ingest_v1_with_intent(
            bundle=bundle,
            material=material,
            receipt=receipt,
            intent=intent,
        )
    )

    for check_id in (
        "ingest.source_binding",
        "ingest.bundle_consistency",
        "ingest.receipt_binding",
        "intent.subject",
        "intent.declared_network",
    ):
        assert finding(report, check_id).outcome == "pass"

    assert not [entry for entry in report.findings if entry.outcome == "fail"]


def test_live_ingest_exact_anchor_scope() -> None:
    transport = ExplorerPublicTransportV1(
        base_url=EXPLORER,
        timeout_ms=15_000,
    )
    resolved = run(
        resolve_explorer_ingest_v1(
            transport,
            ExplorerIngestV1Request(
                anchor_request_id=ANCHOR_REQUEST_ID,
                ingest_object_key=OBJECT_KEY,
                network="mainnet",
            ),
        )
    )

    assert resolved.status == "resolved", resolved.reason_code
    assert resolved.publication is not None
    assert resolved.publication.entity_kind == "merkle_anchor"
    assert resolved.publication.entity_id == ANCHOR_REQUEST_ID
    assert fact(resolved.observation, "ingest.object_key") == OBJECT_KEY
    assert fact(resolved.observation, "fingerprint") == EXPECTED_FINGERPRINT
    assert fact(resolved.observation, "bundle_digest") == EXPECTED_BUNDLE_DIGEST
    assert fact(resolved.observation, "ingest.merkle_root") == EXPECTED_ROOT
    assert fact(resolved.observation, "merkle.anchor_request_id") == ANCHOR_REQUEST_ID

    wrong_anchor = run(
        resolve_explorer_ingest_v1(
            transport,
            ExplorerIngestV1Request(
                anchor_request_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                ingest_object_key=OBJECT_KEY,
                network="mainnet",
            ),
        )
    )
    wrong_object = run(
        resolve_explorer_ingest_v1(
            transport,
            ExplorerIngestV1Request(
                anchor_request_id=ANCHOR_REQUEST_ID,
                ingest_object_key="hf.unrelated-ingest.demo",
                network="mainnet",
            ),
        )
    )
    crossed = run(
        resolve_explorer_ingest_v1(
            transport,
            ExplorerIngestV1Request(
                anchor_request_id=ANCHOR_REQUEST_ID,
                ingest_object_key=OBJECT_KEY,
                network="testnet",
            ),
        )
    )

    assert wrong_anchor.status != "resolved"
    assert wrong_object.status != "resolved"
    assert crossed.status != "resolved"


def test_live_ingest_merkle_triangulation_and_policy() -> None:
    bundle, receipt, material, intent, _ = sample()

    workflow = run(
        triangulate_ingest_with_policy_v1(
            config(),
            bundle=bundle,
            material=material,
            receipt=receipt,
            intent=intent,
            anchor_request_id=ANCHOR_REQUEST_ID,
            policy=policy(),
        )
    )

    assert workflow.report.kind == "public_triangulation"
    assert workflow.policy.decision == "allow"
    assert workflow.policy.authority == "sdk_verification"
    assert workflow.report.context["consistency"] == "consistent"
    assert workflow.report.context["resolution"] == {
        "public_record": "resolved",
        "publication_disclosure": "resolved",
        "hedera_mirror": "resolved",
    }
    assert "publication_payload_binding" not in workflow.report.context

    for check_id in (
        "triangulation.provided_public_record.ingest_fingerprint",
        "triangulation.provided_public_record.ingest_bundle_digest",
        "triangulation.public_record_hedera.message_sha3_512",
    ):
        assert portable_finding(workflow.report, check_id)["outcome"] == "pass"

    requirements = {
        requirement.key: requirement
        for requirement in workflow.policy.requirements
    }
    assert requirements["verification.public_evidence"].outcome == "pass"
    assert requirements["assurance.mirror_corroboration"].outcome == "pass"
    assert validate_portable_verification_report_v1(workflow.report).status == "valid"


def test_live_ingest_policy_scope_rejected_before_io() -> None:
    bundle, receipt, material, intent, _ = sample()
    changed = VerificationPolicyV1(
        schema_version=VERIFICATION_POLICY_SCHEMA_VERSION,
        subject=cast(
            VerificationSubject,
            {
                "kind": "ingest",
                "id": OBJECT_KEY,
                "hedera_network": "testnet",
            },
        ),
        report_kind="public_triangulation",
        required_checks=policy().required_checks,
        required_assurance=("mirror_corroboration",),
    )

    async def forbidden(*args, **kwargs):
        del args, kwargs
        raise AssertionError("network I/O must not occur")

    scoped = PublicTriangulationV1Config(
        explorer=ExplorerPublicTransportV1(
            base_url=EXPLORER,
            fetch_impl=forbidden,
        ),
        mirror=HederaMirrorV1Config(
            base_urls={"mainnet": MIRROR},
            fetch_impl=forbidden,
        ),
    )

    with pytest.raises(TypeError, match="policy intent"):
        run(
            triangulate_ingest_with_policy_v1(
                scoped,
                bundle=bundle,
                material=material,
                receipt=receipt,
                intent=intent,
                anchor_request_id=ANCHOR_REQUEST_ID,
                policy=changed,
            )
        )