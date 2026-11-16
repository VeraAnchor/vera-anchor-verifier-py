import asyncio
import hashlib
import json
import os
from pathlib import Path
from typing import cast

import pytest

from vera_anchor_verifier.contracts import VerificationSubject
from vera_anchor_verifier.policy.contract_v1 import (
    VERIFICATION_POLICY_SCHEMA_VERSION,
    VerificationPolicyV1,
)
from vera_anchor_verifier.policy.evaluate_v1 import triangulate_dataset_with_policy_v1
from vera_anchor_verifier.profiles.dataset import (
    verify_dataset_v1_bundle,
    verify_dataset_v1_receipt,
)
from vera_anchor_verifier.profiles.source_v1_helpers import SourceV1File
from vera_anchor_verifier.reports.validation_v1 import (
    validate_portable_verification_report_v1,
)
from vera_anchor_verifier.resolvers.explorer_public_v1 import (
    ExplorerDatasetV1Request,
    resolve_explorer_dataset_v1,
)
from vera_anchor_verifier.resolvers.explorer_transport_v1 import (
    ExplorerPublicTransportV1,
)
from vera_anchor_verifier.resolvers.hedera_mirror_v1 import HederaMirrorV1Config
from vera_anchor_verifier.triangulation.public_v1 import PublicTriangulationV1Config
from vera_anchor_verifier.verification.source_intent_v1 import (
    verify_dataset_v1_with_intent,
)

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(
        os.getenv("VA_LIVE_TESTS") != "1",
        reason="set VA_LIVE_TESTS=1 to run live conformance",
    ),
]

DATASET_KEY = "07be0cf7-4cab-40ca-aa70-87840df4d3e7.example.verification.demo.v1"
VERSION_ID = "690cddfd-4f4c-434c-8bbe-6b195e59a571"
NETWORK = "mainnet"
PREFIX = "verification_demo"
EXPECTED_BYTES = 32_786
EXPECTED_SHA3 = (
    "04fb07f43cd1d4e89a39090eca8918b584377d4739f4f06888ecf7d1ba0ea27b"
    "f118c3c9d75c5bc6cf09c5cee32a5c20db65b6a4ee756b647ce0b597af761058"
)
EXPECTED_FINGERPRINT = (
    "e751f690339c388e31287c0005301b23379a96880636292ccf83e6d408d8010b"
    "0ff7fc3a45957bb8aa2725194688afa5491df16c957158ae59d4ae1ff0bfecfd"
)
EXPECTED_ROOT = (
    "d9a3fd8af269f1804865d0128826f60af25102660688af45e0dedd621d6c6a087"
    "7a254c7d175c5a407359f92176b3c7666a820834968be7c00671959e0c3e057"
)
EXPLORER = "https://explorer.veraanchor.com"
MIRROR = "https://mainnet-public.mirrornode.hedera.com/api/v1"
FIXTURE = (
    Path(__file__).parent
    / "fixtures"
    / "conformance"
    / "dataset"
    / "mainnet"
    / "2026-10-30"
)


def run[T](coro) -> T:
    return asyncio.run(coro)


def load(name: str) -> object:
    return json.loads((FIXTURE / name).read_text(encoding="utf-8-sig"))


def sample() -> tuple[object, object, list[SourceV1File], object]:
    bundle = load("bundle.json")
    receipt = load("receipt.json")
    files = sorted(path for path in (FIXTURE / "source").rglob("*") if path.is_file())

    assert len(files) == 1
    source = files[0].read_bytes()
    relative = files[0].relative_to(FIXTURE / "source").as_posix()
    path_rel = f"{PREFIX}/{relative}"

    intent = {
        "subject": {
            "kind": "dataset",
            "id": DATASET_KEY,
            "hedera_network": NETWORK,
        },
        "expected": [],
    }
    return (
        bundle,
        receipt,
        [
            cast(
                SourceV1File,
                {
                    "path_rel": path_rel,
                    "source": [source],
                },
            )
        ],
        intent,
    )


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
    subject = cast(
        VerificationSubject,
        {
            "kind": "dataset",
            "id": DATASET_KEY,
            "hedera_network": NETWORK,
        },
    )
    return VerificationPolicyV1(
        schema_version=VERIFICATION_POLICY_SCHEMA_VERSION,
        subject=subject,
        report_kind="public_triangulation",
        required_checks=(
            "dataset.source_binding",
            "dataset.bundle_consistency",
            "dataset.receipt_binding",
            "intent.subject",
            "intent.declared_network",
            "triangulation.public_record_hedera.message_sha3_512",
        ),
        required_assurance=("mirror_corroboration",),
        on_unresolved="review",
    )


def finding(report, check_id: str):
    return next(
        (entry for entry in report.findings if entry.check_id == check_id),
        None,
    )


def test_live_dataset_fixture_and_local_recomputation() -> None:
    bundle, receipt, files, intent = sample()

    bundle_result = verify_dataset_v1_bundle(bundle)
    receipt_result = verify_dataset_v1_receipt(receipt)
    assert bundle_result.ok, bundle_result.mismatches
    assert receipt_result.ok, receipt_result.mismatches

    source = next(iter(files[0]["source"]))
    assert len(source) == EXPECTED_BYTES
    assert hashlib.sha3_512(source).hexdigest() == EXPECTED_SHA3

    report = run(
        verify_dataset_v1_with_intent(
            bundle=bundle,
            files=files,
            receipt=receipt,
            intent=intent,
        )
    )
    for check_id in (
        "dataset.source_binding",
        "dataset.bundle_consistency",
        "dataset.receipt_binding",
        "intent.subject",
        "intent.declared_network",
    ):
        assert finding(report, check_id).outcome == "pass"

    assert not [entry for entry in report.findings if entry.outcome == "fail"]
    assert bundle["dataset_identity"]["dataset_key"] == DATASET_KEY
    assert bundle["merkle"]["root"] == EXPECTED_ROOT
    assert receipt["evidence"]["dataset_fingerprint"] == EXPECTED_FINGERPRINT


def test_live_dataset_exact_explorer_scope() -> None:
    transport = ExplorerPublicTransportV1(
        base_url=EXPLORER,
        timeout_ms=15_000,
    )
    selected = ExplorerDatasetV1Request(
        dataset_key=DATASET_KEY,
        network="mainnet",
    )

    resolved = run(resolve_explorer_dataset_v1(transport, selected))
    assert resolved.status == "resolved", resolved.reason_code
    assert resolved.publication is not None
    assert resolved.publication.entity_kind == "dataset_version"
    assert resolved.publication.entity_id == VERSION_ID

    unrelated = run(
        resolve_explorer_dataset_v1(
            transport,
            ExplorerDatasetV1Request(
                dataset_key=f"{DATASET_KEY}.unrelated",
                network="mainnet",
            ),
        )
    )
    crossed = run(
        resolve_explorer_dataset_v1(
            transport,
            ExplorerDatasetV1Request(
                dataset_key=DATASET_KEY,
                network="testnet",
            ),
        )
    )

    assert unrelated.status != "resolved"
    assert crossed.status != "resolved"


def test_live_dataset_triangulation_and_policy() -> None:
    bundle, receipt, files, intent = sample()

    workflow = run(
        triangulate_dataset_with_policy_v1(
            config(),
            bundle=bundle,
            files=files,
            receipt=receipt,
            intent=intent,
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
    assert (
        next(
            requirement
            for requirement in workflow.policy.requirements
            if requirement.key == "assurance.mirror_corroboration"
        ).outcome
        == "pass"
    )
    assert (
        validate_portable_verification_report_v1(workflow.report).status
        == "valid"
    )


def test_live_dataset_policy_scope_rejected_before_io() -> None:
    bundle, receipt, files, intent = sample()
    changed = VerificationPolicyV1(
        schema_version=VERIFICATION_POLICY_SCHEMA_VERSION,
        subject=cast(
            VerificationSubject,
            {
                "kind": "dataset",
                "id": DATASET_KEY,
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
            triangulate_dataset_with_policy_v1(
                scoped,
                bundle=bundle,
                files=files,
                receipt=receipt,
                intent=intent,
                policy=changed,
            )
        )