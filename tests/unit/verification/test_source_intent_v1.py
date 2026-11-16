import asyncio
import copy
import json
from pathlib import Path
from typing import Any

import pytest

from vera_anchor_verifier import (
    hash_hf_v1,
    verify_dataset_v1_with_intent,
    verify_ingest_v1_with_intent,
)
from vera_anchor_verifier.profiles.source_v1_helpers import (
    source_v1_json_material,
    source_v1_leaf,
)

FIXTURE_PATH = (
    Path(__file__).parents[2]
    / "fixtures"
    / "conformance"
    / "dataset_v1.json"
)
DATASET: dict[str, Any] = json.loads(
    FIXTURE_PATH.read_text(encoding="utf-8")
)

HASH_CONTRACT = {
    "contract_id": "hf-contract-v1",
    "frame": "hf:frame:v1",
    "canonical_json": "hf:canonical-json:v1",
    "algorithm": "sha3-512",
    "encoding": "hex_lower",
}
RULES = {
    "path_normalization": "posix_rel_no_dotdot",
    "follow_symlinks": False,
    "redact_paths": False,
    "normalize_line_endings": False,
    "ordering": "deterministic_sort_v1",
    "merkle_rule": "dup_last_on_odd",
}


def run(coro):
    return asyncio.run(coro)


def dataset_files() -> list[dict[str, Any]]:
    return [
        {"path_rel": "b.txt", "source": [b"data"]},
        {"path_rel": "a.txt", "source": [b"abc"]},
    ]


def dataset_intent() -> dict[str, Any]:
    computed = DATASET["computed"]
    return {
        "subject": {
            "kind": "dataset",
            "id": "dataset.alpha",
        },
        "expected": [
            {
                "key": "bundle_digest",
                "kind": "digest",
                "contract": "hf-contract-v1",
                "material": "json",
                "domain": "va:dataset:bundle:v1",
                "digest": computed["bundle_digest"],
            },
            {
                "key": "dataset_fingerprint",
                "kind": "digest",
                "contract": "hf-contract-v1",
                "material": "json",
                "domain": "va:dataset:fingerprint:v1",
                "digest": computed["dataset_fingerprint"],
            },
            {
                "key": "merkle_root",
                "kind": "merkle-root",
                "tree_alg": "hf-dataset-v1",
                "root_hash": computed["merkle_root"],
                "leaf_count": 2,
            },
        ],
    }


def ingest_bundle(value: object) -> dict[str, Any]:
    material = source_v1_json_material(value)
    item = {
        "item_kind": "json",
        "media_type": "application/json",
        "bytes": material.bytes,
        "sha3_512": material.sha3_512,
    }
    item["leaf_hash"] = source_v1_leaf(
        "ingest",
        item_kind="json",
        media_type="application/json",
        bytes_count=material.bytes,
        sha3_512=material.sha3_512,
    )

    return {
        "bundle_version": "v1",
        "hash_contract": copy.deepcopy(HASH_CONTRACT),
        "identity": {
            "object_key": "object.alpha",
            "object_kind": "json",
        },
        "rules": copy.deepcopy(RULES),
        "items": [item],
        "summary": {
            "item_count": 1,
            "total_bytes": material.bytes,
        },
    }


def finding(report, check_id: str):
    return next(
        item
        for item in report.findings
        if item.check_id == check_id
    )


def test_dataset_intent_passes_bound_expectations() -> None:
    report = run(
        verify_dataset_v1_with_intent(
            bundle=copy.deepcopy(DATASET["bundle"]),
            files=dataset_files(),
            intent=dataset_intent(),
        )
    )

    assert finding(report, "dataset.source_binding").outcome == "pass"
    assert finding(report, "dataset.bundle_consistency").outcome == "pass"
    assert (
        finding(report, "dataset.receipt_binding").outcome
        == "indeterminate"
    )
    assert finding(report, "intent.subject").outcome == "pass"
    assert (
        finding(report, "intent.commitment.bundle_digest").outcome
        == "pass"
    )
    assert (
        finding(report, "intent.commitment.dataset_fingerprint").outcome
        == "pass"
    )
    assert (
        finding(report, "intent.commitment.merkle_root").outcome
        == "pass"
    )

    assert [item.id for item in report.observations] == [
        "dataset.source",
        "dataset.bundle",
    ]


def test_subject_mismatch_is_explicit_failure() -> None:
    intent = dataset_intent()
    intent["subject"]["id"] = "dataset.other"

    report = run(
        verify_dataset_v1_with_intent(
            bundle=copy.deepcopy(DATASET["bundle"]),
            files=dataset_files(),
            intent=intent,
        )
    )

    result = finding(report, "intent.subject")
    assert (result.outcome, result.reason_code) == (
        "fail",
        "SUBJECT_MISMATCH",
    )


def test_source_tampering_makes_expectations_indeterminate() -> None:
    files = dataset_files()
    files[1]["source"] = [b"tampered"]

    report = run(
        verify_dataset_v1_with_intent(
            bundle=copy.deepcopy(DATASET["bundle"]),
            files=files,
            intent=dataset_intent(),
        )
    )

    assert finding(report, "dataset.source_binding").outcome == "fail"
    assert finding(report, "intent.subject").outcome == "indeterminate"

    commitment = finding(
        report,
        "intent.commitment.bundle_digest",
    )
    assert (commitment.outcome, commitment.reason_code) == (
        "indeterminate",
        "SOURCE_BINDING_NOT_ESTABLISHED",
    )


def test_digest_mismatch_and_unsupported_contract_are_distinct() -> None:
    intent = dataset_intent()
    intent["expected"][0]["digest"] = "0" * 128
    intent["expected"][1]["contract"] = "raw-sha3-512"

    report = run(
        verify_dataset_v1_with_intent(
            bundle=copy.deepcopy(DATASET["bundle"]),
            files=dataset_files(),
            intent=intent,
        )
    )

    mismatch = finding(
        report,
        "intent.commitment.bundle_digest",
    )
    unsupported = finding(
        report,
        "intent.commitment.dataset_fingerprint",
    )

    assert (mismatch.outcome, mismatch.reason_code) == (
        "fail",
        "EXPECTED_DIGEST_MISMATCH",
    )
    assert (unsupported.outcome, unsupported.reason_code) == (
        "unsupported",
        "COMMITMENT_CONTRACT_UNSUPPORTED",
    )
    assert unsupported.observation_ids == ()


def test_merkle_contract_and_value_failures_are_distinct() -> None:
    intent = dataset_intent()
    intent["expected"][2]["tree_alg"] = "binary-sorted"

    report = run(
        verify_dataset_v1_with_intent(
            bundle=copy.deepcopy(DATASET["bundle"]),
            files=dataset_files(),
            intent=intent,
        )
    )
    unsupported = finding(
        report,
        "intent.commitment.merkle_root",
    )
    assert unsupported.outcome == "unsupported"

    intent = dataset_intent()
    intent["expected"][2]["root_hash"] = "0" * 128

    report = run(
        verify_dataset_v1_with_intent(
            bundle=copy.deepcopy(DATASET["bundle"]),
            files=dataset_files(),
            intent=intent,
        )
    )
    mismatch = finding(
        report,
        "intent.commitment.merkle_root",
    )
    assert (mismatch.outcome, mismatch.reason_code) == (
        "fail",
        "EXPECTED_MERKLE_MISMATCH",
    )


def test_declared_network_without_receipt_is_indeterminate() -> None:
    intent = dataset_intent()
    intent["subject"]["hedera_network"] = "testnet"

    report = run(
        verify_dataset_v1_with_intent(
            bundle=copy.deepcopy(DATASET["bundle"]),
            files=dataset_files(),
            intent=intent,
        )
    )

    result = finding(report, "intent.declared_network")
    assert (result.outcome, result.reason_code) == (
        "indeterminate",
        "NETWORK_EVIDENCE_UNAVAILABLE",
    )


def test_bound_receipt_can_support_declared_network_claim() -> None:
    receipt = copy.deepcopy(DATASET["receipt"])
    receipt["mode"] = "register_and_anchor"
    receipt["hedera_network"] = "testnet"

    body = {
        key: value
        for key, value in receipt.items()
        if key != "receipt_id"
    }
    receipt["receipt_id"] = hash_hf_v1(
        {
            "material": "json",
            "domain": "va:dataset:receipt:v1",
            "value": body,
        }
    )

    intent = dataset_intent()
    intent["subject"]["hedera_network"] = "testnet"

    report = run(
        verify_dataset_v1_with_intent(
            bundle=copy.deepcopy(DATASET["bundle"]),
            files=dataset_files(),
            receipt=receipt,
            intent=intent,
        )
    )

    assert finding(report, "dataset.receipt_binding").outcome == "pass"
    assert finding(report, "intent.declared_network").outcome == "pass"

    receipt_observation = report.observations[-1]
    assert receipt_observation.source == "provided_evidence"


def test_ingest_intent_binds_source_and_digest() -> None:
    value = {"z": 1, "a": True}
    bundle = ingest_bundle(value)

    from vera_anchor_verifier import verify_ingest_v1_bundle

    computed = verify_ingest_v1_bundle(bundle).computed

    intent = {
        "subject": {
            "kind": "ingest",
            "id": "object.alpha",
        },
        "expected": [
            {
                "key": "fingerprint",
                "kind": "digest",
                "contract": "hf-contract-v1",
                "material": "json",
                "domain": "va:ingest:fingerprint:v1",
                "digest": computed.fingerprint,
            }
        ],
    }

    report = run(
        verify_ingest_v1_with_intent(
            bundle=bundle,
            material={"kind": "json", "value": value},
            intent=intent,
        )
    )

    assert finding(report, "ingest.source_binding").outcome == "pass"
    assert finding(report, "intent.subject").outcome == "pass"
    assert (
        finding(report, "intent.commitment.fingerprint").outcome
        == "pass"
    )


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: value.update(
            {"subject": {"kind": "dataset", "id": " dataset.alpha"}}
        ),
        lambda value: value["subject"].update(
            {"hedera_network": "previewnet"}
        ),
        lambda value: value.update({"expected": [{}]}),
        lambda value: value.update(
            {
                "expected": [
                    {
                        "key": "x",
                        "kind": "digest",
                        "digest": "0" * 128,
                    },
                    {
                        "key": "x",
                        "kind": "digest",
                        "digest": "1" * 128,
                    },
                ]
            }
        ),
    ],
)
def test_invalid_intent_fails_closed(mutate) -> None:
    intent: dict[str, Any] = {
        "subject": {
            "kind": "dataset",
            "id": "dataset.alpha",
        },
        "expected": [],
    }
    mutate(intent)

    with pytest.raises(TypeError):
        run(
            verify_dataset_v1_with_intent(
                bundle=copy.deepcopy(DATASET["bundle"]),
                files=dataset_files(),
                intent=intent,
            )
        )


def test_expectation_count_is_bounded() -> None:
    intent = dataset_intent()
    intent["expected"] = [
        {
            "key": f"x{index}",
            "kind": "digest",
            "digest": "0" * 128,
        }
        for index in range(33)
    ]

    with pytest.raises(
        TypeError,
        match="expectations must be a bounded array",
    ):
        run(
            verify_dataset_v1_with_intent(
                bundle=copy.deepcopy(DATASET["bundle"]),
                files=dataset_files(),
                intent=intent,
            )
        )