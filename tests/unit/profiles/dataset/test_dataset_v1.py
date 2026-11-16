import copy
import json
from pathlib import Path
from typing import Any

import pytest

from vera_anchor_verifier import (
    verify_dataset_v1_bundle,
    verify_dataset_v1_receipt,
)

FIXTURE_PATH = (
    Path(__file__).parents[3]
    / "fixtures"
    / "conformance"
    / "dataset_v1.json"
)
FIXTURE: dict[str, Any] = json.loads(
    FIXTURE_PATH.read_text(encoding="utf-8")
)


def bundle() -> dict[str, Any]:
    return copy.deepcopy(FIXTURE["bundle"])


def receipt() -> dict[str, Any]:
    return copy.deepcopy(FIXTURE["receipt"])


def test_fixture_is_anchored_to_frozen_js_v02() -> None:
    assert FIXTURE["reference_commit"] == (
        "53937fb2177c7340ab0b8e432aea5241fe76231b"
    )


def test_bundle_matches_reference_vector() -> None:
    result = verify_dataset_v1_bundle(bundle())
    expected = FIXTURE["computed"]

    assert result.ok
    assert result.mismatches == ()
    assert result.computed.bundle_digest == expected["bundle_digest"]
    assert (
        result.computed.dataset_fingerprint
        == expected["dataset_fingerprint"]
    )
    assert result.computed.merkle_root == expected["merkle_root"]
    assert result.computed.idempotency_key == expected["idempotency_key"]
    assert result.computed.file_count == 2
    assert result.computed.total_bytes == 7


def test_receipt_matches_reference_vector() -> None:
    result = verify_dataset_v1_receipt(receipt())

    assert result.ok
    assert result.mismatches == ()
    assert result.computed.receipt_id == FIXTURE["receipt"]["receipt_id"]
    assert result.computed.hedera_network is None
    assert (
        result.computed.idempotency_key
        == FIXTURE["computed"]["idempotency_key"]
    )


def test_bundle_reports_leaf_root_and_summary_mismatches() -> None:
    value = bundle()
    value["files"][0]["sha3_512"] = "0" * 128
    value["merkle"]["leaf_count"] = 3
    value["summary"]["file_count"] = 3
    value["summary"]["total_bytes"] = 999

    result = verify_dataset_v1_bundle(value)
    fields = [item.field for item in result.mismatches]

    assert not result.ok
    assert fields == [
        "files[0].leaf_hash",
        "merkle.leaf_count",
        "merkle.root",
        "summary.file_count",
        "summary.total_bytes",
    ]


def test_bundle_rejects_wrong_file_order() -> None:
    value = bundle()
    value["files"].reverse()

    with pytest.raises(TypeError, match="files.path_order"):
        verify_dataset_v1_bundle(value)


def test_bundle_rejects_path_variant_and_redaction_conflicts() -> None:
    value = bundle()
    value["files"][0]["path_hash"] = "0" * 128

    with pytest.raises(TypeError, match="file.path_variant"):
        verify_dataset_v1_bundle(value)

    value = bundle()
    value["rules"]["redact_paths"] = True

    with pytest.raises(TypeError, match="file.redact_paths"):
        verify_dataset_v1_bundle(value)


def test_bundle_rejects_unknown_fields_and_wrong_contract() -> None:
    value = bundle()
    value["unexpected"] = True

    with pytest.raises(TypeError, match="bundle.unexpected"):
        verify_dataset_v1_bundle(value)

    value = bundle()
    value["hash_contract"]["algorithm"] = "sha256"

    with pytest.raises(TypeError, match=r"hash_contract\.algorithm"):
        verify_dataset_v1_bundle(value)


def test_boolean_string_rules_are_normalized_like_js() -> None:
    value = bundle()
    value["rules"]["follow_symlinks"] = "false"
    value["rules"]["redact_paths"] = "false"

    result = verify_dataset_v1_bundle(value)

    assert result.ok
    assert (
        result.computed.bundle_digest
        == FIXTURE["computed"]["bundle_digest"]
    )


def test_receipt_reports_receipt_and_idempotency_mismatches() -> None:
    value = receipt()
    value["receipt_id"] = "0" * 128
    value["evidence"]["idempotency_key"] = "1" * 128

    result = verify_dataset_v1_receipt(value)
    fields = [item.field for item in result.mismatches]

    assert not result.ok
    assert fields == ["receipt_id", "evidence.idempotency_key"]


def test_hash_only_receipt_rejects_network() -> None:
    value = receipt()
    value["hedera_network"] = "testnet"

    with pytest.raises(TypeError, match="hash_only.hedera_network"):
        verify_dataset_v1_receipt(value)


@pytest.mark.parametrize(
    "key",
    ["__proto__", "prototype", "constructor"],
)
def test_receipt_rejects_dangerous_metadata_keys(key: str) -> None:
    value = receipt()
    value["core"] = {key: {"value": 1}}

    with pytest.raises(TypeError, match="receipt.metadata_key"):
        verify_dataset_v1_receipt(value)


def test_receipt_metadata_limits_are_bounded() -> None:
    value = receipt()
    nested: object = 0
    for _ in range(18):
        nested = {"next": nested}
    value["core"] = nested

    with pytest.raises(TypeError, match="receipt.metadata_limit"):
        verify_dataset_v1_receipt(value)


def test_safe_integer_counts_accept_integral_float_semantics() -> None:
    value = bundle()
    value["summary"]["file_count"] = 2.0
    value["summary"]["total_bytes"] = 7.0
    value["merkle"]["leaf_count"] = 2.0

    result = verify_dataset_v1_bundle(value)

    assert result.ok


@pytest.mark.parametrize(
    "value",
    [-1, True, 1 << 53],
)
def test_counts_fail_closed_outside_js_safe_integer_range(
    value: object,
) -> None:
    candidate = bundle()
    candidate["summary"]["file_count"] = value

    with pytest.raises(TypeError, match="summary.file_count"):
        verify_dataset_v1_bundle(candidate)