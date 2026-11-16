import copy
from typing import Any

import pytest

from vera_anchor_verifier import hash_hf_v1
from vera_anchor_verifier.profiles.ingest import (
    verify_ingest_v1_bundle,
    verify_ingest_v1_pair,
    verify_ingest_v1_receipt,
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


def h(domain: str, value: object) -> str:
    return hash_hf_v1({"material": "json", "domain": domain, "value": value})


def item(
    *,
    kind: str = "json",
    content_digest: str = "1" * 128,
    size: int = 3,
    path: str | None = None,
) -> dict[str, Any]:
    leaf: dict[str, Any] = {
        "item_kind": kind,
        "bytes": size,
        "sha3_512": content_digest,
    }
    if path is not None:
        leaf["path_rel"] = path
    leaf_hash = h("va:ingest:leaf:v1", leaf)
    return {**leaf, "leaf_hash": leaf_hash}


def bundle(
    *,
    kind: str = "json",
    items: list[dict[str, Any]] | None = None,
    merkle: bool = False,
) -> dict[str, Any]:
    values = items or [item(kind=kind)]
    result: dict[str, Any] = {
        "bundle_version": "v1",
        "hash_contract": copy.deepcopy(HASH_CONTRACT),
        "identity": {
            "object_key": "object.alpha",
            "object_kind": kind,
            "version_label": "v1",
            "program": "sage",
        },
        "rules": copy.deepcopy(RULES),
        "items": values,
        "summary": {
            "item_count": len(values),
            "total_bytes": sum(value["bytes"] for value in values),
        },
    }
    if merkle:
        level = [value["leaf_hash"] for value in values]
        while len(level) > 1:
            next_level = []
            for index in range(0, len(level), 2):
                left = level[index]
                right = level[index + 1] if index + 1 < len(level) else left
                next_level.append(
                    hash_hf_v1(
                        {
                            "material": "raw",
                            "domain": "va:ingest:node:v1",
                            "bytes": bytes.fromhex(left + right),
                        }
                    )
                )
            level = next_level
        result["merkle"] = {"leaf_count": len(values), "root": level[0]}
    return result


def receipt_for(value: dict[str, Any]) -> dict[str, Any]:
    computed = verify_ingest_v1_bundle(value).computed
    body = {
        "v": "v1",
        "kind": "ingest_receipt",
        "mode": "hash_only",
        "identity": copy.deepcopy(value["identity"]),
        "rules": copy.deepcopy(value["rules"]),
        "evidence": {
            "fingerprint": computed.fingerprint,
            "bundle_digest": computed.bundle_digest,
            "idempotency_key": computed.idempotency_key,
            "item_count": computed.item_count,
            "total_bytes": computed.total_bytes,
        },
    }
    if computed.merkle_root is not None:
        body["evidence"]["merkle_root"] = computed.merkle_root
    return {
        **body,
        "receipt_id": h("va:ingest:receipt:v1", body),
    }


def test_json_bundle_verifies_without_merkle() -> None:
    result = verify_ingest_v1_bundle(bundle())
    assert result.ok
    assert result.mismatches == ()
    assert result.computed.object_kind == "json"
    assert result.computed.merkle_root is None
    assert result.computed.item_count == 1


def test_file_set_bundle_verifies_with_merkle() -> None:
    values = [
        item(kind="file", path="a.txt"),
        item(kind="file", content_digest="2" * 128, path="b.txt"),
    ]
    result = verify_ingest_v1_bundle(
        bundle(kind="file_set", items=values, merkle=True)
    )
    assert result.ok
    assert result.computed.merkle_root is not None
    assert result.computed.item_count == 2


def test_bundle_reports_leaf_summary_and_merkle_mismatches() -> None:
    value = bundle(
        kind="file_set",
        items=[item(kind="file", path="a.txt")],
        merkle=True,
    )
    value["items"][0]["sha3_512"] = "0" * 128
    value["summary"]["item_count"] = 2
    value["summary"]["total_bytes"] = 999
    value["merkle"]["leaf_count"] = 2

    result = verify_ingest_v1_bundle(value)
    assert [m.field for m in result.mismatches] == [
        "items[0].leaf_hash",
        "summary.item_count",
        "summary.total_bytes",
        "merkle.leaf_count",
        "merkle.root",
    ]


@pytest.mark.parametrize(
    ("kind", "items"),
    [
        ("json", [item(kind="text")]),
        ("file_set", [item(kind="json")]),
    ],
)
def test_bundle_rejects_identity_item_kind_conflicts(
    kind: str,
    items: list[dict[str, Any]],
) -> None:
    with pytest.raises(TypeError, match="items.item_kind"):
        verify_ingest_v1_bundle(bundle(kind=kind, items=items))


@pytest.mark.parametrize(
    "path",
    ["/abs.txt", "../x.txt", "a//b.txt", "a/./b.txt", "a..b.txt"],
)
def test_file_paths_fail_closed(path: str) -> None:
    value = bundle(kind="file", items=[item(kind="file", path=path)])
    with pytest.raises(TypeError, match="item.path_rel"):
        verify_ingest_v1_bundle(value)


def test_file_path_backslashes_are_normalized_before_hashing() -> None:
    value = bundle(kind="file", items=[item(kind="file", path="a/b.txt")])
    value["items"][0]["path_rel"] = r"a\b.txt"
    result = verify_ingest_v1_bundle(value)
    assert result.ok


def test_non_file_items_reject_paths() -> None:
    value = bundle()
    value["items"][0]["path_rel"] = "x.json"
    with pytest.raises(TypeError, match="item.path_variant"):
        verify_ingest_v1_bundle(value)


def test_receipt_and_pair_verify() -> None:
    value = bundle()
    receipt = receipt_for(value)

    receipt_result = verify_ingest_v1_receipt(receipt)
    pair_result = verify_ingest_v1_pair(bundle=value, receipt=receipt)

    assert receipt_result.ok
    assert pair_result.ok
    assert pair_result.mismatches == ()


def test_receipt_reports_id_and_idempotency_mismatch() -> None:
    value = receipt_for(bundle())
    value["receipt_id"] = "0" * 128
    value["evidence"]["idempotency_key"] = "1" * 128

    result = verify_ingest_v1_receipt(value)
    assert [m.field for m in result.mismatches] == [
        "receipt_id",
        "evidence.idempotency_key",
    ]


def test_register_and_anchor_requires_anchor_and_allows_network() -> None:
    value = receipt_for(bundle())
    value["mode"] = "register_and_anchor"
    value["hedera_network"] = "mainnet"

    with pytest.raises(TypeError, match="receipt.anchor_required"):
        verify_ingest_v1_receipt(value)

    value["anchor"] = {"domain": "example.org", "proof_date": "2026-11-08"}
    body = {key: item for key, item in value.items() if key != "receipt_id"}
    value["receipt_id"] = h("va:ingest:receipt:v1", body)

    assert verify_ingest_v1_receipt(value).ok


def test_local_modes_reject_hedera_network() -> None:
    value = receipt_for(bundle())
    value["hedera_network"] = "testnet"

    with pytest.raises(TypeError, match="receipt.local_network"):
        verify_ingest_v1_receipt(value)


def test_embedded_core_network_conflicts_are_findings() -> None:
    value = receipt_for(bundle())
    value["mode"] = "register_and_anchor"
    value["hedera_network"] = "mainnet"
    value["anchor"] = {"domain": "example.org", "proof_date": "2026-11-08"}
    value["core"] = {
        "receipt_anchor": {"hedera_network": "testnet"},
        "root_anchor": {"publish": {"hedera_network": "testnet"}},
    }
    body = {key: item for key, item in value.items() if key != "receipt_id"}
    value["receipt_id"] = h("va:ingest:receipt:v1", body)

    result = verify_ingest_v1_receipt(value)
    assert [m.field for m in result.mismatches] == [
        "core.receipt_anchor.hedera_network",
        "core.root_anchor.publish.hedera_network",
    ]


def test_pair_detects_binding_and_rule_conflicts() -> None:
    value = bundle()
    receipt = receipt_for(value)
    receipt["identity"]["object_key"] = "object.other"
    receipt["rules"]["normalize_line_endings"] = True

    body = {key: item for key, item in receipt.items() if key != "receipt_id"}
    receipt["receipt_id"] = h("va:ingest:receipt:v1", body)

    result = verify_ingest_v1_pair(bundle=value, receipt=receipt)
    fields = [m.field for m in result.mismatches]

    assert "binding.object_key" in fields
    assert "binding.idempotency_key" in fields
    assert "binding.rules" in fields


@pytest.mark.parametrize("key", ["__proto__", "prototype", "constructor"])
def test_metadata_rejects_dangerous_keys(key: str) -> None:
    value = receipt_for(bundle())
    value["metadata"] = {key: True}

    with pytest.raises(TypeError, match="json.key"):
        verify_ingest_v1_receipt(value)


def test_metadata_depth_is_bounded() -> None:
    value = receipt_for(bundle())
    nested: object = 0
    for _ in range(10):
        nested = {"next": nested}
    value["metadata"] = nested

    with pytest.raises(TypeError, match="json.limit"):
        verify_ingest_v1_receipt(value)