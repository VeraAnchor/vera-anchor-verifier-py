import asyncio
import copy
from hashlib import sha3_512
from typing import Any

import pytest

from vera_anchor_verifier import hash_hf_v1, verify_ingest_v1_sources
from vera_anchor_verifier.profiles.source_v1_helpers import (
    source_v1_hash_file,
    source_v1_json_material,
    source_v1_leaf,
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


def json_bundle(value: object) -> dict[str, Any]:
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
            "object_key": "object.json",
            "object_kind": "json",
        },
        "rules": copy.deepcopy(RULES),
        "items": [item],
        "summary": {
            "item_count": 1,
            "total_bytes": material.bytes,
        },
    }


def file_set_bundle() -> dict[str, Any]:
    source = b"a\r\nb\r"
    hashed = run(source_v1_hash_file([source], len(source), True))
    item = {
        "item_kind": "file",
        "path_rel": "a.txt",
        "media_type": "text/plain",
        "bytes": hashed.bytes,
        "sha3_512": hashed.sha3_512,
    }
    item["leaf_hash"] = source_v1_leaf(
        "ingest",
        item_kind="file",
        path_rel="a.txt",
        media_type="text/plain",
        bytes_count=hashed.bytes,
        sha3_512=hashed.sha3_512,
    )

    rules = copy.deepcopy(RULES)
    rules["normalize_line_endings"] = True

    return {
        "bundle_version": "v1",
        "hash_contract": copy.deepcopy(HASH_CONTRACT),
        "identity": {
            "object_key": "object.files",
            "object_kind": "file_set",
        },
        "rules": rules,
        "items": [item],
        "merkle": {
            "leaf_count": 1,
            "root": item["leaf_hash"],
        },
        "summary": {
            "item_count": 1,
            "total_bytes": hashed.bytes,
        },
    }


def receipt_for(value: dict[str, Any]) -> dict[str, Any]:
    from vera_anchor_verifier import verify_ingest_v1_bundle

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
        "receipt_id": hash_hf_v1(
            {
                "material": "json",
                "domain": "va:ingest:receipt:v1",
                "value": body,
            }
        ),
    }


def test_json_source_reproduces_ingest_item() -> None:
    value = {"z": 1, "a": True}
    bundle = json_bundle(value)

    result = run(
        verify_ingest_v1_sources(
            bundle=bundle,
            material={"kind": "json", "value": value},
        )
    )

    assert result.ok
    assert result.mismatches == ()
    assert result.computed.source_item_count == 1


def test_json_source_detects_material_tampering() -> None:
    bundle = json_bundle({"value": 1})

    result = run(
        verify_ingest_v1_sources(
            bundle=bundle,
            material={"kind": "json", "value": {"value": 2}},
        )
    )

    assert not result.ok
    fields = {item.field for item in result.mismatches}
    assert "items[0].sha3_512" in fields
    assert "items[0].leaf_hash" in fields


def test_file_set_normalizes_text_line_endings() -> None:
    bundle = file_set_bundle()

    result = run(
        verify_ingest_v1_sources(
            bundle=bundle,
            material={
                "kind": "file_set",
                "files": [
                    {
                        "path_rel": "a.txt",
                        "source": [b"a\r\nb\r"],
                    }
                ],
            },
        )
    )

    assert result.ok
    assert result.computed.source_total_bytes == 5


def test_source_material_kind_must_match_bundle() -> None:
    bundle = json_bundle({"value": 1})

    with pytest.raises(
        TypeError,
        match="material kind does not match",
    ):
        run(
            verify_ingest_v1_sources(
                bundle=bundle,
                material={
                    "kind": "text",
                    "text": "value",
                },
            )
        )


def test_single_file_requires_basename() -> None:
    source = b"abc"
    digest = sha3_512(source).hexdigest()
    leaf = source_v1_leaf(
        "ingest",
        item_kind="file",
        path_rel="nested/a.txt",
        media_type="text/plain",
        bytes_count=3,
        sha3_512=digest,
    )

    bundle = {
        "bundle_version": "v1",
        "hash_contract": copy.deepcopy(HASH_CONTRACT),
        "identity": {
            "object_key": "object.file",
            "object_kind": "file",
        },
        "rules": copy.deepcopy(RULES),
        "items": [
            {
                "item_kind": "file",
                "path_rel": "nested/a.txt",
                "media_type": "text/plain",
                "bytes": 3,
                "sha3_512": digest,
                "leaf_hash": leaf,
            }
        ],
        "summary": {
            "item_count": 1,
            "total_bytes": 3,
        },
    }

    with pytest.raises(
        TypeError,
        match="must use a basename",
    ):
        run(
            verify_ingest_v1_sources(
                bundle=bundle,
                material={
                    "kind": "file",
                    "file": {
                        "path_rel": "nested/a.txt",
                        "source": [source],
                    },
                },
            )
        )


def test_receipt_merkle_root_is_bound_to_source() -> None:
    bundle = file_set_bundle()
    receipt = receipt_for(bundle)

    result = run(
        verify_ingest_v1_sources(
            bundle=bundle,
            material={
                "kind": "file_set",
                "files": [
                    {
                        "path_rel": "a.txt",
                        "source": [b"a\r\nb\r"],
                    }
                ],
            },
            receipt=receipt,
        )
    )

    assert result.ok
    assert result.computed.receipt is not None