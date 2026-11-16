import asyncio
import copy
import json
from pathlib import Path
from typing import Any

import pytest

from vera_anchor_verifier import verify_dataset_v1_sources

FIXTURE_PATH = (
    Path(__file__).parents[3]
    / "fixtures"
    / "conformance"
    / "dataset_v1.json"
)
FIXTURE: dict[str, Any] = json.loads(
    FIXTURE_PATH.read_text(encoding="utf-8")
)


def run(coro):
    return asyncio.run(coro)


def bundle() -> dict[str, Any]:
    return copy.deepcopy(FIXTURE["bundle"])


def receipt() -> dict[str, Any]:
    return copy.deepcopy(FIXTURE["receipt"])


def files() -> list[dict[str, Any]]:
    return [
        {"path_rel": "b.txt", "source": [b"data"]},
        {"path_rel": "a.txt", "source": [b"abc"]},
    ]


def test_dataset_source_bytes_reproduce_bundle() -> None:
    result = run(
        verify_dataset_v1_sources(
            bundle=bundle(),
            files=files(),
        )
    )

    assert result.ok
    assert result.mismatches == ()
    assert (
        result.computed.source_merkle_root
        == FIXTURE["computed"]["merkle_root"]
    )
    assert result.computed.source_file_count == 2
    assert result.computed.source_total_bytes == 7


def test_dataset_sources_bind_optional_receipt() -> None:
    result = run(
        verify_dataset_v1_sources(
            bundle=bundle(),
            files=files(),
            receipt=receipt(),
        )
    )

    assert result.ok
    assert result.computed.receipt is not None


def test_dataset_sources_detect_tampered_bytes() -> None:
    tampered = files()
    tampered[1]["source"] = [b"abcd"]

    result = run(
        verify_dataset_v1_sources(
            bundle=bundle(),
            files=tampered,
        )
    )
    fields = {item.field for item in result.mismatches}

    assert not result.ok
    assert "files[0].bytes" in fields
    assert "files[0].sha3_512" in fields
    assert "files[0].leaf_hash" in fields
    assert "sources.total_bytes" in fields
    assert "sources.merkle_root" in fields


def test_dataset_sources_reject_duplicate_paths() -> None:
    provided = [
        {"path_rel": "a.txt", "source": [b"abc"]},
        {"path_rel": "a.txt", "source": [b"data"]},
    ]

    with pytest.raises(TypeError, match="Duplicate Dataset source path"):
        run(
            verify_dataset_v1_sources(
                bundle=bundle(),
                files=provided,
            )
        )


def test_dataset_sources_enforce_total_byte_limit() -> None:
    with pytest.raises(ValueError, match="exceeds max_bytes"):
        run(
            verify_dataset_v1_sources(
                bundle=bundle(),
                files=files(),
                limits={
                    "max_total_bytes": 6,
                    "max_file_bytes": 6,
                },
            )
        )


def test_dataset_receipt_binding_conflict_is_reported() -> None:
    value = receipt()
    value["evidence"]["bundle_digest"] = "0" * 128

    result = run(
        verify_dataset_v1_sources(
            bundle=bundle(),
            files=files(),
            receipt=value,
        )
    )
    fields = {item.field for item in result.mismatches}

    assert not result.ok
    assert "receipt.receipt_id" in fields
    assert "binding.bundle_digest" in fields