import json
from pathlib import Path
from typing import Any

import pytest

from vera_anchor_verifier import (
    HF_V1_CONTRACT_ID,
    MAX_HF_V1_PAYLOAD_BYTES,
    HfV1BigInt,
    canonicalize_hf_v1_json,
    frame_hf_v1,
    hash_hf_v1,
    normalize_hf_v1_domain,
    verify_hf_v1_digest,
)

FIXTURE_PATH = (
    Path(__file__).parents[2] / "fixtures" / "conformance" / "hf_v1.json"
)
FIXTURE = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
VECTORS = FIXTURE["vectors"]


def decode_value(value: Any) -> Any:
    if isinstance(value, list):
        return [decode_value(item) for item in value]
    if isinstance(value, dict):
        if set(value) == {"$hf_bigint"}:
            return HfV1BigInt(int(value["$hf_bigint"]))
        return {key: decode_value(item) for key, item in value.items()}
    return value


def material_for(vector: dict[str, Any]) -> dict[str, Any]:
    material = vector["material"]
    if material == "raw":
        return {
            "material": "raw",
            "bytes": bytes.fromhex(vector["input_hex"]),
        }
    if material == "utf8":
        return {
            "material": "utf8",
            "text": vector["text"],
        }
    return {
        "material": "json",
        "value": decode_value(vector["value"]),
    }


def payload_for(
    vector: dict[str, Any],
    material: dict[str, Any],
) -> bytes:
    if vector["material"] == "raw":
        return material["bytes"]
    if vector["material"] == "utf8":
        return vector["text"].encode()
    return canonicalize_hf_v1_json(material["value"])


def test_fixture_is_anchored_to_frozen_js_v02() -> None:
    assert FIXTURE["schema"] == "vera-anchor-hf-v1-conformance@1"
    assert FIXTURE["reference"]["repository"] == (
        "VeraAnchor/vera-anchor-verifier"
    )
    assert FIXTURE["reference"]["commit"] == (
        "53937fb2177c7340ab0b8e432aea5241fe76231b"
    )
    assert FIXTURE["reference"]["source"] == "src/hf/hashContractV1.ts"


@pytest.mark.parametrize("vector", VECTORS, ids=lambda item: item["id"])
def test_hf_v1_matches_js_conformance_vectors(
    vector: dict[str, Any],
) -> None:
    material = material_for(vector)
    payload = payload_for(vector, material)
    assert payload.hex() == vector["payload_hex"]

    framed = frame_hf_v1(vector["domain"], payload)
    assert framed.hex() == vector["frame_hex"]

    hash_input = dict(material)
    hash_input["domain"] = vector["domain"]
    assert hash_hf_v1(hash_input) == vector["digest"]

    expected = {
        "kind": "digest",
        "contract": HF_V1_CONTRACT_ID,
        "material": vector["material"],
        "domain": vector["domain"],
        "digest": vector["digest"],
    }
    result = verify_hf_v1_digest(
        expected=expected,
        evidence=material,
    )
    assert result.outcome == "pass"
    assert result.reason_code is None
    assert result.expected_digest == vector["digest"]
    assert result.computed_digest == vector["digest"]


def test_domain_normalization_matches_js_trim_behavior() -> None:
    assert (
        normalize_hf_v1_domain("\u00a0dataset.content\ufeff")
        == "dataset.content"
    )


@pytest.mark.parametrize(
    "domain",
    [
        "",
        "Dataset.content",
        "has space",
        "a" * 65,
    ],
)
def test_invalid_domains_fail_closed(domain: str) -> None:
    with pytest.raises(TypeError, match="Invalid HF v1 domain"):
        normalize_hf_v1_domain(domain)

    with pytest.raises(TypeError, match="must be a string"):
        normalize_hf_v1_domain(None)


@pytest.mark.parametrize(
    "value",
    [
        float("nan"),
        float("inf"),
        float("-inf"),
        1 << 53,
    ],
)
def test_nonportable_numbers_are_rejected(value: object) -> None:
    with pytest.raises(TypeError):
        canonicalize_hf_v1_json(value)


def test_bigint_requires_explicit_python_wrapper() -> None:
    value = HfV1BigInt(9007199254740993)
    assert canonicalize_hf_v1_json(value) == b'"9007199254740993"'

    with pytest.raises(TypeError, match="must be an integer"):
        HfV1BigInt(True)


@pytest.mark.parametrize(
    "value",
    [
        b"bytes",
        (1, 2),
        {1, 2},
    ],
)
def test_json_rejects_non_json_container_types(value: object) -> None:
    with pytest.raises(
        TypeError,
        match="only plain objects, arrays and scalar values",
    ):
        canonicalize_hf_v1_json(value)


def test_json_rejects_non_string_object_keys() -> None:
    with pytest.raises(TypeError, match="object keys must be strings"):
        canonicalize_hf_v1_json({1: "value"})


def test_json_rejects_repeated_and_circular_references() -> None:
    shared = {"value": 1}
    with pytest.raises(TypeError, match="repeated or circular"):
        canonicalize_hf_v1_json({"a": shared, "b": shared})

    circular: list[object] = []
    circular.append(circular)
    with pytest.raises(TypeError, match="repeated or circular"):
        canonicalize_hf_v1_json(circular)


def test_json_enforces_depth_and_array_limits() -> None:
    nested: object = 0
    for _ in range(65):
        nested = [nested]

    with pytest.raises(TypeError, match="nesting limit exceeded"):
        canonicalize_hf_v1_json(nested)

    oversized = [None] * 200_001
    with pytest.raises(ValueError, match="array exceeds SDK limit"):
        canonicalize_hf_v1_json(oversized)


def test_frame_enforces_payload_limit_and_bytes_type() -> None:
    oversized = b"x" * (MAX_HF_V1_PAYLOAD_BYTES + 1)
    with pytest.raises(ValueError, match="payload exceeds SDK byte limit"):
        frame_hf_v1("dataset.content", oversized)

    with pytest.raises(TypeError, match="payload must be bytes"):
        frame_hf_v1("dataset.content", "not-bytes")  # type: ignore[arg-type]


def test_material_mismatch_does_not_compute_digest() -> None:
    expected = {
        "kind": "digest",
        "contract": HF_V1_CONTRACT_ID,
        "material": "raw",
        "domain": "dataset.content",
        "digest": VECTORS[0]["digest"],
    }
    result = verify_hf_v1_digest(
        expected=expected,
        evidence={"material": "utf8", "text": "abc"},
    )
    assert result.outcome == "fail"
    assert result.reason_code == "HF_MATERIAL_MISMATCH"
    assert result.computed_digest is None


def test_digest_mismatch_reports_computed_digest() -> None:
    expected = {
        "kind": "digest",
        "contract": HF_V1_CONTRACT_ID,
        "material": "raw",
        "domain": "dataset.content",
        "digest": "0" * 128,
    }
    result = verify_hf_v1_digest(
        expected=expected,
        evidence={"material": "raw", "bytes": b"abc"},
    )
    assert result.outcome == "fail"
    assert result.reason_code == "DIGEST_MISMATCH"
    assert result.computed_digest == VECTORS[0]["digest"]


def test_verifier_rejects_wrong_commitment_contract() -> None:
    with pytest.raises(
        TypeError,
        match="Expected an hf-contract-v1 digest commitment",
    ):
        verify_hf_v1_digest(
            expected={
                "kind": "digest",
                "contract": "other",
                "material": "raw",
                "domain": "dataset.content",
                "digest": "0" * 128,
            },
            evidence={"material": "raw", "bytes": b"abc"},
        )