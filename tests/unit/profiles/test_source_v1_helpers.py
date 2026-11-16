import asyncio

import pytest

from vera_anchor_verifier import hash_hf_v1
from vera_anchor_verifier.profiles.source_v1_helpers import (
    source_v1_hash_file,
    source_v1_json_material,
    source_v1_media_type,
    source_v1_path,
    source_v1_path_digest,
    source_v1_text_file,
    source_v1_text_material,
)


def run(coro):
    return asyncio.run(coro)


def test_source_paths_are_canonical_and_bounded() -> None:
    assert source_v1_path("a/b.txt", 32) == "a/b.txt"

    for path in (
        "",
        " a.txt",
        "a.txt ",
        "/a.txt",
        r"a\b.txt",
        "C:a.txt",
        "a//b.txt",
        "a/./b.txt",
        "a/../b.txt",
        "a\x00b.txt",
    ):
        with pytest.raises(TypeError):
            source_v1_path(path, 32)


def test_media_and_text_suffixes_match_supported_contract() -> None:
    assert source_v1_media_type("data.json") == "application/json"
    assert source_v1_media_type("image.JPG") == "image/jpeg"
    assert source_v1_media_type("unknown.bin") is None
    assert source_v1_text_file("notes.md")
    assert not source_v1_text_file("blob.bin")


def test_dataset_and_ingest_path_domains_are_distinct() -> None:
    dataset = source_v1_path_digest("a.txt", "dataset")
    ingest = source_v1_path_digest("a.txt", "ingest")

    assert dataset != ingest
    assert len(dataset) == 128
    assert len(ingest) == 128


def test_raw_source_hashing_streams_exact_bytes() -> None:
    result = run(source_v1_hash_file([b"a", b"bc"], 3, False))

    assert result.bytes == 3
    assert len(result.sha3_512) == 128


def test_normalized_text_preserves_source_byte_count() -> None:
    source = b"a\r\nb\rc"
    result = run(source_v1_hash_file([source], len(source), True))

    assert result.bytes == len(source)
    assert result.sha3_512 == hash_hf_v1(
        {
            "domain": "va:ingest:file-text:v1",
            "material": "utf8",
            "text": "a\nb\nc",
        }
    )


def test_normalized_text_enforces_byte_limit() -> None:
    with pytest.raises(ValueError, match="exceeds source byte limit"):
        run(source_v1_hash_file([b"abcd"], 3, True))


def test_json_material_uses_canonical_json_bytes() -> None:
    result = source_v1_json_material({"z": 1, "a": True})

    assert result.bytes == len(b'{"a":true,"z":1}')
    assert result.sha3_512 == hash_hf_v1(
        {
            "domain": "va:ingest:json:v1",
            "material": "raw",
            "bytes": b'{"a":true,"z":1}',
        }
    )


def test_text_material_uses_utf8_byte_length() -> None:
    result = source_v1_text_material("h\u00e9llo")

    assert result.bytes == len("h\u00e9llo".encode())
    assert result.sha3_512 == hash_hf_v1(
        {
            "domain": "va:ingest:text:v1",
            "material": "utf8",
            "text": "h\u00e9llo",
        }
    )