"""Shared bounded source-material verification helpers."""

import posixpath
import re
from collections.abc import AsyncIterable, AsyncIterator, Iterable
from dataclasses import dataclass
from typing import Literal, NotRequired, TypedDict

from ..crypto import ByteChunkSource, sha3_512_stream
from ..hf import (
    MAX_HF_V1_PAYLOAD_BYTES,
    canonicalize_hf_v1_json,
    hash_hf_v1,
)

DEFAULT_SOURCE_V1_MAX_BYTES = 1024 * 1024 * 1024

_DIGEST_RE = re.compile(r"^[0-9a-f]{128}$", re.ASCII)
_DRIVE_RE = re.compile(r"^[a-zA-Z]:", re.ASCII)
_MAX_SAFE_INTEGER = (1 << 53) - 1

_ECMASCRIPT_TRIM = (
    "\u0009\u000b\u000c\u0020\u00a0\u1680"
    "\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a"
    "\u2028\u2029\u202f\u205f\u3000\ufeff\u000a\u000d"
)

_TEXT_SUFFIXES = frozenset(
    {
        ".txt",
        ".text",
        ".csv",
        ".tsv",
        ".fasta",
        ".fa",
        ".fna",
        ".ffn",
        ".faa",
        ".frn",
        ".json",
        ".jsonl",
        ".ndjson",
        ".md",
        ".yaml",
        ".yml",
        ".xml",
        ".html",
        ".htm",
    }
)

_MEDIA_BY_SUFFIX = {
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".webp": "image/webp",
    ".gif": "image/gif",
    ".bmp": "image/bmp",
    ".tif": "image/tiff",
    ".tiff": "image/tiff",
    ".svg": "image/svg+xml",
    ".txt": "text/plain",
    ".text": "text/plain",
    ".csv": "text/csv",
    ".tsv": "text/tab-separated-values",
    ".fasta": "chemical/seq-na-fasta",
    ".fa": "chemical/seq-na-fasta",
    ".fna": "chemical/seq-na-fasta",
    ".ffn": "chemical/seq-na-fasta",
    ".faa": "chemical/seq-aa-fasta",
    ".frn": "chemical/seq-na-fasta",
    ".json": "application/json",
    ".jsonl": "application/x-ndjson",
    ".ndjson": "application/x-ndjson",
    ".md": "text/markdown",
    ".yaml": "application/yaml",
    ".yml": "application/yaml",
    ".xml": "application/xml",
    ".html": "text/html",
    ".htm": "text/html",
}

type SourceProfile = Literal["dataset", "ingest"]


class SourceV1File(TypedDict):
    path_rel: str
    source: ByteChunkSource


class SourceV1Limits(TypedDict):
    max_total_bytes: NotRequired[int]
    max_file_bytes: NotRequired[int]


@dataclass(frozen=True, slots=True)
class SourceV1Mismatch:
    field: str
    expected: object
    actual: object


@dataclass(frozen=True, slots=True)
class SourceV1HashResult:
    bytes: int
    sha3_512: str


def _js_length(value: str) -> int:
    return len(value.encode("utf-16-le", "surrogatepass")) // 2


def _node_utf8_bytes(value: str) -> bytes:
    chars: list[str] = []
    index = 0

    while index < len(value):
        codepoint = ord(value[index])

        if 0xD800 <= codepoint <= 0xDBFF:
            if index + 1 < len(value):
                low = ord(value[index + 1])
                if 0xDC00 <= low <= 0xDFFF:
                    scalar = (
                        0x10000
                        + ((codepoint - 0xD800) << 10)
                        + (low - 0xDC00)
                    )
                    chars.append(chr(scalar))
                    index += 2
                    continue
            chars.append("\ufffd")
        elif 0xDC00 <= codepoint <= 0xDFFF:
            chars.append("\ufffd")
        else:
            chars.append(value[index])

        index += 1

    return "".join(chars).encode()


def source_v1_trim(value: str) -> str:
    return value.strip(_ECMASCRIPT_TRIM)


def source_v1_sort_key(value: str) -> bytes:
    return value.encode("utf-16-be", "surrogatepass")


def _has_control_chars(value: str) -> bool:
    return any(ord(char) <= 31 or ord(char) == 127 for char in value)


def source_v1_path(value: object, max_length: int) -> str:
    if (
        not isinstance(value, str)
        or not value
        or _js_length(value) > max_length
        or _has_control_chars(value)
    ):
        raise TypeError("Source path must be a bounded relative path")

    if (
        source_v1_trim(value) != value
        or "\\" in value
        or value.startswith("/")
        or _DRIVE_RE.match(value)
    ):
        raise TypeError("Source path is not canonical POSIX relative form")

    if any(not segment or segment in {".", ".."} for segment in value.split("/")):
        raise TypeError("Source path contains invalid segments")

    if posixpath.normpath(value) != value:
        raise TypeError("Source path is not normalized")

    return value


def source_v1_media_type(path_rel: str) -> str | None:
    suffix = posixpath.splitext(path_rel)[1].strip().lower()
    return _MEDIA_BY_SUFFIX.get(suffix)


def source_v1_text_file(path_rel: str) -> bool:
    suffix = posixpath.splitext(path_rel)[1].strip().lower()
    return suffix in _TEXT_SUFFIXES


def source_v1_path_digest(path_rel: str, profile: SourceProfile) -> str:
    if profile == "dataset":
        return hash_hf_v1(
            {
                "domain": "va:dataset:path:v1",
                "material": "raw",
                "bytes": _node_utf8_bytes(path_rel),
            }
        )

    return hash_hf_v1(
        {
            "domain": "va:ingest:path:v1",
            "material": "json",
            "value": {"path_rel": path_rel},
        }
    )


def source_v1_leaf(
    profile: SourceProfile,
    *,
    item_kind: str | None = None,
    path_rel: str | None = None,
    path_hash: str | None = None,
    media_type: str | None = None,
    bytes_count: int,
    sha3_512: str,
) -> str:
    value: dict[str, object] = {}

    if profile == "ingest":
        value["item_kind"] = item_kind

    if path_rel:
        value["path_rel"] = path_rel
    if path_hash:
        value["path_hash"] = path_hash
    if media_type:
        value["media_type"] = media_type

    value["bytes"] = bytes_count
    value["sha3_512"] = sha3_512

    return hash_hf_v1(
        {
            "domain": (
                "va:dataset:leaf:v1"
                if profile == "dataset"
                else "va:ingest:leaf:v1"
            ),
            "material": "json",
            "value": value,
        }
    )


def source_v1_root(profile: SourceProfile, leaves: list[str]) -> str:
    if not leaves or any(_DIGEST_RE.fullmatch(leaf) is None for leaf in leaves):
        raise TypeError("Invalid source Merkle leaves")

    level = list(leaves)

    while len(level) > 1:
        next_level: list[str] = []

        for index in range(0, len(level), 2):
            left = level[index]
            right = level[index + 1] if index + 1 < len(level) else left

            next_level.append(
                hash_hf_v1(
                    {
                        "domain": f"va:{profile}:node:v1",
                        "material": "raw",
                        "bytes": bytes.fromhex(left + right),
                    }
                )
            )

        level = next_level

    return level[0]


def source_v1_mismatch(
    field: str,
    expected: object,
    actual: object,
) -> SourceV1Mismatch:
    return SourceV1Mismatch(field, expected, actual)


def source_v1_compare(
    mismatches: list[SourceV1Mismatch],
    field: str,
    expected: object,
    actual: object,
) -> None:
    if expected != actual:
        mismatches.append(source_v1_mismatch(field, expected, actual))


def source_v1_safe_limit(value: object, field: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 0
        or value > _MAX_SAFE_INTEGER
    ):
        raise TypeError(f"{field} must be a non-negative safe integer")

    return value


def source_v1_limits(
    limits: SourceV1Limits | None,
) -> tuple[int, int]:
    source = limits or {}

    total = source_v1_safe_limit(
        source.get("max_total_bytes", DEFAULT_SOURCE_V1_MAX_BYTES),
        "max_total_bytes",
    )
    file = source_v1_safe_limit(
        source.get("max_file_bytes", DEFAULT_SOURCE_V1_MAX_BYTES),
        "max_file_bytes",
    )

    return total, file


async def _chunks(source: ByteChunkSource) -> AsyncIterator[object]:
    if isinstance(source, AsyncIterable):
        async for chunk in source:
            yield chunk
        return

    if isinstance(source, Iterable):
        for chunk in source:
            yield chunk
        return

    raise TypeError("Source must be iterable")


async def source_v1_hash_file(
    source: ByteChunkSource,
    max_bytes: int,
    normalize_text: bool,
) -> SourceV1HashResult:
    if not normalize_text:
        result = await sha3_512_stream(source, max_bytes=max_bytes)
        return SourceV1HashResult(
            bytes=result.bytes_hashed,
            sha3_512=result.digest,
        )

    ceiling = min(max_bytes, MAX_HF_V1_PAYLOAD_BYTES)
    chunks: list[bytes] = []
    bytes_count = 0

    async for chunk in _chunks(source):
        if not isinstance(chunk, (bytes, bytearray, memoryview)):
            raise TypeError("Source chunks must be bytes-like")

        chunk_bytes = bytes(chunk)

        if len(chunk_bytes) > ceiling - bytes_count:
            raise ValueError("Normalized text exceeds source byte limit")

        bytes_count += len(chunk_bytes)
        chunks.append(chunk_bytes)

    normalized = (
        b"".join(chunks)
        .decode("utf-8", errors="replace")
        .replace("\r\n", "\n")
        .replace("\r", "\n")
    )

    return SourceV1HashResult(
        bytes=bytes_count,
        sha3_512=hash_hf_v1(
            {
                "domain": "va:ingest:file-text:v1",
                "material": "utf8",
                "text": normalized,
            }
        ),
    )


def source_v1_json_material(value: object) -> SourceV1HashResult:
    canonical = canonicalize_hf_v1_json(value)

    return SourceV1HashResult(
        bytes=len(canonical),
        sha3_512=hash_hf_v1(
            {
                "domain": "va:ingest:json:v1",
                "material": "raw",
                "bytes": canonical,
            }
        ),
    )


def source_v1_text_material(text: object) -> SourceV1HashResult:
    if not isinstance(text, str):
        raise TypeError("Ingest text material must be a string")

    return SourceV1HashResult(
        bytes=len(_node_utf8_bytes(text)),
        sha3_512=hash_hf_v1(
            {
                "domain": "va:ingest:text:v1",
                "material": "utf8",
                "text": text,
            }
        ),
    )