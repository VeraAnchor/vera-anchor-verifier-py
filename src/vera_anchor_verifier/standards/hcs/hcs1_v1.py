"""Pinned HCS-1 zstd/base64 integrity verification with no network I/O."""

import base64
import binascii
import hashlib
import inspect
import json
import re
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from typing import Literal

MAX_HCS1_V1_FILE_BYTES = 8 * 1024 * 1024
MAX_HCS1_V1_CHUNKS = 4096

_MAX_MESSAGE_BYTES = 1024
_MAX_COMPRESSED_BYTES = MAX_HCS1_V1_CHUNKS * _MAX_MESSAGE_BYTES
_MAX_SAFE_INTEGER = (1 << 53) - 1

_REF_RE = re.compile(r"^hcs://1/(0\.0\.[0-9]+)$", re.ASCII)
_MEMO_RE = re.compile(r"^([0-9a-f]{64}):zstd:base64$", re.ASCII)
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_MIME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9!#$&^_.+\-/]{0,126}$", re.ASCII)
_PREFIX_RE = re.compile(r"^data:([^;]+);base64,", re.ASCII)
_BASE64_RE = re.compile(
    r"^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$",
    re.ASCII,
)

type Hcs1DecompressedBytesV1 = bytes | bytearray | memoryview
type Hcs1ZstdDecompressorV1 = Callable[
    [bytes, int],
    Hcs1DecompressedBytesV1 | Awaitable[Hcs1DecompressedBytesV1],
]


@dataclass(frozen=True, slots=True)
class Hcs1ReferenceV1:
    reference: str
    topic_id: str


@dataclass(frozen=True, slots=True)
class Hcs1V1ContentInput:
    memo: object
    messages: Sequence[bytes | bytearray | memoryview]
    expected_sha256: str | None = None


@dataclass(frozen=True, slots=True)
class Hcs1V1ContentOptions:
    max_file_bytes: int = MAX_HCS1_V1_FILE_BYTES
    decompress_zstd: Hcs1ZstdDecompressorV1 | None = None


@dataclass(frozen=True, slots=True)
class Hcs1V1ContentResult:
    status: Literal["pass", "fail", "unsupported"]
    reason_code: str | None
    sha256: str | None
    mime_type: str | None
    chunk_count: int
    bytes: bytes | None


class _Hcs1Failure(Exception):
    def __init__(self, code: str, *, unsupported: bool = False) -> None:
        super().__init__(code)
        self.code = code
        self.unsupported = unsupported


def parse_hcs1_reference_v1(value: object) -> Hcs1ReferenceV1:
    """Parse the exact pinned HCS-1 topic reference."""
    if not isinstance(value, str):
        raise TypeError("HCS1_REFERENCE_INVALID")
    match = _REF_RE.fullmatch(value)
    if match is None:
        raise TypeError("HCS1_REFERENCE_INVALID")
    return Hcs1ReferenceV1(reference=value, topic_id=match.group(1))


def _failed(
    code: str,
    count: int = 0,
    *,
    unsupported: bool = False,
) -> Hcs1V1ContentResult:
    status: Literal["fail", "unsupported"] = "unsupported" if unsupported else "fail"
    return Hcs1V1ContentResult(
        status=status,
        reason_code=code,
        sha256=None,
        mime_type=None,
        chunk_count=count,
        bytes=None,
    )


def _bound_file_bytes(options: Hcs1V1ContentOptions) -> int:
    value = options.max_file_bytes
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 1
        or value > MAX_HCS1_V1_FILE_BYTES
    ):
        raise TypeError("HCS1_FILE_LIMIT_INVALID")
    return value


def _validated_decompressed_bytes(value: object, limit: int) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise _Hcs1Failure("HCS1_DECOMPRESSION_INVALID")
    result = bytes(value)
    if len(result) > limit:
        raise _Hcs1Failure("HCS1_FILE_TOO_LARGE")
    return result


async def _decompress(
    compressed: bytes,
    limit: int,
    options: Hcs1V1ContentOptions,
) -> bytes:
    adapter = options.decompress_zstd
    if adapter is None:
        raise _Hcs1Failure("HCS1_ZSTD_UNAVAILABLE", unsupported=True)

    try:
        candidate = adapter(compressed, limit)
        if inspect.isawaitable(candidate):
            resolved = await candidate
            return _validated_decompressed_bytes(resolved, limit)
        return _validated_decompressed_bytes(candidate, limit)
    except _Hcs1Failure:
        raise
    except Exception as exc:
        raise _Hcs1Failure("HCS1_DECOMPRESSION_INVALID") from exc


def _safe_order(value: object) -> int | None:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 0
        or value > _MAX_SAFE_INTEGER
    ):
        return None
    return value


def _decode_chunk(message: object) -> tuple[int, str]:
    if not isinstance(message, (bytes, bytearray, memoryview)):
        raise _Hcs1Failure("HCS1_MESSAGE_INVALID")

    raw = bytes(message)
    if not raw or len(raw) > _MAX_MESSAGE_BYTES:
        raise _Hcs1Failure("HCS1_MESSAGE_INVALID")

    try:
        text = raw.decode("utf-8", "strict")
        chunk = json.loads(text)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise _Hcs1Failure("HCS1_CHUNK_INVALID") from exc

    if type(chunk) is not dict or set(chunk) != {"c", "o"}:
        raise _Hcs1Failure("HCS1_CHUNK_INVALID")

    order = _safe_order(chunk.get("o"))
    content = chunk.get("c")
    if order is None or not isinstance(content, str) or not content:
        raise _Hcs1Failure("HCS1_CHUNK_INVALID")
    return order, content


def _decode_base64(encoded: str) -> bytes:
    maximum = (_MAX_COMPRESSED_BYTES * 4 + 2) // 3 + 4
    if (
        not encoded
        or len(encoded) > maximum
        or len(encoded) % 4 != 0
        or _BASE64_RE.fullmatch(encoded) is None
    ):
        raise _Hcs1Failure("HCS1_BASE64_INVALID")

    try:
        decoded = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise _Hcs1Failure("HCS1_BASE64_INVALID") from exc

    canonical = base64.b64encode(decoded).decode("ascii")
    if canonical != encoded or len(decoded) > _MAX_COMPRESSED_BYTES:
        raise _Hcs1Failure("HCS1_BASE64_INVALID")
    return decoded


async def verify_hcs1_content_v1(
    input: Hcs1V1ContentInput,
    options: Hcs1V1ContentOptions | None = None,
) -> Hcs1V1ContentResult:
    """Reconstruct and verify supplied HCS-1 file chunks."""
    checked_options = options if options is not None else Hcs1V1ContentOptions()
    limit = _bound_file_bytes(checked_options)
    messages = input.messages
    count = len(messages) if isinstance(messages, (tuple, list)) else 0

    try:
        memo = _MEMO_RE.fullmatch(input.memo) if isinstance(input.memo, str) else None
        if memo is None:
            raise _Hcs1Failure("HCS1_MEMO_INVALID")

        raw_expected: object = input.expected_sha256
        if raw_expected is None:
            expected: str | None = None
        elif isinstance(raw_expected, str):
            expected = raw_expected.lower()
        else:
            expected = ""

        if expected is not None and _SHA256_RE.fullmatch(expected) is None:
            raise _Hcs1Failure("HCS1_EXPECTED_CHECKSUM_INVALID")
        if (
            not isinstance(messages, (tuple, list))
            or count < 1
            or count > MAX_HCS1_V1_CHUNKS
        ):
            raise _Hcs1Failure("HCS1_CHUNKS_INVALID")

        by_order: dict[int, str] = {}
        for message in messages:
            order, content = _decode_chunk(message)
            if order in by_order:
                raise _Hcs1Failure("HCS1_CHUNK_DUPLICATE")
            by_order[order] = content

        parts: list[str] = []
        for index in range(count):
            part = by_order.get(index)
            if part is None:
                raise _Hcs1Failure("HCS1_CHUNK_GAP")
            parts.append(part)

        prefix = _PREFIX_RE.match(parts[0])
        if prefix is None or _MIME_RE.fullmatch(prefix.group(1)) is None:
            raise _Hcs1Failure("HCS1_PREFIX_INVALID")

        mime_type = prefix.group(1)
        parts[0] = parts[0][prefix.end() :]
        compressed = _decode_base64("".join(parts))
        output = await _decompress(compressed, limit, checked_options)

        if not output:
            raise _Hcs1Failure("HCS1_FILE_TOO_LARGE")

        actual = hashlib.sha256(output).hexdigest()
        if actual != memo.group(1):
            raise _Hcs1Failure("HCS1_CHECKSUM_MISMATCH")
        if expected and actual != expected:
            raise _Hcs1Failure("HCS1_EXPECTED_CHECKSUM_MISMATCH")

        return Hcs1V1ContentResult(
            status="pass",
            reason_code=None,
            sha256=actual,
            mime_type=mime_type,
            chunk_count=count,
            bytes=output,
        )
    except _Hcs1Failure as exc:
        return _failed(exc.code, count, unsupported=exc.unsupported)