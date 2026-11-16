"""Bounded streaming SHA3-512 verification."""

from collections.abc import AsyncIterable, AsyncIterator, Iterable
from dataclasses import dataclass
from hashlib import sha3_512 as _sha3_512

from .sha3 import BytesLike, DigestVerificationResult, normalize_sha3_512_digest

type ByteChunkSource = Iterable[BytesLike] | AsyncIterable[BytesLike]

_MAX_SAFE_INTEGER = (1 << 53) - 1


@dataclass(frozen=True, slots=True)
class Sha3_512StreamHashResult:
    digest: str
    bytes_hashed: int


@dataclass(frozen=True, slots=True)
class Sha3_512StreamVerificationResult(DigestVerificationResult):
    bytes_hashed: int


def _safe_byte_count(value: object, name: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 <= value <= _MAX_SAFE_INTEGER
    ):
        raise TypeError(f"{name} must be a non-negative safe integer")
    return value


async def _chunks(source: ByteChunkSource) -> AsyncIterator[BytesLike]:
    if isinstance(source, AsyncIterable):
        async for chunk in source:
            yield chunk
        return
    if isinstance(source, Iterable):
        for chunk in source:
            yield chunk
        return
    raise TypeError("SHA3-512 stream source must be iterable")


async def sha3_512_stream(
    source: ByteChunkSource, *, max_bytes: int | None = None
) -> Sha3_512StreamHashResult:
    """Hash exact byte chunks with constant auxiliary memory and a hard byte ceiling."""
    limit = (
        _MAX_SAFE_INTEGER
        if max_bytes is None
        else _safe_byte_count(max_bytes, "max_bytes")
    )
    digest = _sha3_512()
    bytes_hashed = 0
    async for chunk in _chunks(source):
        if not isinstance(chunk, (bytes, bytearray, memoryview)):
            raise TypeError("SHA3-512 stream chunks must be bytes-like")
        chunk_bytes = bytes(chunk)
        if len(chunk_bytes) > limit - bytes_hashed:
            raise ValueError("SHA3-512 stream exceeds max_bytes")
        digest.update(chunk_bytes)
        bytes_hashed += len(chunk_bytes)
    return Sha3_512StreamHashResult(
        digest=digest.hexdigest(),
        bytes_hashed=bytes_hashed,
    )


async def verify_sha3_512_stream(
    *,
    source: ByteChunkSource,
    expected_digest: str,
    expected_bytes: int | None = None,
    max_bytes: int | None = None,
) -> Sha3_512StreamVerificationResult:
    expected = normalize_sha3_512_digest(expected_digest)
    expected_count = (
        None
        if expected_bytes is None
        else _safe_byte_count(expected_bytes, "expected_bytes")
    )
    result = await sha3_512_stream(source, max_bytes=max_bytes)
    if result.digest != expected:
        reason_code = "DIGEST_MISMATCH"
    elif expected_count is not None and result.bytes_hashed != expected_count:
        reason_code = "BYTE_COUNT_MISMATCH"
    else:
        reason_code = None
    return Sha3_512StreamVerificationResult(
        outcome="pass" if reason_code is None else "fail",
        reason_code=reason_code,
        expected_digest=expected,
        computed_digest=result.digest,
        bytes_hashed=result.bytes_hashed,
    )