"""Exact-byte SHA3-512 verification primitives."""

import re
from dataclasses import dataclass
from hashlib import sha3_512 as _sha3_512
from typing import Literal

type BytesLike = bytes | bytearray | memoryview

_DIGEST_RE = re.compile(r"^[0-9a-f]{128}$", re.IGNORECASE | re.ASCII)


@dataclass(frozen=True, slots=True)
class DigestVerificationResult:
    outcome: Literal["pass", "fail"]
    reason_code: str | None
    expected_digest: str
    computed_digest: str


def normalize_sha3_512_digest(value: object) -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise TypeError("SHA3-512 digest must contain exactly 128 hex characters")
    return value.lower()


def _exact_bytes(value: object) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise TypeError("SHA3-512 input must be bytes-like")
    return bytes(value)


def sha3_512_hex(data: BytesLike) -> str:
    """Return SHA3-512 over exact bytes with no canonicalization or framing."""
    return _sha3_512(_exact_bytes(data)).hexdigest()


def verify_sha3_512_bytes(
    *, data: BytesLike, expected_digest: str
) -> DigestVerificationResult:
    expected = normalize_sha3_512_digest(expected_digest)
    computed = sha3_512_hex(data)
    matches = computed == expected
    return DigestVerificationResult(
        outcome="pass" if matches else "fail",
        reason_code=None if matches else "DIGEST_MISMATCH",
        expected_digest=expected,
        computed_digest=computed,
    )