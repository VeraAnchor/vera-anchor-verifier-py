from dataclasses import FrozenInstanceError

import pytest

from vera_anchor_verifier import (
    normalize_sha3_512_digest,
    sha3_512_hex,
    verify_sha3_512_bytes,
)

EMPTY_SHA3_512 = (
    "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6"
    "15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
)
ABC_SHA3_512 = (
    "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e1"
    "0e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"
)


def test_sha3_512_known_vectors_and_bytes_like_inputs() -> None:
    assert sha3_512_hex(b"") == EMPTY_SHA3_512
    assert sha3_512_hex(b"abc") == ABC_SHA3_512
    assert sha3_512_hex(bytearray(b"abc")) == ABC_SHA3_512
    assert sha3_512_hex(memoryview(b"abc")) == ABC_SHA3_512


def test_normalize_digest_is_strict_and_lowercases() -> None:
    assert normalize_sha3_512_digest(ABC_SHA3_512.upper()) == ABC_SHA3_512
    for value in (None, b"a" * 128, "0" * 127, "0" * 129, "g" * 128):
        with pytest.raises(TypeError, match="exactly 128 hex characters"):
            normalize_sha3_512_digest(value)


def test_sha3_rejects_non_bytes_like_input() -> None:
    with pytest.raises(TypeError, match="must be bytes-like"):
        sha3_512_hex("abc")  # type: ignore[arg-type]


def test_verify_sha3_pass_and_fail_are_deterministic_and_immutable() -> None:
    passed = verify_sha3_512_bytes(
        data=b"abc",
        expected_digest=ABC_SHA3_512.upper(),
    )
    assert (passed.outcome, passed.reason_code) == ("pass", None)
    assert passed.expected_digest == ABC_SHA3_512
    assert passed.computed_digest == ABC_SHA3_512

    failed = verify_sha3_512_bytes(data=b"abc", expected_digest=EMPTY_SHA3_512)
    assert (failed.outcome, failed.reason_code) == ("fail", "DIGEST_MISMATCH")
    with pytest.raises(FrozenInstanceError):
        failed.outcome = "pass"  # type: ignore[misc]