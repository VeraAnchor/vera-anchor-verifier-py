import asyncio
from collections.abc import AsyncIterator, Coroutine
from typing import Any

import pytest

from vera_anchor_verifier import sha3_512_stream, verify_sha3_512_stream

ABC_SHA3_512 = (
    "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e1"
    "0e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"
)
EMPTY_SHA3_512 = (
    "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6"
    "15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
)


def run[T](coro: Coroutine[Any, Any, T]) -> T:
    return asyncio.run(coro)


async def async_chunks() -> AsyncIterator[bytes]:
    yield b"a"
    yield b"bc"


def test_stream_hashes_sync_async_and_empty_sources() -> None:
    sync = run(sha3_512_stream([b"a", bytearray(b"b"), memoryview(b"c")]))
    async_result = run(sha3_512_stream(async_chunks()))
    empty = run(sha3_512_stream([]))
    assert (sync.digest, sync.bytes_hashed) == (ABC_SHA3_512, 3)
    assert async_result == sync
    assert (empty.digest, empty.bytes_hashed) == (EMPTY_SHA3_512, 0)


def test_stream_enforces_max_bytes() -> None:
    assert run(sha3_512_stream([b"abc"], max_bytes=3)).bytes_hashed == 3
    with pytest.raises(ValueError, match="exceeds max_bytes"):
        run(sha3_512_stream([b"ab", b"c"], max_bytes=2))


def test_stream_rejects_invalid_limits_and_chunks() -> None:
    for value in (-1, True, 1.5, 1 << 53):
        with pytest.raises(TypeError, match="non-negative safe integer"):
            run(sha3_512_stream([], max_bytes=value))  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="chunks must be bytes-like"):
        run(sha3_512_stream([b"a", "b"]))  # type: ignore[list-item]


def test_stream_verification_pass_and_byte_count_mismatch() -> None:
    passed = run(
        verify_sha3_512_stream(
            source=[b"a", b"bc"],
            expected_digest=ABC_SHA3_512.upper(),
            expected_bytes=3,
        )
    )
    assert (passed.outcome, passed.reason_code, passed.bytes_hashed) == (
        "pass",
        None,
        3,
    )

    mismatch = run(
        verify_sha3_512_stream(
            source=[b"abc"],
            expected_digest=ABC_SHA3_512,
            expected_bytes=4,
        )
    )
    assert (mismatch.outcome, mismatch.reason_code) == (
        "fail",
        "BYTE_COUNT_MISMATCH",
    )


def test_digest_mismatch_precedes_byte_count_mismatch() -> None:
    result = run(
        verify_sha3_512_stream(
            source=[b"abc"],
            expected_digest=EMPTY_SHA3_512,
            expected_bytes=4,
        )
    )
    assert (result.outcome, result.reason_code) == ("fail", "DIGEST_MISMATCH")


def test_expected_bytes_uses_js_safe_integer_semantics() -> None:
    for value in (-1, True, 1.5, 1 << 53):
        with pytest.raises(TypeError, match="expected_bytes must be a non-negative safe integer"):
            run(
                verify_sha3_512_stream(
                    source=[],
                    expected_digest=EMPTY_SHA3_512,
                    expected_bytes=value,  # type: ignore[arg-type]
                )
            )