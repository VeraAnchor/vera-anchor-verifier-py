import base64
import hashlib
import json

import pytest

from vera_anchor_verifier.standards.hcs.hcs1_v1 import (
    MAX_HCS1_V1_CHUNKS,
    MAX_HCS1_V1_FILE_BYTES,
    Hcs1V1ContentInput,
    Hcs1V1ContentOptions,
    parse_hcs1_reference_v1,
    verify_hcs1_content_v1,
)

TOPIC = "0.0.10765268"
REFERENCE = f"hcs://1/{TOPIC}"

CONTENT = (
    b'{"name":"SAGE","version":"1.0.0"}'
)
COMPRESSED = b"deterministic-zstd-fixture"

SHA256 = hashlib.sha256(
    CONTENT
).hexdigest()

MEMO = (
    f"{SHA256}:zstd:base64"
)


def chunk(
    order: int,
    content: str,
) -> bytes:
    return json.dumps(
        {
            "o": order,
            "c": content,
        },
        separators=(",", ":"),
    ).encode(
        "utf-8"
    )


def messages() -> tuple[bytes, ...]:
    encoded = (
        base64.b64encode(
            COMPRESSED
        ).decode(
            "ascii"
        )
    )

    split = 12

    return (
        chunk(
            0,
            (
                "data:application/json;"
                "base64,"
                + encoded[:split]
            ),
        ),
        chunk(
            1,
            encoded[split:],
        ),
    )


def options(
) -> Hcs1V1ContentOptions:
    def decompress(
        compressed: bytes,
        limit: int,
    ) -> bytes:
        assert compressed == COMPRESSED
        assert limit == (
            MAX_HCS1_V1_FILE_BYTES
        )

        return CONTENT

    return Hcs1V1ContentOptions(
        decompress_zstd=decompress
    )


def run(coro):
    import asyncio

    return asyncio.run(
        coro
    )


def test_parses_exact_hcs1_reference() -> None:
    parsed = (
        parse_hcs1_reference_v1(
            REFERENCE
        )
    )

    assert parsed.reference == REFERENCE
    assert parsed.topic_id == TOPIC

    for invalid in (
        "",
        " hcs://1/0.0.42",
        "hcs://1/0.0.42 ",
        "hcs://2/0.0.42",
        "hcs://1/0.0.-1",
        "https://example.test",
        None,
        42,
    ):
        with pytest.raises(
            TypeError,
            match="HCS1_REFERENCE_INVALID",
        ):
            parse_hcs1_reference_v1(
                invalid
            )


def test_reassembles_out_of_order_chunks_and_verifies_sha256() -> None:
    first, second = messages()

    result = run(
        verify_hcs1_content_v1(
            Hcs1V1ContentInput(
                memo=MEMO,
                messages=(
                    second,
                    first,
                ),
                expected_sha256=SHA256,
            ),
            options(),
        )
    )

    assert result.status == "pass"
    assert result.reason_code is None
    assert result.sha256 == SHA256
    assert (
        result.mime_type
        == "application/json"
    )
    assert result.chunk_count == 2
    assert result.bytes == CONTENT


def test_accepts_async_explicit_decompressor() -> None:
    async def decompress(
        compressed: bytes,
        limit: int,
    ) -> bytes:
        assert compressed == COMPRESSED
        assert limit == (
            MAX_HCS1_V1_FILE_BYTES
        )
        return CONTENT

    result = run(
        verify_hcs1_content_v1(
            Hcs1V1ContentInput(
                memo=MEMO,
                messages=messages(),
            ),
            Hcs1V1ContentOptions(
                decompress_zstd=(
                    decompress
                )
            ),
        )
    )

    assert result.status == "pass"
    assert result.bytes == CONTENT


def test_reports_unsupported_when_zstd_adapter_is_absent() -> None:
    result = run(
        verify_hcs1_content_v1(
            Hcs1V1ContentInput(
                memo=MEMO,
                messages=messages(),
            )
        )
    )

    assert result.status == "unsupported"
    assert result.reason_code == (
        "HCS1_ZSTD_UNAVAILABLE"
    )
    assert result.bytes is None


@pytest.mark.parametrize(
    ("value", "reason"),
    (
        (
            Hcs1V1ContentInput(
                memo="not-a-memo",
                messages=messages(),
            ),
            "HCS1_MEMO_INVALID",
        ),
        (
            Hcs1V1ContentInput(
                memo=MEMO,
                messages=(),
            ),
            "HCS1_CHUNKS_INVALID",
        ),
        (
            Hcs1V1ContentInput(
                memo=MEMO,
                messages=(
                    b"",
                ),
            ),
            "HCS1_MESSAGE_INVALID",
        ),
        (
            Hcs1V1ContentInput(
                memo=MEMO,
                messages=(
                    b"{",
                ),
            ),
            "HCS1_CHUNK_INVALID",
        ),
        (
            Hcs1V1ContentInput(
                memo=MEMO,
                messages=(
                    json.dumps(
                        {
                            "o": 0,
                            "c": "x",
                            "extra": True,
                        }
                    ).encode(),
                ),
            ),
            "HCS1_CHUNK_INVALID",
        ),
    ),
)
def test_rejects_invalid_structure(
    value: Hcs1V1ContentInput,
    reason: str,
) -> None:
    result = run(
        verify_hcs1_content_v1(
            value,
            options(),
        )
    )

    assert result.status == "fail"
    assert result.reason_code == reason


def test_rejects_duplicate_and_missing_chunk_orders() -> None:
    first, _second = messages()

    duplicate = run(
        verify_hcs1_content_v1(
            Hcs1V1ContentInput(
                memo=MEMO,
                messages=(
                    first,
                    first,
                ),
            ),
            options(),
        )
    )

    assert duplicate.status == "fail"
    assert duplicate.reason_code == (
        "HCS1_CHUNK_DUPLICATE"
    )

    encoded = (
        base64.b64encode(
            COMPRESSED
        ).decode(
            "ascii"
        )
    )

    gap = run(
        verify_hcs1_content_v1(
            Hcs1V1ContentInput(
                memo=MEMO,
                messages=(
                    chunk(
                        0,
                        (
                            "data:application/json;"
                            "base64,"
                            + encoded[:12]
                        ),
                    ),
                    chunk(
                        2,
                        encoded[12:],
                    ),
                ),
            ),
            options(),
        )
    )

    assert gap.status == "fail"
    assert gap.reason_code == (
        "HCS1_CHUNK_GAP"
    )


def test_rejects_noncanonical_base64_and_bad_prefix() -> None:
    bad_prefix = run(
        verify_hcs1_content_v1(
            Hcs1V1ContentInput(
                memo=MEMO,
                messages=(
                    chunk(
                        0,
                        (
                            "data:bad mime;"
                            "base64,AAAA"
                        ),
                    ),
                ),
            ),
            options(),
        )
    )

    assert bad_prefix.status == "fail"
    assert bad_prefix.reason_code == (
        "HCS1_PREFIX_INVALID"
    )

    bad_base64 = run(
        verify_hcs1_content_v1(
            Hcs1V1ContentInput(
                memo=MEMO,
                messages=(
                    chunk(
                        0,
                        (
                            "data:application/json;"
                            "base64,AAA!"
                        ),
                    ),
                ),
            ),
            options(),
        )
    )

    assert bad_base64.status == "fail"
    assert bad_base64.reason_code == (
        "HCS1_BASE64_INVALID"
    )


def test_detects_memo_and_caller_checksum_conflicts() -> None:
    memo_mismatch = run(
        verify_hcs1_content_v1(
            Hcs1V1ContentInput(
                memo=(
                    f"{'a' * 64}:"
                    "zstd:base64"
                ),
                messages=messages(),
            ),
            options(),
        )
    )

    assert memo_mismatch.status == "fail"
    assert memo_mismatch.reason_code == (
        "HCS1_CHECKSUM_MISMATCH"
    )

    expected_mismatch = run(
        verify_hcs1_content_v1(
            Hcs1V1ContentInput(
                memo=MEMO,
                messages=messages(),
                expected_sha256=(
                    "b" * 64
                ),
            ),
            options(),
        )
    )

    assert expected_mismatch.status == "fail"
    assert expected_mismatch.reason_code == (
        "HCS1_EXPECTED_CHECKSUM_MISMATCH"
    )

    invalid_expected = run(
        verify_hcs1_content_v1(
            Hcs1V1ContentInput(
                memo=MEMO,
                messages=messages(),
                expected_sha256="xyz",
            ),
            options(),
        )
    )

    assert invalid_expected.status == "fail"
    assert invalid_expected.reason_code == (
        "HCS1_EXPECTED_CHECKSUM_INVALID"
    )


def test_enforces_output_and_configuration_bounds() -> None:
    def oversized(
        compressed: bytes,
        limit: int,
    ) -> bytes:
        del compressed
        return b"x" * (
            limit + 1
        )

    result = run(
        verify_hcs1_content_v1(
            Hcs1V1ContentInput(
                memo=MEMO,
                messages=messages(),
            ),
            Hcs1V1ContentOptions(
                max_file_bytes=16,
                decompress_zstd=oversized,
            ),
        )
    )

    assert result.status == "fail"
    assert result.reason_code == (
        "HCS1_FILE_TOO_LARGE"
    )

    with pytest.raises(
        TypeError,
        match="HCS1_FILE_LIMIT_INVALID",
    ):
        run(
            verify_hcs1_content_v1(
                Hcs1V1ContentInput(
                    memo=MEMO,
                    messages=messages(),
                ),
                Hcs1V1ContentOptions(
                    max_file_bytes=0,
                    decompress_zstd=(
                        lambda compressed, limit: (
                            CONTENT
                        )
                    ),
                ),
            )
        )

    with pytest.raises(
        TypeError,
        match="HCS1_FILE_LIMIT_INVALID",
    ):
        run(
            verify_hcs1_content_v1(
                Hcs1V1ContentInput(
                    memo=MEMO,
                    messages=messages(),
                ),
                Hcs1V1ContentOptions(
                    max_file_bytes=(
                        MAX_HCS1_V1_FILE_BYTES
                        + 1
                    ),
                ),
            )
        )

    assert (
        MAX_HCS1_V1_CHUNKS
        == 4096
    )


def test_maps_explicit_decompressor_failure_to_invalid() -> None:
    def broken(
        compressed: bytes,
        limit: int,
    ) -> bytes:
        del compressed, limit
        raise ValueError(
            "bad zstd stream"
        )

    result = run(
        verify_hcs1_content_v1(
            Hcs1V1ContentInput(
                memo=MEMO,
                messages=messages(),
            ),
            Hcs1V1ContentOptions(
                decompress_zstd=broken
            ),
        )
    )

    assert result.status == "fail"
    assert result.reason_code == (
        "HCS1_DECOMPRESSION_INVALID"
    )