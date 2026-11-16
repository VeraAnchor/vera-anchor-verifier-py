import json

import pytest

from vera_anchor_verifier.standards.hcs.hcs2_v1 import (
    Hcs2V1Error,
    Hcs2V1Memo,
    Hcs2V1VerificationInput,
    parse_hcs2_memo_v1,
    parse_hcs2_register_v1,
    verify_hcs2_register_v1,
)

TARGET = "0.0.10765268"
MEMO = "hcs-2:0:86400"


def raw(
    overrides: dict[
        str,
        object,
    ]
    | None = None,
) -> bytes:
    value: dict[
        str,
        object,
    ] = {
        "p": "hcs-2",
        "op": "register",
        "t_id": TARGET,
    }

    if overrides:
        value.update(
            overrides
        )

    return json.dumps(
        value,
        separators=(",", ":"),
    ).encode("utf-8")


def test_parses_memo_ttl_boundaries() -> None:
    assert (
        parse_hcs2_memo_v1(
            " hcs-2:0:86400 "
        )
        == Hcs2V1Memo(
            memo=MEMO,
            indexed=True,
            ttl=86400,
        )
    )

    assert (
        parse_hcs2_memo_v1(
            "hcs-2:1:0"
        ).indexed
        is False
    )

    assert (
        parse_hcs2_memo_v1(
            "hcs-2:1:31536000"
        ).ttl
        == 31_536_000
    )

    with pytest.raises(
        Hcs2V1Error,
        match="HCS2_TTL_INVALID",
    ):
        parse_hcs2_memo_v1(
            "hcs-2:0:31536001"
        )

    with pytest.raises(
        Hcs2V1Error,
        match="HCS2_MEMO_INVALID",
    ):
        parse_hcs2_memo_v1(
            "hcs-2:2:10"
        )

    with pytest.raises(
        Hcs2V1Error,
        match="HCS2_MEMO_INVALID",
    ):
        parse_hcs2_memo_v1(
            "HCS-2:0:10"
        )


def test_verifies_without_inventing_expected_target() -> None:
    result = (
        verify_hcs2_register_v1(
            Hcs2V1VerificationInput(
                memo=MEMO,
                message=raw(),
            )
        )
    )

    assert result.status == "pass"
    assert result.reason_code is None
    assert (
        result.target_match
        == "not_checked"
    )
    assert result.register is not None
    assert (
        result.register.t_id
        == TARGET
    )


def test_compares_independent_expected_target() -> None:
    matching = (
        verify_hcs2_register_v1(
            Hcs2V1VerificationInput(
                memo=MEMO,
                message=raw(),
                expected_t_id=TARGET,
            )
        )
    )

    assert (
        matching.target_match
        == "match"
    )

    mismatch = (
        verify_hcs2_register_v1(
            Hcs2V1VerificationInput(
                memo=MEMO,
                message=raw(),
                expected_t_id=(
                    "0.0.999"
                ),
            )
        )
    )

    assert mismatch.status == "fail"
    assert mismatch.reason_code == (
        "HCS2_TARGET_MISMATCH"
    )
    assert (
        mismatch.target_match
        == "mismatch"
    )


def test_reorders_keys_and_normalizes_optional_text() -> None:
    value = json.dumps(
        {
            "m": " test ",
            "metadata": (
                " hcs://1/0.0.5 "
            ),
            "t_id": f" {TARGET} ",
            "op": "register",
            "p": "hcs-2",
        }
    )

    parsed = (
        parse_hcs2_register_v1(
            value
        )
    )

    assert parsed.t_id == TARGET
    assert (
        parsed.metadata
        == "hcs://1/0.0.5"
    )
    assert parsed.m == "test"

    empty = (
        parse_hcs2_register_v1(
            raw(
                {
                    "metadata": "   ",
                    "m": "",
                }
            )
        )
    )

    assert empty.metadata is None
    assert empty.m is None


@pytest.mark.parametrize(
    ("fields", "reason"),
    [
        (
            {"op": "update"},
            "HCS2_OPERATION_INVALID",
        ),
        (
            {"injected": "yes"},
            "HCS2_MESSAGE_INVALID",
        ),
        (
            {"t_id": "1.0.123"},
            "HCS2_TOPIC_INVALID",
        ),
        (
            {"m": "has\nline"},
            "HCS2_TEXT_INVALID",
        ),
        (
            {"metadata": 1},
            "HCS2_MESSAGE_INVALID",
        ),
        (
            {
                "metadata": {
                    "url": (
                        "https://example.com"
                    ),
                },
            },
            "HCS2_MESSAGE_INVALID",
        ),
    ],
)
def test_rejects_invalid_register_material(
    fields: dict[
        str,
        object,
    ],
    reason: str,
) -> None:
    result = (
        verify_hcs2_register_v1(
            Hcs2V1VerificationInput(
                memo=MEMO,
                message=raw(fields),
            )
        )
    )

    assert (
        result.reason_code
        == reason
    )


def test_rejects_duplicate_and_escaped_duplicate_keys() -> None:
    duplicate = (
        '{"p":"hcs-2",'
        '"op":"register",'
        f'"t_id":"{TARGET}",'
        '"t_id":"0.0.999"}'
    )

    assert (
        verify_hcs2_register_v1(
            Hcs2V1VerificationInput(
                memo=MEMO,
                message=duplicate,
            )
        ).reason_code
        == "HCS2_MESSAGE_INVALID"
    )

    escaped = (
        '{"p":"hcs-2",'
        '"op":"register",'
        f'"t_id":"{TARGET}",'
        '"t_\\u0069d":"0.0.999"}'
    )

    assert (
        verify_hcs2_register_v1(
            Hcs2V1VerificationInput(
                memo=MEMO,
                message=escaped,
            )
        ).reason_code
        == "HCS2_MESSAGE_INVALID"
    )


def test_enforces_message_ceiling_and_utf8() -> None:
    oversized = (
        verify_hcs2_register_v1(
            Hcs2V1VerificationInput(
                memo=MEMO,
                message=raw(
                    {
                        "metadata": (
                            "x" * 962
                        ),
                    }
                ),
            )
        )
    )

    assert oversized.reason_code == (
        "HCS2_MESSAGE_TOO_LARGE"
    )

    invalid_utf8 = (
        verify_hcs2_register_v1(
            Hcs2V1VerificationInput(
                memo=MEMO,
                message=bytes(
                    [123, 255, 125]
                ),
            )
        )
    )

    assert (
        invalid_utf8.reason_code
        == "HCS2_MESSAGE_INVALID"
    )


def test_exports_stable_validation_error() -> None:
    with pytest.raises(
        Hcs2V1Error,
    ):
        parse_hcs2_register_v1(
            b"[]"
        )