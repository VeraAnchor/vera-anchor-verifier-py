from datetime import UTC, datetime

import pytest

from vera_anchor_verifier.profiles.execution.recomputation_v1 import (
    canonicalize_execution_verification_value,
    compute_execution_domain_separated_sha3_512,
    execution_timestamp_nanos,
    hedera_consensus_timestamp_nanos,
)

EXPECTED_DIGEST = (
    "227d4e4539c9fea7bd170be48fbb0d55"
    "e5c2a6b01961e5a3460cfcd4585806d8"
    "fc58bf1b99bdd88d960e0c04bc68e1fee"
    "3b8dc17ae43467eacb595b81422efe0"
)


def test_canonicalizes_nested_objects_independent_of_order() -> None:
    first = {
        "z": [
            1,
            {
                "beta": True,
                "alpha": "ok",
            },
        ],
        "a": None,
    }
    second = {
        "a": None,
        "z": [
            1,
            {
                "alpha": "ok",
                "beta": True,
            },
        ],
    }

    expected = (
        '{"a":null,"z":'
        '[1,{"alpha":"ok","beta":true}]}'
    )

    assert (
        canonicalize_execution_verification_value(
            first
        )
        == expected
    )
    assert (
        canonicalize_execution_verification_value(
            second
        )
        == expected
    )


def test_matches_frozen_domain_separated_sha3_512() -> None:
    evidence = {
        "b": 2,
        "a": 1,
    }

    assert (
        compute_execution_domain_separated_sha3_512(
            "va:execution:binding:v1",
            evidence,
        )
        == EXPECTED_DIGEST
    )

    assert (
        compute_execution_domain_separated_sha3_512(
            "va:execution:other:v1",
            evidence,
        )
        != EXPECTED_DIGEST
    )


def test_uses_js_json_number_rendering() -> None:
    value = {
        "negative_zero": -0.0,
        "integer_float": 1.0,
        "small": 1e-7,
        "expanded": 1e-6,
    }

    assert (
        canonicalize_execution_verification_value(
            value
        )
        == (
            '{"expanded":0.000001,'
            '"integer_float":1,'
            '"negative_zero":0,'
            '"small":1e-7}'
        )
    )


def test_rejects_unsupported_and_malformed_values() -> None:
    with pytest.raises(
        TypeError,
        match="Non-finite",
    ):
        canonicalize_execution_verification_value(
            {
                "a": float("inf"),
            }
        )

    with pytest.raises(
        TypeError,
        match="Unpaired UTF-16 surrogate",
    ):
        canonicalize_execution_verification_value(
            {
                "a": "\ud800",
            }
        )

    with pytest.raises(
        TypeError,
        match="Unsupported canonical JSON",
    ):
        canonicalize_execution_verification_value(
            datetime.now(
                UTC
            )
        )

    deep: object = None

    for _ in range(66):
        deep = {
            "x": deep,
        }

    with pytest.raises(
        TypeError,
        match="depth",
    ):
        canonicalize_execution_verification_value(
            deep
        )


def test_uses_utf16_object_key_order() -> None:
    value = {
        "\ue000": 2,
        "\U00010000": 1,
    }

    canonical = (
        canonicalize_execution_verification_value(
            value
        )
    )

    assert canonical == (
        '{"𐀀":1,"\ue000":2}'
    )


def test_preserves_one_nanosecond_hedera_difference() -> None:
    first = (
        hedera_consensus_timestamp_nanos(
            "1792033594.745290900"
        )
    )
    second = (
        hedera_consensus_timestamp_nanos(
            "1792033594.745290901"
        )
    )

    assert first is not None
    assert second is not None
    assert second - first == 1

    assert (
        hedera_consensus_timestamp_nanos(
            "1792033594.74529090"
        )
        is None
    )
    assert (
        hedera_consensus_timestamp_nanos(
            "1792033594.745290900Z"
        )
        is None
    )


def test_preserves_utc_fractional_nanoseconds() -> None:
    first = execution_timestamp_nanos(
        "2026-10-15T04:36:19.000000001Z"
    )
    second = execution_timestamp_nanos(
        "2026-10-15T04:36:19.000000002Z"
    )
    millis = execution_timestamp_nanos(
        "2026-10-15T04:36:19.001Z"
    )

    assert first is not None
    assert second is not None
    assert millis is not None

    assert second - first == 1
    assert millis - first == 999_999

    assert (
        execution_timestamp_nanos(
            "2026-10-15T04:36:19+00:00"
        )
        == execution_timestamp_nanos(
            "2026-10-15T04:36:19Z"
        )
    )


def test_rejects_malformed_or_ambiguous_utc_timestamps() -> None:
    assert (
        execution_timestamp_nanos(
            "2026-02-30T00:00:00Z"
        )
        is None
    )
    assert (
        execution_timestamp_nanos(
            "2026-10-15T25:00:00Z"
        )
        is None
    )
    assert (
        execution_timestamp_nanos(
            "2026-10-15T04:36:19.0000000001Z"
        )
        is None
    )
    assert (
        execution_timestamp_nanos(
            "2026-10-15T04:36:19-06:00"
        )
        is None
    )
    assert (
        execution_timestamp_nanos(
            1792033594
        )
        is None
    )

    assert (
        execution_timestamp_nanos(
            datetime(
                2026,
                10,
                15,
                4,
                36,
                19,
            )
        )
        is None
    )


def test_accepts_timezone_aware_datetime_without_float_conversion() -> None:
    value = datetime(
        2026,
        10,
        15,
        4,
        36,
        19,
        123456,
        tzinfo=UTC,
    )

    parsed = execution_timestamp_nanos(
        value
    )
    base = execution_timestamp_nanos(
        "2026-10-15T04:36:19Z"
    )

    assert parsed is not None
    assert base is not None
    assert (
        parsed - base
        == 123_456_000
    )