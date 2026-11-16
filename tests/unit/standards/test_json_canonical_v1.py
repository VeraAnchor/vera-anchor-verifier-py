import pytest

from vera_anchor_verifier.standards.hcs.json_canonical_v1 import (
    HcsJsonV1Error,
    canonical_hcs_json_v1,
    parse_strict_hcs_json_v1,
)


def test_canonicalizes_ecmascript_number_forms() -> None:
    value = {
        "a": 1e20,
        "b": 1e21,
        "c": 1e-6,
        "d": 1e-7,
        "e": -0.0,
    }

    assert canonical_hcs_json_v1(
        value,
        4096,
    ) == (
        '{"a":100000000000000000000,'
        '"b":1e+21,'
        '"c":0.000001,'
        '"d":1e-7,'
        '"e":0}'
    )


def test_sorts_keys_by_utf16_and_preserves_array_order() -> None:
    value = {
        "\U0001f600": 1,
        "\ue000": 2,
        "array": [
            3,
            2,
            1,
        ],
    }

    canonical = canonical_hcs_json_v1(
        value,
        4096,
    )

    assert canonical.index(
        '"😀"'
    ) < canonical.index(
        '"\ue000"'
    )

    assert (
        '"array":[3,2,1]'
        in canonical
    )


def test_rejects_duplicate_and_escaped_duplicate_keys() -> None:
    for raw in (
        '{"type":"object","type":"array"}',
        (
            '{"type":"object",'
            '"t\\u0079pe":"array"}'
        ),
    ):
        with pytest.raises(
            HcsJsonV1Error,
            match="JSON_AMBIGUOUS",
        ):
            parse_strict_hcs_json_v1(
                raw,
                4096,
            )


def test_rejects_invalid_unicode_and_nonfinite_numbers() -> None:
    with pytest.raises(
        HcsJsonV1Error,
        match="JSON_INVALID",
    ):
        canonical_hcs_json_v1(
            {
                "bad": "\ud800",
            },
            4096,
        )

    with pytest.raises(
        HcsJsonV1Error,
        match="JSON_INVALID",
    ):
        canonical_hcs_json_v1(
            {
                "bad": float(
                    "inf"
                ),
            },
            4096,
        )


def test_rejects_cycles_and_excessive_depth() -> None:
    cycle: list[object] = []
    cycle.append(cycle)

    with pytest.raises(
        HcsJsonV1Error,
        match="JSON_INVALID",
    ):
        canonical_hcs_json_v1(
            cycle,
            4096,
        )

    root: dict[str, object] = {}
    cursor = root

    for _ in range(66):
        child: dict[
            str,
            object,
        ] = {}
        cursor["x"] = child
        cursor = child

    with pytest.raises(
        HcsJsonV1Error,
        match="JSON_TOO_LARGE",
    ):
        canonical_hcs_json_v1(
            root,
            1024 * 1024,
        )


def test_strict_parser_requires_utf8_and_bounded_input() -> None:
    with pytest.raises(
        HcsJsonV1Error,
        match="JSON_INVALID",
    ):
        parse_strict_hcs_json_v1(
            b'{"x":"\xff"}',
            4096,
        )

    with pytest.raises(
        HcsJsonV1Error,
        match="JSON_TOO_LARGE",
    ):
        parse_strict_hcs_json_v1(
            '{"x":"' + ("a" * 100) + '"}',
            16,
        )