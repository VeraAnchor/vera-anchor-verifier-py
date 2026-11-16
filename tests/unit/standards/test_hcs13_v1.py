import hashlib
import json

import pytest

from vera_anchor_verifier.standards.hcs.hcs13_v1 import (
    Hcs13SchemaVerificationInput,
    Hcs13V1Error,
    build_hcs13_reference_v1,
    finalize_hcs13_schema_v1,
    parse_hcs13_reference_v1,
    parse_hcs13_schema_v1,
    verify_hcs13_schema_v1,
)

A = "a" * 64

SCHEMA_SHA = (
    "47609d2a1c1777932ece21aaf0deea00"
    "625a2d4072e559b4e3a728e30d5284f2"
)


def schema() -> dict[str, object]:
    return {
        "$schema": (
            "https://json-schema.org/"
            "draft/2020-12/schema"
        ),
        "$id": (
            "https://veraanchor.ai/"
            "schemas/"
            "sage-parameters-v1.json"
        ),
        "title": (
            "SAGE Parameters V1"
        ),
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "iterations": {
                "type": "integer",
                "minimum": 1,
            },
            "seed": {
                "type": "integer",
                "minimum": 0,
            },
            "temperature": {
                "type": "number",
                "minimum": 0,
            },
        },
        "required": [
            "iterations",
            "seed",
        ],
    }


def test_parses_exact_historical_references() -> None:
    assert (
        build_hcs13_reference_v1(
            " 0.0.5001 ",
            "007",
        )
        == "hcs://13/0.0.5001#7"
    )

    parsed = (
        parse_hcs13_reference_v1(
            "hcs://13/0.0.5001#7"
        )
    )

    assert (
        parsed.ref
        == "hcs://13/0.0.5001#7"
    )
    assert (
        parsed.registry_topic_id
        == "0.0.5001"
    )
    assert (
        parsed.sequence_number
        == 7
    )

    for invalid in (
        "hcs://13/0.0.5001",
        "hcs://13/0.0.5001#latest",
        "hcs://13/0.0.5001#01",
        "hcs://13/1.0.5001#1",
    ):
        with pytest.raises(
            Hcs13V1Error,
            match="HCS13_REF_INVALID",
        ):
            parse_hcs13_reference_v1(
                invalid
            )


def test_matches_frozen_canonical_byte_and_sha256_vector() -> None:
    computed = (
        finalize_hcs13_schema_v1(
            schema()
        )
    )

    assert (
        computed.byte_length
        == 368
    )
    assert (
        computed.sha256
        == SCHEMA_SHA
    )

    assert (
        hashlib.sha256(
            computed.canonical_payload.encode(
                "utf-8"
            )
        ).hexdigest()
        == SCHEMA_SHA
    )

    assert (
        parse_hcs13_schema_v1(
            json.dumps(
                schema()
            )
        ).sha256
        == SCHEMA_SHA
    )


def test_compares_independent_reference_and_checksum_expectations() -> None:
    evidence = (
        Hcs13SchemaVerificationInput(
            reference=(
                "hcs://13/"
                "0.0.5001#7"
            ),
            schema=json.dumps(
                schema()
            ),
            expected_registry_topic_id=(
                "0.0.5001"
            ),
            expected_sequence_number=7,
            expected_sha256=(
                SCHEMA_SHA
            ),
        )
    )

    passed = (
        verify_hcs13_schema_v1(
            evidence
        )
    )

    assert passed.status == "pass"
    assert (
        passed.checksum_match
        == "match"
    )

    mismatch = (
        verify_hcs13_schema_v1(
            Hcs13SchemaVerificationInput(
                reference=(
                    evidence.reference
                ),
                schema=evidence.schema,
                expected_registry_topic_id=(
                    "0.0.5001"
                ),
                expected_sequence_number=7,
                expected_sha256=A,
            )
        )
    )

    assert mismatch.status == "fail"
    assert (
        mismatch.checksum_match
        == "mismatch"
    )
    assert mismatch.reason_code == (
        "HCS13_CHECKSUM_MISMATCH"
    )

    sequence = (
        verify_hcs13_schema_v1(
            Hcs13SchemaVerificationInput(
                reference=(
                    evidence.reference
                ),
                schema=evidence.schema,
                expected_sequence_number=8,
            )
        )
    )

    assert sequence.reason_code == (
        "HCS13_SEQUENCE_MISMATCH"
    )

    unchecked = (
        verify_hcs13_schema_v1(
            Hcs13SchemaVerificationInput(
                reference=(
                    evidence.reference
                ),
                schema=evidence.schema,
            )
        )
    )

    assert unchecked.status == "pass"
    assert (
        unchecked.checksum_match
        == "not_checked"
    )


def test_rejects_duplicate_and_escaped_duplicate_json_keys() -> None:
    for raw in (
        (
            '{"type":"object",'
            '"type":"array"}'
        ),
        (
            '{"type":"object",'
            '"t\\u0079pe":"array"}'
        ),
    ):
        with pytest.raises(
            Hcs13V1Error,
            match=(
                "HCS13_SCHEMA_JSON_INVALID"
            ),
        ):
            parse_hcs13_schema_v1(
                raw
            )


def test_does_not_evaluate_json_schema_semantics() -> None:
    computed = (
        finalize_hcs13_schema_v1(
            {
                "$schema": "urn:unknown",
                "foo": 1,
            }
        )
    )

    assert len(
        computed.sha256
    ) == 64

    result = (
        verify_hcs13_schema_v1(
            Hcs13SchemaVerificationInput(
                reference=(
                    "hcs://13/"
                    "0.0.5001#7"
                ),
                schema="{}",
            )
        )
    )

    assert result.status == "pass"
    assert (
        result.checksum_match
        == "not_checked"
    )


def test_preserves_array_order_and_rejects_invalid_json_material() -> None:
    first = (
        finalize_hcs13_schema_v1(
            schema()
        )
    )

    reordered = schema()

    required = reordered[
        "required"
    ]

    assert isinstance(
        required,
        list,
    )

    required.reverse()

    second = (
        finalize_hcs13_schema_v1(
            reordered
        )
    )

    assert (
        second.sha256
        != first.sha256
    )

    with pytest.raises(
        Hcs13V1Error,
        match=(
            "HCS13_CANONICALIZATION_FAILED"
        ),
    ):
        finalize_hcs13_schema_v1(
            {
                "bad": object(),
            }
        )

    with pytest.raises(
        Hcs13V1Error,
        match=(
            "HCS13_CANONICALIZATION_FAILED"
        ),
    ):
        finalize_hcs13_schema_v1(
            {
                "bad": "\ud800",
            }
        )

    with pytest.raises(
        Hcs13V1Error,
        match=(
            "HCS13_SCHEMA_JSON_INVALID"
        ),
    ):
        parse_hcs13_schema_v1(
            '{"type":'
        )


def test_preserves_exact_512kib_canonical_ceiling() -> None:
    maximum = (
        finalize_hcs13_schema_v1(
            {
                "payload": (
                    "x" * 524_274
                )
            }
        )
    )

    assert (
        maximum.byte_length
        == 524_288
    )

    with pytest.raises(
        Hcs13V1Error,
        match=(
            "HCS13_SCHEMA_TOO_LARGE"
        ),
    ):
        finalize_hcs13_schema_v1(
            {
                "payload": (
                    "x" * 524_275
                )
            }
        )