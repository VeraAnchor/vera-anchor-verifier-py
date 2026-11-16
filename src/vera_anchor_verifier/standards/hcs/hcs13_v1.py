"""Pinned HCS-13 historical schema references and canonical integrity."""

import hashlib
import math
import re
from dataclasses import dataclass
from typing import Literal, Never, cast

from .json_canonical_v1 import (
    HcsJsonV1Error,
    canonical_hcs_json_v1,
    clone_hcs_json_v1,
    parse_strict_hcs_json_v1,
)

MAX_HCS13_V1_SCHEMA_BYTES = 512 * 1024
_RAW_SCHEMA_BYTES = MAX_HCS13_V1_SCHEMA_BYTES + 64 * 1024
_MAX_SAFE_INTEGER = (1 << 53) - 1

_TOPIC_RE = re.compile(r"^0\.0\.[0-9]+$", re.ASCII)
_REFERENCE_RE = re.compile(r"^hcs://13/(0\.0\.[0-9]+)#([1-9][0-9]*)$", re.ASCII)
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$", re.ASCII)


@dataclass(frozen=True, slots=True)
class Hcs13ReferenceV1:
    ref: str
    registry_topic_id: str
    sequence_number: int


@dataclass(frozen=True, slots=True)
class Hcs13SchemaV1:
    schema: dict[str, object]
    canonical_payload: str
    sha256: str
    byte_length: int


@dataclass(frozen=True, slots=True)
class Hcs13SchemaVerificationInput:
    reference: object
    schema: bytes | bytearray | memoryview | str
    expected_sha256: str | None = None
    expected_registry_topic_id: str | None = None
    expected_sequence_number: int | None = None


@dataclass(frozen=True, slots=True)
class Hcs13SchemaVerificationV1:
    status: Literal["pass", "fail"]
    reason_code: str | None
    reference: Hcs13ReferenceV1 | None
    sha256: str | None
    checksum_match: Literal["match", "mismatch", "not_checked"]


class Hcs13V1Error(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _fail(code: str) -> Never:
    raise Hcs13V1Error(code)


def _topic_id(value: object) -> str:
    if not isinstance(value, str):
        _fail("HCS13_TOPIC_INVALID")

    topic = value.strip()
    if _TOPIC_RE.fullmatch(topic) is None:
        _fail("HCS13_TOPIC_INVALID")

    return topic


def _js_number(value: object) -> float:
    if isinstance(value, bool):
        return 1.0 if value else 0.0

    if isinstance(value, (int, float)):
        try:
            return float(value)
        except OverflowError:
            return math.nan

    if isinstance(value, str):
        text = value.strip()
        if not text:
            return 0.0

        lowered = text.lower()
        try:
            sign = -1 if lowered.startswith("-") else 1
            unsigned = lowered[1:] if lowered[:1] in {"+", "-"} else lowered

            if unsigned.startswith("0x"):
                return float(sign * int(unsigned[2:], 16))
            if unsigned.startswith("0b"):
                return float(sign * int(unsigned[2:], 2))
            if unsigned.startswith("0o"):
                return float(sign * int(unsigned[2:], 8))

            return float(text)
        except (ValueError, OverflowError):
            return math.nan

    return math.nan


def _sequence(value: object) -> int:
    if value is None or value == "":
        _fail("HCS13_SEQUENCE_INVALID")

    number = _js_number(value)
    if (
        not math.isfinite(number)
        or not number.is_integer()
        or number < 1
        or number > _MAX_SAFE_INTEGER
    ):
        _fail("HCS13_SEQUENCE_INVALID")

    return int(number)


def build_hcs13_reference_v1(
    registry_topic_id: object,
    sequence_number: object,
) -> str:
    return f"hcs://13/{_topic_id(registry_topic_id)}#{_sequence(sequence_number)}"


def parse_hcs13_reference_v1(value: object) -> Hcs13ReferenceV1:
    match = _REFERENCE_RE.fullmatch(value.strip()) if isinstance(value, str) else None
    if match is None:
        _fail("HCS13_REF_INVALID")

    number = _sequence(match.group(2))
    return Hcs13ReferenceV1(
        ref=f"hcs://13/{match.group(1)}#{number}",
        registry_topic_id=match.group(1),
        sequence_number=number,
    )


def _finalize(value: object) -> Hcs13SchemaV1:
    if type(value) is not dict:
        _fail("HCS13_SCHEMA_INVALID")

    schema = cast(dict[str, object], value)
    schema_uri = schema.get("$schema")
    if schema_uri is not None and not isinstance(schema_uri, str):
        _fail("HCS13_SCHEMA_INVALID")

    try:
        canonical = canonical_hcs_json_v1(schema, MAX_HCS13_V1_SCHEMA_BYTES)
    except HcsJsonV1Error as exc:
        _fail(
            "HCS13_SCHEMA_TOO_LARGE"
            if exc.code == "JSON_TOO_LARGE"
            else "HCS13_CANONICALIZATION_FAILED"
        )

    payload = canonical.encode("utf-8")
    cloned = clone_hcs_json_v1(schema)
    if type(cloned) is not dict:
        _fail("HCS13_CANONICALIZATION_FAILED")

    return Hcs13SchemaV1(
        schema=cast(dict[str, object], cloned),
        canonical_payload=canonical,
        sha256=hashlib.sha256(payload).hexdigest(),
        byte_length=len(payload),
    )


def finalize_hcs13_schema_v1(value: object) -> Hcs13SchemaV1:
    return _finalize(value)


def parse_hcs13_schema_v1(
    value: bytes | bytearray | memoryview | str,
) -> Hcs13SchemaV1:
    try:
        document = parse_strict_hcs_json_v1(value, _RAW_SCHEMA_BYTES)
    except HcsJsonV1Error as exc:
        _fail(
            "HCS13_SCHEMA_TOO_LARGE"
            if exc.code == "JSON_TOO_LARGE"
            else "HCS13_SCHEMA_JSON_INVALID"
        )

    return _finalize(document)


def verify_hcs13_schema_v1(
    input: Hcs13SchemaVerificationInput,
) -> Hcs13SchemaVerificationV1:
    """Verify one exact HCS-13 reference and supplied schema material.

    A pass without independent expected commitments is not a registry or
    publication-authentication claim.
    """
    reference: Hcs13ReferenceV1 | None = None
    sha256: str | None = None
    checksum_match: Literal["match", "mismatch", "not_checked"] = "not_checked"

    def result(
        status: Literal["pass", "fail"],
        reason_code: str | None,
    ) -> Hcs13SchemaVerificationV1:
        return Hcs13SchemaVerificationV1(
            status=status,
            reason_code=reason_code,
            reference=reference,
            sha256=sha256,
            checksum_match=checksum_match,
        )

    try:
        if not isinstance(input, Hcs13SchemaVerificationInput):
            _fail("HCS13_INPUT_INVALID")

        reference = parse_hcs13_reference_v1(input.reference)

        if (
            input.expected_registry_topic_id is not None
            and _topic_id(input.expected_registry_topic_id)
            != reference.registry_topic_id
        ):
            _fail("HCS13_REGISTRY_MISMATCH")

        if (
            input.expected_sequence_number is not None
            and _sequence(input.expected_sequence_number) != reference.sequence_number
        ):
            _fail("HCS13_SEQUENCE_MISMATCH")

        document = parse_hcs13_schema_v1(input.schema)
        sha256 = document.sha256
        raw_expected: object = input.expected_sha256

        if raw_expected is not None:
            if (
                not isinstance(raw_expected, str)
                or _SHA256_RE.fullmatch(raw_expected) is None
            ):
                _fail("HCS13_EXPECTED_CHECKSUM_INVALID")

            checksum_match = "match" if raw_expected == sha256 else "mismatch"
            if checksum_match == "mismatch":
                _fail("HCS13_CHECKSUM_MISMATCH")

        return result("pass", None)
    except Hcs13V1Error as exc:
        return result("fail", exc.code)