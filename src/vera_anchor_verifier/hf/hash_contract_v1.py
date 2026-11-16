"""HF v1 deterministic canonicalization, framing, hashing, and verification."""

import math
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final, Literal, TypedDict, cast

from ..crypto.sha3 import BytesLike, normalize_sha3_512_digest, sha3_512_hex

HF_V1_CONTRACT_ID: Final = "hf-contract-v1"
HF_V1_FRAME_ID: Final = "hf:frame:v1"
HF_V1_CANONICAL_JSON_ID: Final = "hf:canonical-json:v1"
MAX_HF_V1_PAYLOAD_BYTES: Final = 16 * 1024 * 1024

_MAX_JSON_DEPTH = 64
_MAX_JSON_KEYS = 200_000
_MAX_JSON_ARRAY_LENGTH = 200_000
_MAX_SAFE_INTEGER = (1 << 53) - 1

_DOMAIN_RE = re.compile(r"^[a-z0-9][a-z0-9._:/-]{0,63}$", re.ASCII)
_FRAME_MAGIC = HF_V1_FRAME_ID.encode("utf-8")

_ECMASCRIPT_TRIM = (
    "\u0009\u000b\u000c\u0020\u00a0\u1680"
    "\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a"
    "\u2028\u2029\u202f\u205f\u3000\ufeff\u000a\u000d"
)

type HfV1MaterialKind = Literal["json", "raw", "utf8"]


@dataclass(frozen=True, slots=True)
class HfV1BigInt:
    """Explicit JavaScript BigInt equivalent for HF canonical JSON."""

    value: int

    def __post_init__(self) -> None:
        if isinstance(self.value, bool) or not isinstance(self.value, int):
            raise TypeError("HF v1 bigint value must be an integer")


class HfV1JsonMaterial(TypedDict):
    material: Literal["json"]
    value: object


class HfV1RawMaterial(TypedDict):
    material: Literal["raw"]
    bytes: BytesLike


class HfV1Utf8Material(TypedDict):
    material: Literal["utf8"]
    text: str


class HfV1ExpectedCommitment(TypedDict):
    kind: Literal["digest"]
    contract: Literal["hf-contract-v1"]
    material: HfV1MaterialKind
    domain: str
    digest: str


@dataclass(frozen=True, slots=True)
class HfV1DigestVerificationResult:
    outcome: Literal["pass", "fail"]
    reason_code: str | None
    contract: Literal["hf-contract-v1"]
    material: HfV1MaterialKind
    domain: str
    expected_digest: str
    computed_digest: str | None


def _node_utf8_bytes(value: str) -> bytes:
    chars: list[str] = []
    index = 0

    while index < len(value):
        codepoint = ord(value[index])

        if 0xD800 <= codepoint <= 0xDBFF:
            if index + 1 < len(value):
                low = ord(value[index + 1])
                if 0xDC00 <= low <= 0xDFFF:
                    scalar = (
                        0x10000
                        + ((codepoint - 0xD800) << 10)
                        + (low - 0xDC00)
                    )
                    chars.append(chr(scalar))
                    index += 2
                    continue
            chars.append("\ufffd")
        elif 0xDC00 <= codepoint <= 0xDFFF:
            chars.append("\ufffd")
        else:
            chars.append(value[index])

        index += 1

    return "".join(chars).encode("utf-8")


def _quoted(value: str) -> str:
    parts = ['"']
    index = 0

    while index < len(value):
        codepoint = ord(value[index])

        if codepoint == 0x22:
            parts.append('\\"')
        elif codepoint == 0x5C:
            parts.append("\\\\")
        elif codepoint == 0x08:
            parts.append("\\b")
        elif codepoint == 0x09:
            parts.append("\\t")
        elif codepoint == 0x0A:
            parts.append("\\n")
        elif codepoint == 0x0C:
            parts.append("\\f")
        elif codepoint == 0x0D:
            parts.append("\\r")
        elif codepoint < 0x20:
            parts.append(f"\\u{codepoint:04x}")
        elif 0xD800 <= codepoint <= 0xDBFF:
            if index + 1 < len(value):
                low = ord(value[index + 1])
                if 0xDC00 <= low <= 0xDFFF:
                    scalar = (
                        0x10000
                        + ((codepoint - 0xD800) << 10)
                        + (low - 0xDC00)
                    )
                    parts.append(chr(scalar))
                    index += 2
                    continue
            parts.append(f"\\u{codepoint:04x}")
        elif 0xDC00 <= codepoint <= 0xDFFF:
            parts.append(f"\\u{codepoint:04x}")
        else:
            parts.append(value[index])

        index += 1

    parts.append('"')
    return "".join(parts)


def _ecmascript_number(value: int | float) -> str:
    if isinstance(value, int):
        if abs(value) > _MAX_SAFE_INTEGER:
            raise TypeError(
                "HF v1 JSON integers outside the JavaScript safe-integer "
                "range require HfV1BigInt"
            )
        return str(value)

    if not math.isfinite(value):
        raise TypeError("HF v1 JSON numbers must be finite")

    if value == 0:
        return "0"

    representation = repr(value)
    sign = ""

    if representation.startswith("-"):
        sign = "-"
        representation = representation[1:]

    if "e" in representation or "E" in representation:
        mantissa, exponent_text = re.split(r"[eE]", representation)
        exponent = int(exponent_text)
        digits = mantissa.replace(".", "").rstrip("0") or "0"
        decimal_exponent = exponent
    elif "." in representation:
        integer, fraction = representation.split(".", 1)
        fraction = fraction.rstrip("0")

        if not fraction:
            return sign + integer

        if integer != "0":
            digits = (integer + fraction).lstrip("0")
            decimal_exponent = len(integer) - 1
        else:
            leading_zeroes = len(fraction) - len(fraction.lstrip("0"))
            digits = fraction[leading_zeroes:]
            decimal_exponent = -(leading_zeroes + 1)
    else:
        return sign + representation

    if -6 <= decimal_exponent <= 20:
        point = decimal_exponent + 1

        if point <= 0:
            body = "0." + ("0" * -point) + digits
        elif point >= len(digits):
            body = digits + ("0" * (point - len(digits)))
        else:
            body = digits[:point] + "." + digits[point:]

        return sign + body

    mantissa = digits[0]

    if len(digits) > 1:
        mantissa += "." + digits[1:]

    exponent_sign = "+" if decimal_exponent >= 0 else "-"

    return (
        f"{sign}{mantissa}e{exponent_sign}{abs(decimal_exponent)}"
    )


def _utf16_sort_key(value: str) -> bytes:
    return value.encode("utf-16-be", "surrogatepass")


def canonicalize_hf_v1_json(value: object) -> bytes:
    seen: set[int] = set()
    budget_used = 0
    key_count = 0

    def charge_budget(size: int) -> None:
        nonlocal budget_used

        budget_used += size

        if budget_used > MAX_HF_V1_PAYLOAD_BYTES:
            raise ValueError(
                "HF v1 canonical JSON exceeds SDK byte limit"
            )

    def walk(node: object, depth: int) -> str:
        nonlocal key_count

        if depth > _MAX_JSON_DEPTH:
            raise TypeError("HF v1 JSON nesting limit exceeded")

        if node is None:
            charge_budget(4)
            return "null"

        if isinstance(node, str):
            result = _quoted(node)
            charge_budget(len(result.encode("utf-8")))
            return result

        if isinstance(node, bool):
            result = "true" if node else "false"
            charge_budget(len(result))
            return result

        if isinstance(node, HfV1BigInt):
            result = _quoted(str(node.value))
            charge_budget(len(result.encode("utf-8")))
            return result

        if isinstance(node, (int, float)):
            result = _ecmascript_number(node)
            charge_budget(len(result))
            return result

        if type(node) not in (dict, list):
            raise TypeError(
                "HF v1 JSON accepts only plain objects, arrays and "
                "scalar values"
            )

        identity = id(node)

        if identity in seen:
            raise TypeError(
                "HF v1 JSON repeated or circular object reference"
            )

        seen.add(identity)

        if type(node) is list:
            array = cast(list[object], node)

            if len(array) > _MAX_JSON_ARRAY_LENGTH:
                raise ValueError("HF v1 JSON array exceeds SDK limit")

            charge_budget(len(array) + 1 if array else 2)

            return (
                "["
                + ",".join(walk(item, depth + 1) for item in array)
                + "]"
            )

        mapping = cast(dict[object, object], node)

        if any(not isinstance(key, str) for key in mapping):
            raise TypeError("HF v1 JSON object keys must be strings")

        keys = sorted(
            cast(list[str], list(mapping.keys())),
            key=_utf16_sort_key,
        )

        key_count += len(keys)

        if key_count > _MAX_JSON_KEYS:
            raise ValueError("HF v1 JSON key count exceeds SDK limit")

        charge_budget(len(keys) + 1 if keys else 2)

        entries: list[str] = []

        for key in keys:
            field = _quoted(key)
            charge_budget(len(field.encode("utf-8")) + 1)
            entries.append(
                f"{field}:{walk(mapping[key], depth + 1)}"
            )

        return "{" + ",".join(entries) + "}"

    return walk(value, 0).encode("utf-8")


def normalize_hf_v1_domain(domain: object) -> str:
    if not isinstance(domain, str):
        raise TypeError("HF v1 domain must be a string")

    normalized = domain.strip(_ECMASCRIPT_TRIM)

    if _DOMAIN_RE.fullmatch(normalized) is None:
        raise TypeError("Invalid HF v1 domain")

    return normalized


def frame_hf_v1(domain: str, payload: BytesLike) -> bytes:
    normalized = normalize_hf_v1_domain(domain)

    if not isinstance(payload, (bytes, bytearray, memoryview)):
        raise TypeError("HF v1 payload must be bytes")

    payload_bytes = bytes(payload)

    if len(payload_bytes) > MAX_HF_V1_PAYLOAD_BYTES:
        raise ValueError("HF v1 payload exceeds SDK byte limit")

    domain_bytes = normalized.encode("utf-8")

    header = (
        _FRAME_MAGIC
        + b"\x00"
        + len(domain_bytes).to_bytes(2, "big")
        + domain_bytes
        + len(payload_bytes).to_bytes(4, "big")
    )

    return header + payload_bytes


def _payload_bytes(material: Mapping[str, object]) -> bytes:
    kind = material.get("material")

    if kind == "json":
        return canonicalize_hf_v1_json(material.get("value"))

    if kind == "utf8":
        text = material.get("text")

        if not isinstance(text, str):
            raise TypeError("HF v1 UTF-8 material must be a string")

        data = _node_utf8_bytes(text)

        if len(data) > MAX_HF_V1_PAYLOAD_BYTES:
            raise ValueError("HF v1 text exceeds SDK byte limit")

        return data

    if kind == "raw":
        raw = material.get("bytes")

        if not isinstance(raw, (bytes, bytearray, memoryview)):
            raise TypeError("HF v1 raw material must be bytes")

        return bytes(raw)

    raise TypeError("Unsupported HF v1 material kind")


def hash_hf_v1(input: Mapping[str, object]) -> str:
    payload = _payload_bytes(input)

    return sha3_512_hex(
        frame_hf_v1(
            cast(str, input.get("domain")),
            payload,
        )
    )


def verify_hf_v1_digest(
    *,
    expected: object,
    evidence: object,
) -> HfV1DigestVerificationResult:
    if (
        not isinstance(expected, Mapping)
        or expected.get("kind") != "digest"
        or expected.get("contract") != HF_V1_CONTRACT_ID
    ):
        raise TypeError(
            "Expected an hf-contract-v1 digest commitment"
        )

    expected_digest = normalize_sha3_512_digest(
        expected.get("digest")
    )
    domain = normalize_hf_v1_domain(expected.get("domain"))

    material_value = expected.get("material")

    if material_value not in ("json", "raw", "utf8"):
        raise TypeError("Unsupported HF v1 material kind")

    material = cast(HfV1MaterialKind, material_value)

    if (
        not isinstance(evidence, Mapping)
        or evidence.get("material") != material
    ):
        return HfV1DigestVerificationResult(
            outcome="fail",
            reason_code="HF_MATERIAL_MISMATCH",
            contract=HF_V1_CONTRACT_ID,
            material=material,
            domain=domain,
            expected_digest=expected_digest,
            computed_digest=None,
        )

    hash_input = dict(evidence)
    hash_input["domain"] = domain

    computed = hash_hf_v1(hash_input)
    matches = expected_digest == computed

    return HfV1DigestVerificationResult(
        outcome="pass" if matches else "fail",
        reason_code=None if matches else "DIGEST_MISMATCH",
        contract=HF_V1_CONTRACT_ID,
        material=material,
        domain=domain,
        expected_digest=expected_digest,
        computed_digest=computed,
    )