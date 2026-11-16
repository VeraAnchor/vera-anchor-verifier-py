"""Pinned HCS-11 Draft 1.1 AI-agent profile verification."""

import hashlib
import json
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Literal, Never, cast

from .hcs14_v1 import (
    Hcs14V1Error,
    parse_hcs14_did_uaid_v1,
    verify_hcs14_did_binding_v1,
)

MAX_HCS11_V1_PROFILE_BYTES = 128 * 1024
_MAX_SAFE_INTEGER = (1 << 53) - 1

_REF_RE = re.compile(r"^hcs://(1|2)/(0\.0\.[0-9]+)$", re.ASCII)
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_TOP_KEYS = frozenset(
    {
        "version",
        "type",
        "display_name",
        "uaid",
        "alias",
        "bio",
        "profileImage",
        "properties",
        "aiAgent",
    }
)
_AGENT_KEYS = frozenset({"type", "capabilities", "model", "creator"})


@dataclass(frozen=True, slots=True)
class Hcs11V1Memo:
    memo: str
    profile_reference: str
    protocol: Literal["hcs-1", "hcs-2"]
    topic_id: str


@dataclass(frozen=True, slots=True)
class _Hcs11AiAgentV1:
    type: Literal[0, 1]
    capabilities: tuple[int, ...]
    model: str
    creator: str | None = None


@dataclass(frozen=True, slots=True)
class Hcs11V1Profile:
    version: str
    type: Literal[1]
    display_name: str
    uaid: str
    alias: str | None
    bio: str | None
    profileImage: str | None
    properties: Mapping[str, object] | None
    aiAgent: _Hcs11AiAgentV1


@dataclass(frozen=True, slots=True)
class Hcs11V1Input:
    profile: str | bytes | bytearray | memoryview
    expected_sha256: str | None = None
    expected_uaid: str | None = None
    expected_base_did: str | None = None
    account_memo: str | None = None
    expected_profile_reference: str | None = None


@dataclass(frozen=True, slots=True)
class Hcs11V1Result:
    status: Literal["pass", "fail", "unsupported"]
    reason_code: str | None
    profile: Hcs11V1Profile | None
    sha256: str | None
    account_memo: Hcs11V1Memo | None
    memo_reference_match: Literal["match", "mismatch", "not_checked"]


class Hcs11V1Error(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _fail(code: str) -> Never:
    raise Hcs11V1Error(code)


def _js_length(value: str) -> int:
    return len(value.encode("utf-16-le", "surrogatepass")) // 2


def _trim(value: str) -> str:
    return value.strip().strip("\ufeff")


def _record(value: object) -> dict[str, object]:
    if type(value) is not dict:
        _fail("HCS11_FIELD_INVALID")
    return cast(dict[str, object], value)


def _keys_only(value: Mapping[str, object], allowed: frozenset[str]) -> None:
    if any(key not in allowed for key in value):
        _fail("HCS11_FIELD_UNSUPPORTED")


def _required_text(value: object, maximum: int) -> str:
    if not isinstance(value, str):
        _fail("HCS11_FIELD_INVALID")
    text = _trim(value)
    if not text or _js_length(text) > maximum or _CONTROL_RE.search(text) is not None:
        _fail("HCS11_FIELD_INVALID")
    return text


def _optional_text(value: object, maximum: int) -> str | None:
    if value is None or value == "":
        return None
    if isinstance(value, str) and not _trim(value):
        return None
    return _required_text(value, maximum)


def parse_hcs11_account_memo_v1(value: object) -> Hcs11V1Memo:
    """
    Parse an HCS-11 account memo.

    This does not assert account ownership.
    """
    if not isinstance(value, str):
        _fail("HCS11_MEMO_INVALID")
    if _js_length(value) > 4096:
        _fail("HCS11_MEMO_TOO_LARGE")

    memo = _trim(value)
    if not memo.startswith("hcs-11:"):
        _fail("HCS11_MEMO_INVALID")
    if len(memo.encode("utf-8")) > 100:
        _fail("HCS11_MEMO_TOO_LARGE")

    reference = memo[7:]
    match = _REF_RE.fullmatch(reference)
    if match is None:
        _fail("HCS11_PROFILE_REF_INVALID")

    protocol: Literal["hcs-1", "hcs-2"] = (
        "hcs-1" if match.group(1) == "1" else "hcs-2"
    )
    return Hcs11V1Memo(
        memo=memo,
        profile_reference=reference,
        protocol=protocol,
        topic_id=match.group(2),
    )


def _pairs_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            _fail("HCS11_PROFILE_JSON_INVALID")
        result[key] = value
    return result


def _invalid_json_constant(_value: str) -> Never:
    _fail("HCS11_PROFILE_JSON_INVALID")


def _parse_js_number(value: str) -> float:
    return float(value)


def _freeze_json(value: object, depth: int = 0) -> object:
    if depth > 32:
        _fail("HCS11_PROFILE_TOO_LARGE")
    if type(value) is dict:
        record = cast(dict[str, object], value)
        return MappingProxyType(
            {key: _freeze_json(child, depth + 1) for key, child in record.items()}
        )
    if type(value) is list:
        return tuple(
            _freeze_json(child, depth + 1) for child in cast(list[object], value)
        )
    return value


def _js_number(value: object) -> float:
    if value is None:
        return 0.0
    if isinstance(value, bool):
        return 1.0 if value else 0.0
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    if isinstance(value, str):
        text = _trim(value)
        if not text:
            return 0.0
        try:
            lowered = text.lower()
            if lowered.startswith(("0x", "+0x", "-0x")):
                sign = -1 if lowered.startswith("-") else 1
                digits = lowered[3:] if lowered[0] in "+-" else lowered[2:]
                return float(sign * int(digits, 16))
            if lowered.startswith(("0b", "+0b", "-0b")):
                sign = -1 if lowered.startswith("-") else 1
                digits = lowered[3:] if lowered[0] in "+-" else lowered[2:]
                return float(sign * int(digits, 2))
            if lowered.startswith(("0o", "+0o", "-0o")):
                sign = -1 if lowered.startswith("-") else 1
                digits = lowered[3:] if lowered[0] in "+-" else lowered[2:]
                return float(sign * int(digits, 8))
            return float(text)
        except ValueError:
            return math.nan
    return math.nan


def _capabilities(value: object) -> tuple[int, ...]:
    if type(value) is not list:
        _fail("HCS11_CAPABILITIES_INVALID")

    output: list[int] = []
    for item in cast(list[object], value):
        number = _js_number(item)
        if (
            not math.isfinite(number)
            or not number.is_integer()
            or number < 0
            or number > _MAX_SAFE_INTEGER
        ):
            _fail("HCS11_CAPABILITIES_INVALID")
        output.append(int(number))

    if len(set(output)) != len(output):
        _fail("HCS11_CAPABILITIES_INVALID")
    output.sort()
    return tuple(output)


def parse_hcs11_ai_agent_profile_v1(value: object) -> Hcs11V1Profile:
    """
    Parse and normalize one HCS-11 Draft 1.1 AI-agent profile.

    The supplied profile is caller-provided offline material.
    """
    if isinstance(value, str):
        if _js_length(value) > MAX_HCS11_V1_PROFILE_BYTES:
            _fail("HCS11_PROFILE_TOO_LARGE")
        try:
            raw = value.encode("utf-8", errors="strict")
        except UnicodeEncodeError:
            _fail("HCS11_PROFILE_JSON_INVALID")
    elif isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
    else:
        _fail("HCS11_PROFILE_JSON_INVALID")

    if not raw:
        _fail("HCS11_PROFILE_JSON_INVALID")
    if len(raw) > MAX_HCS11_V1_PROFILE_BYTES:
        _fail("HCS11_PROFILE_TOO_LARGE")

    try:
        source = raw.decode("utf-8", errors="strict")
        parsed = json.loads(
            source,
            object_pairs_hook=_pairs_object,
            parse_int=_parse_js_number,
            parse_float=_parse_js_number,
            parse_constant=_invalid_json_constant,
        )
    except Hcs11V1Error:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError):
        _fail("HCS11_PROFILE_JSON_INVALID")

    obj = _record(parsed)
    _keys_only(obj, _TOP_KEYS)
    if obj.get("type") != 1:
        _fail("HCS11_PROFILE_TYPE_UNSUPPORTED")

    uaid = _required_text(obj.get("uaid"), 4096)
    parse_hcs14_did_uaid_v1(uaid)

    agent = _record(obj.get("aiAgent"))
    _keys_only(agent, _AGENT_KEYS)
    if agent.get("type") not in (0, 1):
        _fail("HCS11_AGENT_TYPE_INVALID")

    agent_type: Literal[0, 1] = 0 if agent.get("type") == 0 else 1
    capabilities = _capabilities(agent.get("capabilities"))
    alias = _optional_text(obj.get("alias"), 256)
    bio = _optional_text(obj.get("bio"), 4096)
    profile_image = _optional_text(obj.get("profileImage"), 4096)
    creator = _optional_text(agent.get("creator"), 256)

    properties: Mapping[str, object] | None = None
    if obj.get("properties") is not None:
        properties_obj = _record(obj.get("properties"))
        frozen = _freeze_json(properties_obj)
        if not isinstance(frozen, Mapping):
            _fail("HCS11_FIELD_INVALID")
        properties = cast(Mapping[str, object], frozen)

    version = _required_text(obj.get("version", "1.1"), 32)
    display_name = _required_text(obj.get("display_name"), 128)
    model = _required_text(agent.get("model"), 256)
    return Hcs11V1Profile(
        version=version,
        type=1,
        display_name=display_name,
        uaid=uaid,
        alias=alias,
        bio=bio,
        profileImage=profile_image,
        properties=properties,
        aiAgent=_Hcs11AiAgentV1(
            type=agent_type,
            capabilities=capabilities,
            model=model,
            creator=creator,
        ),
    )


def _has_unpaired_surrogate(value: str) -> bool:
    index = 0
    while index < len(value):
        code = ord(value[index])
        if 55296 <= code <= 56319:
            if index + 1 >= len(value):
                return True
            next_code = ord(value[index + 1])
            if not 56320 <= next_code <= 57343:
                return True
            index += 2
            continue
        if 56320 <= code <= 57343:
            return True
        index += 1
    return False


def _quote_string(value: str) -> str:
    if _has_unpaired_surrogate(value):
        _fail("HCS11_CANONICALIZATION_FAILED")
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _normalize_exponent_form(value: str) -> str:
    mantissa, exponent_raw = value.lower().split("e", 1)
    if "." in mantissa:
        mantissa = mantissa.rstrip("0").rstrip(".")
    exponent = int(exponent_raw)
    sign = "+" if exponent >= 0 else "-"
    return f"{mantissa}e{sign}{abs(exponent)}"


def _expand_scientific_to_plain(value: str) -> str:
    mantissa, exponent_raw = value.lower().split("e", 1)
    exponent = int(exponent_raw)
    negative = mantissa.startswith("-")
    if negative:
        mantissa = mantissa[1:]

    if "." in mantissa:
        integer, fraction = mantissa.split(".", 1)
    else:
        integer = mantissa
        fraction = ""

    digits = integer + fraction
    position = len(integer) + exponent
    if position <= 0:
        output = "0." + "0" * -position + digits
    elif position >= len(digits):
        output = digits + "0" * (position - len(digits))
    else:
        output = digits[:position] + "." + digits[position:]

    if "." in output:
        output = output.rstrip("0").rstrip(".")
    if negative and output != "0":
        output = "-" + output
    return output or "0"


def _js_number_text(value: float) -> str:
    if not math.isfinite(value):
        _fail("HCS11_CANONICALIZATION_FAILED")
    if value == 0:
        return "0"

    text = repr(value)
    if "e" in text.lower():
        exponent = int(text.lower().split("e", 1)[1])
        if -6 <= exponent < 21:
            return _expand_scientific_to_plain(text)
        return _normalize_exponent_form(text)
    if text.endswith(".0"):
        return text[:-2]
    return text


def _js_utf16_sort_key(value: str) -> bytes:
    return value.encode("utf-16-be", "surrogatepass")


def _canonical(
    value: object,
    depth: int = 0,
    seen: set[int] | None = None,
) -> str:
    if depth > 32:
        _fail("HCS11_CANONICALIZATION_FAILED")
    if seen is None:
        seen = set()
    if value is None:
        return "null"
    if isinstance(value, str):
        return _quote_string(value)
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return _js_number_text(float(value))

    identity = id(value)
    if identity in seen:
        _fail("HCS11_CANONICALIZATION_FAILED")
    seen.add(identity)
    try:
        if isinstance(value, tuple):
            return (
                "["
                + ",".join(_canonical(item, depth + 1, seen) for item in value)
                + "]"
            )
        if isinstance(value, Mapping):
            keys = list(value.keys())
            if any(not isinstance(key, str) for key in keys):
                _fail("HCS11_CANONICALIZATION_FAILED")
            string_keys = cast(list[str], keys)
            string_keys.sort(key=_js_utf16_sort_key)
            fields = [
                f"{_quote_string(key)}:{_canonical(value[key], depth + 1, seen)}"
                for key in string_keys
            ]
            return "{" + ",".join(fields) + "}"
    finally:
        seen.discard(identity)

    _fail("HCS11_CANONICALIZATION_FAILED")


def _profile_material(profile: Hcs11V1Profile) -> dict[str, object]:
    material: dict[str, object] = {
        "version": profile.version,
        "type": profile.type,
        "display_name": profile.display_name,
        "uaid": profile.uaid,
        "aiAgent": {
            "type": profile.aiAgent.type,
            "capabilities": profile.aiAgent.capabilities,
            "model": profile.aiAgent.model,
        },
    }
    if profile.alias is not None:
        material["alias"] = profile.alias
    if profile.bio is not None:
        material["bio"] = profile.bio
    if profile.profileImage is not None:
        material["profileImage"] = profile.profileImage
    if profile.properties is not None:
        material["properties"] = profile.properties
    if profile.aiAgent.creator is not None:
        agent = cast(dict[str, object], material["aiAgent"])
        agent["creator"] = profile.aiAgent.creator
    return material


def verify_hcs11_ai_agent_profile_v1(input: Hcs11V1Input) -> Hcs11V1Result:
    """
    Verify normalized HCS-11 content.

    This does not assert account ownership, DID control, or publication.
    """
    profile: Hcs11V1Profile | None = None
    memo: Hcs11V1Memo | None = None
    sha256: str | None = None
    memo_match: Literal["match", "mismatch", "not_checked"] = "not_checked"

    def output(
        status: Literal["pass", "fail", "unsupported"],
        reason: str | None,
    ) -> Hcs11V1Result:
        return Hcs11V1Result(
            status=status,
            reason_code=reason,
            profile=profile,
            sha256=sha256,
            account_memo=memo,
            memo_reference_match=memo_match,
        )

    try:
        profile = parse_hcs11_ai_agent_profile_v1(input.profile)
        if profile.version != "1.1":
            return output("unsupported", "HCS11_VERSION_UNSUPPORTED")

        canonical_bytes = _canonical(_profile_material(profile)).encode("utf-8")
        if len(canonical_bytes) > MAX_HCS11_V1_PROFILE_BYTES:
            _fail("HCS11_PROFILE_TOO_LARGE")
        sha256 = hashlib.sha256(canonical_bytes).hexdigest()

        raw_expected: object = input.expected_sha256
        if raw_expected is not None:
            if (
                not isinstance(raw_expected, str)
                or _SHA256_RE.fullmatch(raw_expected) is None
            ):
                _fail("HCS11_EXPECTED_CHECKSUM_INVALID")
            if sha256 != raw_expected:
                _fail("HCS11_CHECKSUM_MISMATCH")

        if input.expected_uaid is not None and profile.uaid != input.expected_uaid:
            _fail("HCS11_UAID_MISMATCH")

        if input.expected_base_did is not None:
            binding = verify_hcs14_did_binding_v1(
                uaid=profile.uaid,
                base_did=input.expected_base_did,
            )
            if binding.status != "pass":
                _fail(binding.reason_code or "HCS14_DID_BINDING_MISMATCH")

        if input.account_memo is not None:
            memo = parse_hcs11_account_memo_v1(input.account_memo)
            if input.expected_profile_reference is not None:
                memo_match = (
                    "match"
                    if memo.profile_reference == input.expected_profile_reference
                    else "mismatch"
                )
                if memo_match == "mismatch":
                    _fail("HCS11_PROFILE_REFERENCE_MISMATCH")
        elif input.expected_profile_reference is not None:
            _fail("HCS11_ACCOUNT_MEMO_UNAVAILABLE")

        return output("pass", None)
    except (Hcs11V1Error, Hcs14V1Error) as exc:
        return output("fail", exc.code)