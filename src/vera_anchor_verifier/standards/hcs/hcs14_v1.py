"""Pinned HCS-14 deterministic DID-backed UAID checks."""

import re
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Literal, Never

_DID_RE = re.compile(r"^did:([a-z0-9]+):(.+)$", re.ASCII)
_CONTROL_OR_SEMICOLON_RE = re.compile(r"[\x00-\x1f\x7f;]")
_ID_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_SRC_RE = re.compile(r"^z[1-9A-HJ-NP-Za-km-z]+$", re.ASCII)

_PREFIX = "uaid:did:"
_ORDER = ("uid", "registry", "proto", "nativeId", "domain", "src")
_REQUIRED = ("uid", "registry", "proto", "nativeId")
_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_BASE58_INDEX = {char: index for index, char in enumerate(_ALPHABET)}


@dataclass(frozen=True, slots=True)
class Hcs14DidUaidV1:
    uaid: str
    target: Literal["did"]
    id: str
    params: Mapping[str, str]


@dataclass(frozen=True, slots=True)
class Hcs14BindingV1Result:
    status: Literal["pass", "fail"]
    reason_code: str | None
    binding: Hcs14DidUaidV1 | None


@dataclass(frozen=True, slots=True)
class _DidParts:
    did: str
    id: str
    sanitized: bool


class Hcs14V1Error(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _fail(code: str) -> Never:
    raise Hcs14V1Error(code)


def _text(value: object, maximum: int) -> str:
    if not isinstance(value, str):
        _fail("HCS14_FIELD_INVALID")

    text = value.strip()
    if (
        not text
        or len(text) > maximum
        or _CONTROL_OR_SEMICOLON_RE.search(value) is not None
    ):
        _fail("HCS14_FIELD_INVALID")

    return text


def _did_parts(value: object) -> _DidParts:
    if not isinstance(value, str):
        _fail("HCS14_DID_INVALID")

    did = value.strip()
    match = _DID_RE.fullmatch(did)
    if match is None:
        _fail("HCS14_DID_INVALID")

    method_specific_id = match.group(2)
    positions = [
        position
        for marker in (";", "?", "#")
        if (position := method_specific_id.find(marker)) >= 0
    ]
    cut = min(positions) if positions else -1
    identifier = method_specific_id if cut < 0 else method_specific_id[:cut]

    if not identifier or ";" in identifier:
        _fail("HCS14_DID_ID_INVALID")

    return _DidParts(did=did, id=identifier, sanitized=cut >= 0)


def _base58_encode(value: bytes) -> str:
    leading = 0
    while leading < len(value) and value[leading] == 0:
        leading += 1

    number = int.from_bytes(value, "big")
    encoded = ""

    while number > 0:
        number, remainder = divmod(number, 58)
        encoded = _ALPHABET[remainder] + encoded

    suffix = encoded or ("" if leading else "1")
    return f"z{'1' * leading}{suffix}"


def _base58_decode(value: str) -> bytes:
    if _SRC_RE.fullmatch(value) is None:
        _fail("HCS14_SRC_INVALID")

    encoded = value[1:]
    leading = len(encoded) - len(encoded.lstrip("1"))
    number = 0

    for char in encoded:
        digit = _BASE58_INDEX.get(char)
        if digit is None:
            _fail("HCS14_SRC_INVALID")
        number = number * 58 + digit

    body = (
        b""
        if number == 0
        else number.to_bytes((number.bit_length() + 7) // 8, "big")
    )
    result = b"\x00" * leading + body

    if _base58_encode(result) != value:
        _fail("HCS14_SRC_INVALID")

    return result


def parse_hcs14_did_uaid_v1(value: object) -> Hcs14DidUaidV1:
    """Parse the pinned uaid:did form.

    Structural consistency does not authenticate DID control.
    """
    if not isinstance(value, str) or len(value) > 8192:
        _fail("HCS14_UAID_INVALID")

    uaid = value.strip()
    if not uaid.startswith(_PREFIX):
        if uaid.startswith("uaid:aid:"):
            _fail("HCS14_TARGET_UNSUPPORTED")
        _fail("HCS14_UAID_INVALID")

    if len(uaid) > 8192:
        _fail("HCS14_UAID_INVALID")

    body = uaid[len(_PREFIX) :]
    position = body.find(";")
    if position < 1:
        _fail("HCS14_UAID_INVALID")

    identifier = body[:position]
    if _ID_CONTROL_RE.search(identifier) is not None:
        _fail("HCS14_UAID_INVALID")

    params: dict[str, str] = {}
    seen: list[str] = []

    for entry in body[position + 1 :].split(";"):
        equals = entry.find("=")
        if equals <= 0:
            _fail("HCS14_PARAMETER_INVALID")

        key = entry[:equals]
        if key not in _ORDER or key in params:
            _fail("HCS14_PARAMETER_INVALID")

        limit = 2048 if key == "nativeId" else 512
        params[key] = _text(entry[equals + 1 :], limit)
        seen.append(key)

    expected_order = [key for key in _ORDER if key in params]
    if seen != expected_order:
        _fail("HCS14_PARAMETER_ORDER_INVALID")

    if any(not params.get(key) for key in _REQUIRED):
        _fail("HCS14_PARAMETER_MISSING")

    return Hcs14DidUaidV1(
        uaid=uaid,
        target="did",
        id=identifier,
        params=MappingProxyType(dict(params)),
    )


def build_hcs14_did_uaid_v1(
    *,
    base_did: str,
    proto: str,
    native_id: str,
    uid: str = "0",
    registry: str = "self",
    domain: str | None = None,
) -> Hcs14DidUaidV1:
    """Build a deterministic UAID from supplied DID material.

    This does not issue or authenticate an identity.
    """
    did = _did_parts(base_did)
    params: dict[str, str] = {
        "uid": _text(uid, 256),
        "registry": _text(registry, 128),
        "proto": _text(proto, 64),
        "nativeId": _text(native_id, 2048),
    }

    if domain is not None:
        if not isinstance(domain, str):
            _fail("HCS14_FIELD_INVALID")
        if domain.strip():
            params["domain"] = _text(domain, 253)

    if did.sanitized:
        params["src"] = _base58_encode(did.did.encode("utf-8"))

    encoded_params = ";".join(
        f"{key}={params[key]}" for key in _ORDER if key in params
    )
    return parse_hcs14_did_uaid_v1(f"{_PREFIX}{did.id};{encoded_params}")


def verify_hcs14_did_binding_v1(
    *,
    uaid: object,
    base_did: object,
) -> Hcs14BindingV1Result:
    """Compare supplied UAID and DID structurally.

    This does not resolve or authenticate DID controller control.
    """
    binding: Hcs14DidUaidV1 | None = None

    try:
        binding = parse_hcs14_did_uaid_v1(uaid)
        did = _did_parts(base_did)

        if binding.id != did.id:
            _fail("HCS14_DID_BINDING_MISMATCH")

        src = binding.params.get("src")
        if did.sanitized:
            if not src:
                _fail("HCS14_SRC_REQUIRED")

            recovered_bytes = _base58_decode(src)
            try:
                recovered = recovered_bytes.decode("utf-8", errors="strict")
            except UnicodeDecodeError:
                _fail("HCS14_SRC_INVALID")

            if recovered != did.did:
                _fail("HCS14_SRC_MISMATCH")

        elif src:
            _fail("HCS14_SRC_UNEXPECTED")

        return Hcs14BindingV1Result(
            status="pass",
            reason_code=None,
            binding=binding,
        )
    except Hcs14V1Error as exc:
        return Hcs14BindingV1Result(
            status="fail",
            reason_code=exc.code,
            binding=binding,
        )