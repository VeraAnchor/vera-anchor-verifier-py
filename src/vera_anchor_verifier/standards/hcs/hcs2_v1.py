"""Pinned HCS-2 registry memo and historical register verification."""

import json
import re
from dataclasses import dataclass
from typing import Literal, Never, cast

_TOPIC_ID_RE = re.compile(r"^0\.0\.[0-9]+$", re.ASCII)
_MEMO_RE = re.compile(r"^hcs-2:(0|1):([0-9]+)$", re.ASCII)
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_MAX_MESSAGE_BYTES = 1024
_MAX_TTL = 31_536_000
_ALLOWED_KEYS = frozenset({"p", "op", "t_id", "metadata", "m"})


@dataclass(frozen=True, slots=True)
class Hcs2V1Memo:
    memo: str
    indexed: bool
    ttl: int


@dataclass(frozen=True, slots=True)
class Hcs2V1Register:
    p: Literal["hcs-2"]
    op: Literal["register"]
    t_id: str
    metadata: str | None = None
    m: str | None = None


@dataclass(frozen=True, slots=True)
class Hcs2V1VerificationInput:
    memo: object
    message: str | bytes | bytearray | memoryview
    expected_t_id: str | None = None


@dataclass(frozen=True, slots=True)
class Hcs2V1VerificationResult:
    status: Literal["pass", "fail"]
    reason_code: str | None
    memo: Hcs2V1Memo | None
    register: Hcs2V1Register | None
    target_match: Literal["match", "not_checked", "mismatch"]


class Hcs2V1Error(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _invalid(code: str) -> Never:
    raise Hcs2V1Error(code)


def parse_hcs2_memo_v1(value: object) -> Hcs2V1Memo:
    """Parse a pinned HCS-2 registry topic memo."""
    if not isinstance(value, str) or len(value) > 256:
        _invalid("HCS2_MEMO_INVALID")

    memo = value.strip()
    match = _MEMO_RE.fullmatch(memo)
    if match is None:
        _invalid("HCS2_MEMO_INVALID")

    ttl = int(match.group(2))
    if ttl > _MAX_TTL:
        _invalid("HCS2_TTL_INVALID")

    return Hcs2V1Memo(memo=memo, indexed=match.group(1) == "0", ttl=ttl)


def _topic_id(value: object) -> str:
    if not isinstance(value, str) or len(value) > 128:
        _invalid("HCS2_TOPIC_INVALID")

    topic = value.strip()
    if _TOPIC_ID_RE.fullmatch(topic) is None:
        _invalid("HCS2_TOPIC_INVALID")
    return topic


def _optional_text(value: object, maximum: int) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        _invalid("HCS2_TEXT_INVALID")

    text = value.strip()
    if not text:
        return None
    if len(text) > maximum or _CONTROL_RE.search(text) is not None:
        _invalid("HCS2_TEXT_INVALID")
    return text


def _pairs_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            _invalid("HCS2_MESSAGE_INVALID")
        result[key] = value
    return result


def _message_bytes(message: object) -> bytes:
    if isinstance(message, str):
        if len(message) > _MAX_MESSAGE_BYTES:
            _invalid("HCS2_MESSAGE_TOO_LARGE")
        try:
            return message.encode("utf-8", errors="strict")
        except UnicodeEncodeError:
            _invalid("HCS2_MESSAGE_INVALID")

    if isinstance(message, (bytes, bytearray, memoryview)):
        return bytes(message)
    _invalid("HCS2_MESSAGE_INVALID")


def _parse_flat_register(message: object) -> dict[str, object]:
    raw = _message_bytes(message)
    if len(raw) > _MAX_MESSAGE_BYTES:
        _invalid("HCS2_MESSAGE_TOO_LARGE")
    if len(raw) < 2:
        _invalid("HCS2_MESSAGE_INVALID")

    try:
        text = raw.decode("utf-8", errors="strict")
        parsed = json.loads(
            text,
            object_pairs_hook=_pairs_object,
            parse_constant=lambda _: _invalid("HCS2_MESSAGE_INVALID"),
        )
    except Hcs2V1Error:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError):
        _invalid("HCS2_MESSAGE_INVALID")

    if type(parsed) is not dict:
        _invalid("HCS2_MESSAGE_INVALID")

    record = cast(dict[str, object], parsed)
    if not record or any(key not in _ALLOWED_KEYS for key in record):
        _invalid("HCS2_MESSAGE_INVALID")
    if any(
        value is not None and not isinstance(value, str) for value in record.values()
    ):
        _invalid("HCS2_MESSAGE_INVALID")
    return record


def parse_hcs2_register_v1(message: object) -> Hcs2V1Register:
    """Parse one supported HCS-2 register operation."""
    record = _parse_flat_register(message)
    if record.get("p") != "hcs-2" or record.get("op") != "register":
        _invalid("HCS2_OPERATION_INVALID")

    t_id = _topic_id(record.get("t_id"))
    metadata = _optional_text(record.get("metadata"), 4096)
    m = _optional_text(record.get("m"), 500)
    normalized = {"p": "hcs-2", "op": "register", "t_id": t_id}
    if metadata is not None:
        normalized["metadata"] = metadata
    if m is not None:
        normalized["m"] = m

    normalized_bytes = json.dumps(
        normalized,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    if len(normalized_bytes) > _MAX_MESSAGE_BYTES:
        _invalid("HCS2_MESSAGE_TOO_LARGE")

    return Hcs2V1Register(p="hcs-2", op="register", t_id=t_id, metadata=metadata, m=m)


def verify_hcs2_register_v1(
    input: Hcs2V1VerificationInput,
) -> Hcs2V1VerificationResult:
    """Verify one pinned historical HCS-2 register operation."""
    memo: Hcs2V1Memo | None = None
    register: Hcs2V1Register | None = None

    try:
        memo = parse_hcs2_memo_v1(input.memo)
        register = parse_hcs2_register_v1(input.message)

        if input.expected_t_id is not None:
            expected = _topic_id(input.expected_t_id)
            if expected != register.t_id:
                return Hcs2V1VerificationResult(
                    status="fail",
                    reason_code="HCS2_TARGET_MISMATCH",
                    memo=memo,
                    register=register,
                    target_match="mismatch",
                )
            target_match: Literal["match", "not_checked"] = "match"
        else:
            target_match = "not_checked"

        return Hcs2V1VerificationResult(
            status="pass",
            reason_code=None,
            memo=memo,
            register=register,
            target_match=target_match,
        )
    except Hcs2V1Error as exc:
        return Hcs2V1VerificationResult(
            status="fail",
            reason_code=exc.code,
            memo=memo,
            register=register,
            target_match="not_checked",
        )