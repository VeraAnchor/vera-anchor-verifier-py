"""Deterministic execution-verification recomputation primitives."""

import json
import math
import re
from datetime import UTC, datetime, timedelta

from ...crypto import sha3_512_hex

_MAX_DEPTH = 64
_MAX_SAFE_INTEGER = (1 << 53) - 1
_NANOS_PER_SECOND = 1_000_000_000
_NANOS_PER_MILLISECOND = 1_000_000

_UTC_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})[T ]"
    r"(\d{2}):(\d{2}):(\d{2})"
    r"(?:\.(\d{1,9}))?"
    r"(?:Z|\+00(?::?00)?)$",
    re.ASCII,
)
_HEDERA_RE = re.compile(r"^(\d{1,20})\.(\d{9})$", re.ASCII)
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


def _paired_string(value: str, path: str) -> str:
    try:
        return value.encode("utf-16-le", "surrogatepass").decode("utf-16-le", "strict")
    except UnicodeDecodeError as exc:
        raise TypeError(f"Unpaired UTF-16 surrogate at {path}.") from exc


def _js_sort_key(value: str) -> tuple[int, ...]:
    encoded = value.encode("utf-16-be", "surrogatepass")
    return tuple(
        int.from_bytes(encoded[index : index + 2], "big")
        for index in range(0, len(encoded), 2)
    )


def _normalize_exponent(value: str) -> str:
    mantissa, raw_exponent = value.lower().split("e", 1)
    if "." in mantissa:
        mantissa = mantissa.rstrip("0").rstrip(".")
    exponent = int(raw_exponent)
    sign = "+" if exponent >= 0 else "-"
    return f"{mantissa}e{sign}{abs(exponent)}"


def _expand_scientific(value: str) -> str:
    mantissa, raw_exponent = value.lower().split("e", 1)
    exponent = int(raw_exponent)
    negative = mantissa.startswith("-")
    if negative:
        mantissa = mantissa[1:]

    if "." in mantissa:
        integer, fraction = mantissa.split(".", 1)
    else:
        integer = mantissa
        fraction = ""

    digits = integer + fraction
    point = len(integer) + exponent
    if point <= 0:
        rendered = "0." + ("0" * (-point)) + digits
    elif point >= len(digits):
        rendered = digits + ("0" * (point - len(digits)))
    else:
        rendered = digits[:point] + "." + digits[point:]

    if "." in rendered:
        rendered = rendered.rstrip("0").rstrip(".")
    if not rendered:
        rendered = "0"
    if negative and rendered != "0":
        rendered = "-" + rendered
    return rendered


def _json_number(value: int | float) -> str:
    if isinstance(value, int):
        if -_MAX_SAFE_INTEGER <= value <= _MAX_SAFE_INTEGER:
            return str(value)
        try:
            value = float(value)
        except OverflowError as exc:
            raise TypeError("Non-finite canonical JSON number") from exc

    if not math.isfinite(value):
        raise TypeError("Non-finite canonical JSON number")
    if value == 0:
        return "0"

    rendered = repr(value)
    if "e" in rendered or "E" in rendered:
        exponent = int(rendered.lower().split("e", 1)[1])
        if -6 <= exponent < 21:
            return _expand_scientific(rendered)
        return _normalize_exponent(rendered)

    if rendered.endswith(".0"):
        return rendered[:-2]
    return rendered


def _canonical(value: object, path: str, depth: int) -> str:
    if depth > _MAX_DEPTH:
        raise TypeError(f"Maximum canonical JSON depth exceeded at {path}.")
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"

    if isinstance(value, (int, float)):
        try:
            return _json_number(value)
        except TypeError as exc:
            raise TypeError(f"Non-finite canonical JSON number at {path}.") from exc

    if isinstance(value, str):
        checked = _paired_string(value, path)
        return json.dumps(checked, ensure_ascii=False, separators=(",", ":"))

    if isinstance(value, list):
        return (
            "["
            + ",".join(
                _canonical(item, f"{path}[{index}]", depth + 1)
                for index, item in enumerate(value)
            )
            + "]"
        )

    if type(value) is not dict:
        raise TypeError(f"Unsupported canonical JSON value at {path}.")

    row = value
    if not all(isinstance(key, str) for key in row):
        raise TypeError(f"Unsupported canonical JSON value at {path}.")

    parts: list[str] = []
    for key in sorted(row, key=_js_sort_key):
        checked_key = _paired_string(key, f"{path}.{{key}}")
        parts.append(
            json.dumps(checked_key, ensure_ascii=False, separators=(",", ":"))
            + ":"
            + _canonical(row[key], f"{path}.{key}", depth + 1)
        )
    return "{" + ",".join(parts) + "}"


def canonicalize_execution_verification_value(value: object) -> str:
    """Canonicalize using the frozen execution-verification JSON contract."""
    return _canonical(value, "$", 0)


def compute_execution_domain_separated_sha3_512(
    domain_separator: str,
    value: object,
) -> str:
    """Hash domain, NUL separator, and canonical execution-verification JSON."""
    if not isinstance(domain_separator, str):
        raise TypeError("Domain separator must be a string")

    canonical = canonicalize_execution_verification_value(value)
    return sha3_512_hex(
        domain_separator.encode("utf-8")
        + b"\x00"
        + canonical.encode("utf-8")
    )


def hedera_consensus_timestamp_nanos(value: object) -> int | None:
    """Parse exact Hedera seconds.nanoseconds without floating-point loss."""
    if not isinstance(value, str):
        return None

    match = _HEDERA_RE.fullmatch(value.strip())
    if match is None:
        return None

    return int(match.group(1)) * _NANOS_PER_SECOND + int(match.group(2))


def _datetime_nanos(value: datetime) -> int | None:
    if value.tzinfo is None:
        return None

    utc = value.astimezone(UTC)
    if utc.year < 1970:
        return None

    delta = utc - _EPOCH
    return (
        (delta.days * 86_400 + delta.seconds) * _NANOS_PER_SECOND
        + delta.microseconds * 1_000
    )


def execution_timestamp_nanos(value: object) -> int | None:
    """Parse exact UTC execution time without rounding fractional seconds."""
    if isinstance(value, datetime):
        return _datetime_nanos(value)
    if not isinstance(value, str):
        return None

    match = _UTC_RE.fullmatch(value.strip())
    if match is None:
        return None

    year = int(match.group(1))
    month = int(match.group(2))
    day = int(match.group(3))
    hour = int(match.group(4))
    minute = int(match.group(5))
    second = int(match.group(6))
    if not 1970 <= year <= 9999:
        return None

    try:
        instant = datetime(
            year,
            month,
            day,
            hour,
            minute,
            second,
            tzinfo=UTC,
        )
    except ValueError:
        return None

    delta = instant - _EPOCH
    whole_seconds = delta.days * 86_400 + delta.seconds
    fraction = (match.group(7) or "").ljust(9, "0")
    return whole_seconds * _NANOS_PER_SECOND + int(fraction or "0")


def execution_timestamp_iso(value: object) -> str | None:
    """Normalize a supported execution timestamp to millisecond UTC ISO form."""
    nanos = execution_timestamp_nanos(value)
    if nanos is None:
        return None

    milliseconds = nanos // _NANOS_PER_MILLISECOND
    seconds, remainder_ms = divmod(milliseconds, 1_000)
    try:
        instant = _EPOCH + timedelta(seconds=seconds)
    except OverflowError:
        return None

    return instant.strftime("%Y-%m-%dT%H:%M:%S") + f".{remainder_ms:03d}Z"