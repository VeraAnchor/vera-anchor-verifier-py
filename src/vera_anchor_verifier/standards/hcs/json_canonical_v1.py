"""Strict bounded I-JSON/JCS substrate for pinned HCS standards."""

import json
import math
from typing import Literal, Never, cast

type HcsJsonV1ErrorCode = Literal[
    "JSON_INVALID",
    "JSON_AMBIGUOUS",
    "JSON_TOO_LARGE",
]


class HcsJsonV1Error(ValueError):
    def __init__(self, code: HcsJsonV1ErrorCode) -> None:
        super().__init__(code)
        self.code = code


def _invalid(code: HcsJsonV1ErrorCode) -> Never:
    raise HcsJsonV1Error(code)


def _valid_unicode(value: str) -> bool:
    index = 0

    while index < len(value):
        code = ord(value[index])

        if 0xD800 <= code <= 0xDBFF:
            if index + 1 >= len(value) or not 0xDC00 <= ord(value[index + 1]) <= 0xDFFF:
                return False
            index += 2
            continue

        if 0xDC00 <= code <= 0xDFFF:
            return False

        index += 1

    return True


def _unicode_scalar_text(value: str) -> str:
    if not _valid_unicode(value):
        _invalid("JSON_INVALID")

    try:
        return value.encode("utf-16-le", "surrogatepass").decode(
            "utf-16-le",
            "strict",
        )
    except UnicodeError:
        _invalid("JSON_INVALID")


def _quote_string(value: str) -> str:
    return json.dumps(
        _unicode_scalar_text(value),
        ensure_ascii=False,
        separators=(",", ":"),
    )


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


def _js_number_text(value: int | float) -> str:
    try:
        number = float(value)
    except (OverflowError, ValueError):
        _invalid("JSON_INVALID")

    if not math.isfinite(number):
        _invalid("JSON_INVALID")

    if number == 0:
        return "0"

    text = repr(number)

    if "e" in text.lower():
        mantissa, exponent_raw = text.lower().split("e", 1)
        exponent = int(exponent_raw)

        if -6 <= exponent < 21:
            return _expand_scientific_to_plain(text)

        if "." in mantissa:
            mantissa = mantissa.rstrip("0").rstrip(".")

        sign = "+" if exponent >= 0 else "-"
        return f"{mantissa}e{sign}{abs(exponent)}"

    if text.endswith(".0"):
        return text[:-2]

    return text


def _js_utf16_sort_key(value: str) -> bytes:
    return value.encode("utf-16-be", "surrogatepass")


def canonical_hcs_json_v1(value: object, max_bytes: int) -> str:
    """Canonicalize a bounded JSON-native value.

    Ordering follows ECMAScript UTF-16 code-unit order. Non-finite numbers,
    cycles, non-JSON values, excessive depth and excessive size are rejected.
    """
    seen: set[int] = set()
    visited = 0

    def walk(item: object, depth: int) -> str:
        nonlocal visited

        visited += 1
        if visited > 100_000 or depth > 64:
            _invalid("JSON_TOO_LARGE")

        if item is None:
            return "null"

        if isinstance(item, str):
            return _quote_string(item)

        if isinstance(item, bool):
            return "true" if item else "false"

        if isinstance(item, (int, float)) and not isinstance(item, bool):
            return _js_number_text(item)

        if type(item) is list:
            identity = id(item)
            if identity in seen:
                _invalid("JSON_INVALID")

            seen.add(identity)
            try:
                array = cast(list[object], item)
                result = "[" + ",".join(walk(child, depth + 1) for child in array) + "]"
            finally:
                seen.discard(identity)

        elif type(item) is dict:
            identity = id(item)
            if identity in seen:
                _invalid("JSON_INVALID")

            seen.add(identity)
            try:
                raw_record = cast(dict[object, object], item)
                if any(not isinstance(key, str) for key in raw_record):
                    _invalid("JSON_INVALID")

                record = cast(dict[str, object], item)
                keys = sorted(record, key=_js_utf16_sort_key)
                result = "{" + ",".join(
                    f"{walk(key, depth + 1)}:{walk(record[key], depth + 1)}"
                    for key in keys
                ) + "}"
            finally:
                seen.discard(identity)

        else:
            _invalid("JSON_INVALID")

        if len(result.encode("utf-8")) > max_bytes:
            _invalid("JSON_TOO_LARGE")

        return result

    return walk(value, 0)


def _pairs_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}

    for key, value in pairs:
        if key in result:
            _invalid("JSON_AMBIGUOUS")
        result[key] = value

    return result


def _invalid_constant(_value: str) -> Never:
    _invalid("JSON_INVALID")


def _json_number(value: str) -> float:
    try:
        return float(value)
    except ValueError:
        _invalid("JSON_INVALID")


def _validate_tree_bounds(value: object) -> None:
    stack: list[tuple[object, int]] = [(value, 0)]
    nodes = 0

    while stack:
        item, depth = stack.pop()
        nodes += 1

        if nodes > 100_000 or depth > 64:
            _invalid("JSON_TOO_LARGE")

        if type(item) is dict:
            record = cast(dict[str, object], item)
            stack.extend((child, depth + 1) for child in record.values())
        elif type(item) is list:
            array = cast(list[object], item)
            stack.extend((child, depth + 1) for child in array)


def parse_strict_hcs_json_v1(
    value: bytes | bytearray | memoryview | str,
    max_bytes: int,
) -> object:
    """Parse strict bounded JSON before canonicalization.

    Duplicate property names, including escaped aliases, are rejected before
    any caller can hash the resulting object.
    """
    if isinstance(value, str):
        text = value
        try:
            raw = text.encode("utf-8", errors="strict")
        except UnicodeEncodeError:
            _invalid("JSON_INVALID")

    elif isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
        try:
            text = raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            _invalid("JSON_INVALID")

    else:
        _invalid("JSON_INVALID")

    if len(raw) > max_bytes:
        _invalid("JSON_TOO_LARGE")

    try:
        result: object = json.loads(
            text,
            object_pairs_hook=_pairs_object,
            parse_int=_json_number,
            parse_float=_json_number,
            parse_constant=_invalid_constant,
        )
    except HcsJsonV1Error:
        raise
    except (json.JSONDecodeError, ValueError, TypeError, RecursionError):
        _invalid("JSON_INVALID")

    _validate_tree_bounds(result)
    return result


def clone_hcs_json_v1(item: object) -> object:
    """Clone a JSON-native tree after successful validation."""
    if item is None or isinstance(item, (str, bool, int, float)):
        return item

    if type(item) is list:
        array = cast(list[object], item)
        return [clone_hcs_json_v1(child) for child in array]

    if type(item) is dict:
        record = cast(dict[str, object], item)
        return {key: clone_hcs_json_v1(child) for key, child in record.items()}

    _invalid("JSON_INVALID")