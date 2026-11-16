"""Canonical shared verification report core."""

import json
import math
import re
from collections.abc import Callable, Mapping
from dataclasses import fields, is_dataclass
from typing import Any, cast

from ..contracts import VerificationReport
from ..crypto.sha3 import sha3_512_hex

VERIFICATION_CORE_SCHEMA_VERSION = "va.verification-core.v1"

_DOMAIN = "va:verification-core:v1"
_MAX_CANONICAL_BYTES = 1024 * 1024
_MAX_SAFE_INTEGER = (1 << 53) - 1

_CHECK_ID_RE = re.compile(
    r"^[a-z][a-z0-9._:-]{0,159}$",
    re.ASCII,
)
_OBSERVATION_ID_RE = re.compile(
    r"^[a-z][a-z0-9._:-]{0,127}$",
    re.ASCII,
)
_EXPECTED_KEY_RE = re.compile(
    r"^[a-z][a-z0-9_]{0,63}$",
    re.ASCII,
)
_HEX_512_RE = re.compile(
    r"^[0-9a-f]{128}$",
    re.IGNORECASE | re.ASCII,
)

_SUBJECT_KINDS = {
    "artifact",
    "dataset",
    "ingest",
    "evidence_package",
    "merkle_anchor",
    "merkle_root",
    "merkle_leaf",
    "execution",
    "result",
}

_OUTCOMES = {
    "pass",
    "fail",
    "indeterminate",
    "unsupported",
    "skipped",
}

_SOURCES = {
    "provided_evidence",
    "public_record",
    "authorized_service",
    "hedera_mirror",
    "local_computation",
}


def _record(
    value: object,
    name: str,
) -> tuple[dict[str, object], bool]:
    if isinstance(value, Mapping):
        if not all(
            isinstance(key, str)
            for key in value
        ):
            raise TypeError(
                f"Invalid {name}"
            )

        return (
            {
                key: item
                for key, item in value.items()
                if isinstance(key, str)
            },
            False,
        )

    if (
        is_dataclass(value)
        and not isinstance(value, type)
    ):
        instance = value

        return (
            {
                field.name: getattr(
                    instance,
                    field.name,
                )
                for field in fields(
                    cast(Any, instance)
                )
            },
            True,
        )

    raise TypeError(
        f"Invalid {name}"
    )


def _fields(
    value: Mapping[str, object],
    allowed: set[str],
    name: str,
) -> None:
    if any(
        key not in allowed
        for key in value
    ):
        raise TypeError(
            f"Unknown {name} field"
        )


def _items(
    value: object,
    maximum: int,
    name: str,
) -> list[object]:
    if (
        not isinstance(value, (list, tuple))
        or len(value) > maximum
    ):
        raise TypeError(
            f"Invalid {name}"
        )

    return list(value)


def _js_length(
    value: str,
) -> int:
    return len(
        value.encode(
            "utf-16-le",
            "surrogatepass",
        )
    ) // 2


def _text(
    value: object,
    name: str,
    maximum: int,
    *,
    nonempty: bool = True,
) -> str:
    if (
        not isinstance(value, str)
        or _js_length(value) > maximum
        or (
            nonempty
            and not value
        )
    ):
        raise TypeError(
            f"Invalid {name}"
        )

    try:
        return value.encode(
            "utf-16-le",
            "surrogatepass",
        ).decode(
            "utf-16-le",
            "strict",
        )
    except UnicodeDecodeError as exc:
        raise TypeError(
            f"Invalid {name}"
        ) from exc


def _identifier(
    value: object,
    name: str,
    pattern: re.Pattern[str],
) -> str:
    result = _text(
        value,
        name,
        160,
    )

    if pattern.fullmatch(result) is None:
        raise TypeError(
            f"Invalid {name}"
        )

    return result


def _digest(
    value: object,
    name: str,
) -> str:
    result = _text(
        value,
        name,
        128,
    )

    if _HEX_512_RE.fullmatch(result) is None:
        raise TypeError(
            f"Invalid {name}"
        )

    return result.lower()


def _subject(
    value: object,
) -> dict[str, object]:
    row, _ = _record(
        value,
        "verification subject",
    )

    _fields(
        row,
        {
            "kind",
            "id",
            "hedera_network",
        },
        "subject",
    )

    kind = row.get("kind")

    if kind not in _SUBJECT_KINDS:
        raise TypeError(
            "Invalid subject kind"
        )

    subject_id = _text(
        row.get("id"),
        "subject id",
        256,
    )

    if subject_id.strip() != subject_id:
        raise TypeError(
            "Invalid subject id"
        )

    result: dict[str, object] = {
        "kind": kind,
        "id": subject_id,
    }

    if "hedera_network" in row:
        network = row.get(
            "hedera_network"
        )

        if network not in (
            "mainnet",
            "testnet",
        ):
            raise TypeError(
                "Invalid subject network"
            )

        result["hedera_network"] = (
            network
        )

    return result


def _safe_positive_integer(
    value: object,
) -> int | None:
    if isinstance(value, bool):
        return None

    if isinstance(value, int):
        if (
            1 <= value
            <= _MAX_SAFE_INTEGER
        ):
            return value

        return None

    if (
        isinstance(value, float)
        and math.isfinite(value)
        and value.is_integer()
        and 1 <= value
        <= _MAX_SAFE_INTEGER
    ):
        return int(value)

    return None


def _commitment(
    value: object,
) -> dict[str, object]:
    row, _ = _record(
        value,
        "expected commitment",
    )

    key = _identifier(
        row.get("key"),
        "expected commitment key",
        _EXPECTED_KEY_RE,
    )

    kind = row.get("kind")

    if kind == "merkle-root":
        _fields(
            row,
            {
                "key",
                "kind",
                "tree_alg",
                "root_hash",
                "leaf_count",
            },
            "merkle commitment",
        )

        tree_alg = row.get(
            "tree_alg"
        )
        leaf_count = (
            _safe_positive_integer(
                row.get("leaf_count")
            )
        )

        if (
            tree_alg
            not in {
                "binary-sorted",
                "binary-sorted-v2",
                "hf-dataset-v1",
                "hf-ingest-v1",
            }
            or leaf_count is None
        ):
            raise TypeError(
                "Invalid Merkle commitment"
            )

        return {
            "key": key,
            "kind": "merkle-root",
            "tree_alg": tree_alg,
            "root_hash": _digest(
                row.get("root_hash"),
                "root hash",
            ),
            "leaf_count": leaf_count,
        }

    if kind != "digest":
        raise TypeError(
            "Invalid commitment kind"
        )

    contract = row.get(
        "contract"
    )

    if contract == "hf-contract-v1":
        _fields(
            row,
            {
                "key",
                "kind",
                "contract",
                "material",
                "domain",
                "digest",
            },
            "HF commitment",
        )

        material = row.get(
            "material"
        )

        if material not in {
            "json",
            "utf8",
            "raw",
        }:
            raise TypeError(
                "Invalid HF material"
            )

        return {
            "key": key,
            "kind": "digest",
            "contract": "hf-contract-v1",
            "material": material,
            "domain": _text(
                row.get("domain"),
                "HF domain",
                256,
            ),
            "digest": _digest(
                row.get("digest"),
                "expected digest",
            ),
        }

    _fields(
        row,
        {
            "key",
            "kind",
            "contract",
            "digest",
        },
        "digest commitment",
    )

    if contract not in {
        "raw-sha3-512",
        "core-canonical-json",
    }:
        raise TypeError(
            "Invalid digest contract"
        )

    return {
        "key": key,
        "kind": "digest",
        "contract": contract,
        "digest": _digest(
            row.get("digest"),
            "expected digest",
        ),
    }


def _fact(
    value: object,
) -> dict[str, object]:
    row, dataclass_row = _record(
        value,
        "verification fact",
    )

    state = row.get("state")

    if dataclass_row:
        if state == "available":
            if row.get(
                "reason_code"
            ) is None:
                row.pop(
                    "reason_code",
                    None,
                )
        else:
            if row.get("value") is None:
                row.pop(
                    "value",
                    None,
                )

            if row.get(
                "reason_code"
            ) is None:
                row.pop(
                    "reason_code",
                    None,
                )

    key = _identifier(
        row.get("key"),
        "fact key",
        _CHECK_ID_RE,
    )

    if state == "available":
        _fields(
            row,
            {
                "key",
                "state",
                "value",
            },
            "available fact",
        )

        if "value" not in row:
            raise TypeError(
                "Missing fact value"
            )

        fact_value = row["value"]

        if isinstance(
            fact_value,
            (bool, int),
        ):
            pass

        elif isinstance(
            fact_value,
            float,
        ):
            if (
                not math.isfinite(
                    fact_value
                )
                or (
                    fact_value == 0.0
                    and math.copysign(
                        1.0,
                        fact_value,
                    )
                    < 0
                )
            ):
                raise TypeError(
                    "Invalid numeric fact"
                )

        elif isinstance(
            fact_value,
            str,
        ):
            fact_value = _text(
                fact_value,
                "fact value",
                4096,
                nonempty=False,
            )

        elif fact_value is not None:
            raise TypeError(
                "Invalid fact value"
            )

        return {
            "key": key,
            "state": "available",
            "value": fact_value,
        }

    if state not in {
        "unavailable",
        "not_applicable",
    }:
        raise TypeError(
            "Invalid fact state"
        )

    _fields(
        row,
        {
            "key",
            "state",
            "reason_code",
        },
        "unavailable fact",
    )

    result: dict[str, object] = {
        "key": key,
        "state": state,
    }

    if "reason_code" in row:
        reason = row.get(
            "reason_code"
        )

        result["reason_code"] = (
            None
            if reason is None
            else _text(
                reason,
                "fact reason",
                160,
            )
        )

    return result


def _unique[T](
    values: list[T],
    key: Callable[[T], str],
    name: str,
) -> list[T]:
    values = sorted(
        values,
        key=key,
    )

    for index in range(
        1,
        len(values),
    ):
        if (
            key(values[index])
            == key(values[index - 1])
        ):
            raise TypeError(
                f"Duplicate {name}"
            )

    return values


def _observation(
    value: object,
) -> dict[str, object]:
    row, dataclass_row = _record(
        value,
        "observation",
    )

    if dataclass_row:
        if row.get(
            "resolver_id"
        ) is None:
            row.pop(
                "resolver_id",
                None,
            )

        if row.get(
            "observed_at"
        ) is None:
            row.pop(
                "observed_at",
                None,
            )

    _fields(
        row,
        {
            "id",
            "subject",
            "source",
            "resolver_id",
            "observed_at",
            "facts",
        },
        "observation",
    )

    observation_id = _identifier(
        row.get("id"),
        "observation id",
        _OBSERVATION_ID_RE,
    )

    source = row.get("source")

    if source not in _SOURCES:
        raise TypeError(
            "Invalid observation source"
        )

    facts = _unique(
        [
            _fact(item)
            for item in _items(
                row.get("facts"),
                256,
                "observation facts",
            )
        ],
        lambda item: str(item["key"]),
        "fact key",
    )

    result: dict[str, object] = {
        "id": observation_id,
        "subject": _subject(
            row.get("subject")
        ),
        "source": source,
    }

    if "resolver_id" in row:
        result["resolver_id"] = _text(
            row.get("resolver_id"),
            "resolver id",
            256,
        )

    if "observed_at" in row:
        observed_at = row.get(
            "observed_at"
        )

        result["observed_at"] = (
            None
            if observed_at is None
            else _text(
                observed_at,
                "observation time",
                128,
            )
        )

    result["facts"] = facts

    return result


def _finding(
    value: object,
) -> dict[str, object]:
    row, _ = _record(
        value,
        "finding",
    )

    _fields(
        row,
        {
            "check_id",
            "outcome",
            "reason_code",
            "observation_ids",
        },
        "finding",
    )

    check_id = _identifier(
        row.get("check_id"),
        "check id",
        _CHECK_ID_RE,
    )
    outcome = row.get(
        "outcome"
    )

    if outcome not in _OUTCOMES:
        raise TypeError(
            "Invalid finding outcome"
        )

    reason = row.get(
        "reason_code"
    )

    reason_code = (
        None
        if reason is None
        else _text(
            reason,
            "finding reason",
            160,
        )
    )

    observation_ids = _unique(
        [
            _identifier(
                item,
                "finding observation id",
                _OBSERVATION_ID_RE,
            )
            for item in _items(
                row.get(
                    "observation_ids"
                ),
                32,
                "finding observation ids",
            )
        ],
        lambda item: item,
        "finding observation id",
    )

    return {
        "check_id": check_id,
        "outcome": outcome,
        "reason_code": reason_code,
        "observation_ids": observation_ids,
    }


def _normalize_exponent(
    value: str,
) -> str:
    mantissa, raw_exponent = (
        value.lower().split(
            "e",
            1,
        )
    )

    if "." in mantissa:
        mantissa = (
            mantissa.rstrip("0")
            .rstrip(".")
        )

    exponent = int(
        raw_exponent
    )

    sign = (
        "+"
        if exponent >= 0
        else "-"
    )

    return (
        f"{mantissa}e"
        f"{sign}{abs(exponent)}"
    )


def _expand_scientific(
    value: str,
) -> str:
    mantissa, raw_exponent = (
        value.lower().split(
            "e",
            1,
        )
    )
    exponent = int(
        raw_exponent
    )

    negative = mantissa.startswith(
        "-"
    )

    if negative:
        mantissa = mantissa[1:]

    if "." in mantissa:
        integer, fraction = (
            mantissa.split(
                ".",
                1,
            )
        )
    else:
        integer = mantissa
        fraction = ""

    digits = integer + fraction
    point = (
        len(integer)
        + exponent
    )

    if point <= 0:
        rendered = (
            "0."
            + ("0" * (-point))
            + digits
        )
    elif point >= len(digits):
        rendered = (
            digits
            + (
                "0"
                * (
                    point
                    - len(digits)
                )
            )
        )
    else:
        rendered = (
            digits[:point]
            + "."
            + digits[point:]
        )

    if "." in rendered:
        rendered = (
            rendered.rstrip("0")
            .rstrip(".")
        )

    if not rendered:
        rendered = "0"

    if (
        negative
        and rendered != "0"
    ):
        rendered = (
            "-"
            + rendered
        )

    return rendered


def _json_number(
    value: int | float,
) -> str:
    if isinstance(value, int):
        if (
            -_MAX_SAFE_INTEGER
            <= value
            <= _MAX_SAFE_INTEGER
        ):
            return str(value)

        try:
            value = float(value)
        except OverflowError as exc:
            raise TypeError(
                "Invalid numeric fact"
            ) from exc

    if not math.isfinite(value):
        raise TypeError(
            "Invalid numeric fact"
        )

    if value == 0:
        return "0"

    rendered = repr(value)

    if (
        "e" in rendered
        or "E" in rendered
    ):
        exponent = int(
            rendered.lower().split(
                "e",
                1,
            )[1]
        )

        if -6 <= exponent < 21:
            return _expand_scientific(
                rendered
            )

        return _normalize_exponent(
            rendered
        )

    if rendered.endswith(".0"):
        return rendered[:-2]

    return rendered


def _json_stringify(
    value: object,
) -> str:
    if value is None:
        return "null"

    if value is True:
        return "true"

    if value is False:
        return "false"

    if isinstance(
        value,
        (int, float),
    ):
        return _json_number(
            value
        )

    if isinstance(value, str):
        return json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
        )

    if isinstance(
        value,
        (list, tuple),
    ):
        return (
            "["
            + ",".join(
                _json_stringify(item)
                for item in value
            )
            + "]"
        )

    if isinstance(value, dict):
        parts: list[str] = []

        for key, item in value.items():
            if not isinstance(
                key,
                str,
            ):
                raise TypeError(
                    "Invalid canonical JSON object key"
                )

            parts.append(
                
                    json.dumps(
                        key,
                        ensure_ascii=False,
                    )
                    + ":"
                    + _json_stringify(
                        item
                    )
                
            )

        return (
            "{"
            + ",".join(parts)
            + "}"
        )

    raise TypeError(
        "Invalid canonical JSON value"
    )


def canonicalize_verification_core_v1(
    input: VerificationReport,
) -> str:
    """Return the deterministic shared verification-core projection."""
    report, _ = _record(
        input,
        "verification report",
    )
    intent, _ = _record(
        report.get("intent"),
        "verification intent",
    )

    _fields(
        intent,
        {
            "subject",
            "expected",
        },
        "intent",
    )

    expected = _unique(
        [
            _commitment(item)
            for item in _items(
                intent.get("expected"),
                32,
                "expectations",
            )
        ],
        lambda item: str(item["key"]),
        "expectation key",
    )

    observations = _unique(
        [
            _observation(item)
            for item in _items(
                report.get(
                    "observations"
                ),
                32,
                "observations",
            )
        ],
        lambda item: str(item["id"]),
        "observation id",
    )

    findings = _unique(
        [
            _finding(item)
            for item in _items(
                report.get(
                    "findings"
                ),
                512,
                "findings",
            )
        ],
        lambda item: str(
            item["check_id"]
        ),
        "check id",
    )

    observation_ids = {
        str(item["id"])
        for item in observations
    }

    for finding in findings:
        referenced = finding[
            "observation_ids"
        ]

        assert isinstance(
            referenced,
            list,
        )

        if any(
            str(observation_id)
            not in observation_ids
            for observation_id
            in referenced
        ):
            raise TypeError(
                "Finding references missing observation"
            )

    canonical = _json_stringify(
        {
            "schema_version": (
                VERIFICATION_CORE_SCHEMA_VERSION
            ),
            "intent": {
                "subject": _subject(
                    intent.get(
                        "subject"
                    )
                ),
                "expected": expected,
            },
            "findings": findings,
            "observations": observations,
        }
    )

    if (
        len(
            canonical.encode(
                "utf-8"
            )
        )
        > _MAX_CANONICAL_BYTES
    ):
        raise ValueError(
            "Verification core exceeds size limit"
        )

    return canonical


def compute_verification_core_digest_v1(
    input: VerificationReport,
) -> str:
    """Return the unauthenticated content digest of the verification core."""
    canonical = (
        canonicalize_verification_core_v1(
            input
        )
    )

    return sha3_512_hex(
        
            _DOMAIN.encode("utf-8")
            + b"\x00"
            + canonical.encode("utf-8")
        
    )