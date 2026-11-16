"""Dataset v1 offline verification."""

import math
import re
from dataclasses import dataclass
from typing import NoReturn, NotRequired, TypedDict, cast

from ...hf import hash_hf_v1

_HEX = re.compile(r"^[0-9a-f]{128}$", re.ASCII)
_DATASET_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$", re.ASCII)
_PROGRAM = re.compile(r"^[a-z][a-z0-9_:-]{1,63}$", re.ASCII)
_MAX_FILES = 5_000
_MAX_JSON_DEPTH = 16
_MAX_METADATA_NODES = 20_000
_MAX_SAFE_INTEGER = (1 << 53) - 1
_ECMASCRIPT_TRIM = (
    "\u0009\u000b\u000c\u0020\u00a0\u1680"
    "\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a"
    "\u2028\u2029\u202f\u205f\u3000\ufeff\u000a\u000d"
)
_MISSING = object()


@dataclass(frozen=True, slots=True)
class DatasetV1Mismatch:
    field: str
    expected: object
    actual: object


@dataclass(frozen=True, slots=True)
class DatasetV1BundleComputed:
    dataset_key: str
    program: str | None
    version_label: str | None
    bundle_digest: str
    dataset_fingerprint: str
    merkle_root: str
    idempotency_key: str
    file_count: int
    total_bytes: int


@dataclass(frozen=True, slots=True)
class DatasetV1ReceiptComputed:
    dataset_key: str
    program: str | None
    version_label: str | None
    receipt_id: str
    hedera_network: str | None
    idempotency_key: str
    dataset_fingerprint: str
    bundle_digest: str
    merkle_root: str
    file_count: int
    total_bytes: int


@dataclass(frozen=True, slots=True)
class DatasetV1VerificationResult[T]:
    ok: bool
    mismatches: tuple[DatasetV1Mismatch, ...]
    computed: T


class _DatasetIdentity(TypedDict):
    dataset_key: str
    version_label: NotRequired[str]
    program: NotRequired[str]


class _DatasetRules(TypedDict):
    path_normalization: str
    follow_symlinks: bool
    redact_paths: bool
    ordering: str
    merkle_rule: str
    include_globs: NotRequired[list[str]]
    exclude_globs: NotRequired[list[str]]
    allowed_suffixes: NotRequired[list[str]]


class _DatasetFile(TypedDict):
    path_rel: NotRequired[str]
    path_hash: NotRequired[str]
    bytes: int
    sha3_512: str
    leaf_hash: str


class _Merkle(TypedDict):
    leaf_count: int
    root: str


class _Summary(TypedDict):
    file_count: int
    total_bytes: int


class _DatasetBundle(TypedDict):
    bundle_version: str
    hash_contract: dict[str, str]
    dataset_identity: _DatasetIdentity
    rules: _DatasetRules
    files: list[_DatasetFile]
    merkle: _Merkle
    summary: _Summary


class _ReceiptEvidence(TypedDict):
    dataset_fingerprint: str
    bundle_digest: str
    merkle_root: str
    idempotency_key: str
    file_count: int
    total_bytes: int


@dataclass(frozen=True, slots=True)
class _ParsedReceipt:
    body: dict[str, object]
    dataset_identity: _DatasetIdentity
    evidence: _ReceiptEvidence
    hedera_network: str | None


_HASH_CONTRACT = {
    "contract_id": "hf-contract-v1",
    "frame": "hf:frame:v1",
    "canonical_json": "hf:canonical-json:v1",
    "algorithm": "sha3-512",
    "encoding": "hex_lower",
}


def _invalid(field: str) -> NoReturn:
    raise TypeError(f"Invalid Dataset v1 evidence: {field}")


def _record(value: object, field: str) -> dict[str, object]:
    if type(value) is not dict:
        _invalid(field)
    return cast(dict[str, object], value)


def _exact_keys(value: dict[str, object], allowed: set[str], field: str) -> None:
    for key in value:
        if not isinstance(key, str) or key not in allowed:
            _invalid(f"{field}.{key}")


def _js_length(value: str) -> int:
    return len(value.encode("utf-16-le", "surrogatepass")) // 2


def _trim(value: str) -> str:
    return value.strip(_ECMASCRIPT_TRIM)


def _required_string(value: object, field: str, maximum: int) -> str:
    if not isinstance(value, str):
        _invalid(field)
    text = _trim(value)
    if not text or _js_length(text) > maximum:
        _invalid(field)
    return text


def _optional_string(value: object, field: str, maximum: int) -> str | None:
    if value is _MISSING or value is None:
        return None
    if not isinstance(value, str):
        _invalid(field)
    text = _trim(value)
    if _js_length(text) > maximum:
        _invalid(field)
    return text or None


def _digest(value: object, field: str) -> str:
    text = _required_string(value, field, 128).lower()
    if _HEX.fullmatch(text) is None:
        _invalid(field)
    return text


def _count(value: object, field: str) -> int:
    if isinstance(value, bool):
        _invalid(field)
    if isinstance(value, int):
        number = value
    elif isinstance(value, float) and math.isfinite(value) and value.is_integer():
        number = int(value)
    else:
        _invalid(field)
    if number < 0 or number > _MAX_SAFE_INTEGER:
        _invalid(field)
    return number


def _flag(value: object, field: str) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        text = _trim(value).lower()
        if text == "true":
            return True
        if text == "false":
            return False
    _invalid(field)


def _literal(value: object, expected: str, field: str) -> str:
    if _required_string(value, field, 128) != expected:
        _invalid(field)
    return expected


def _identity(value: object) -> _DatasetIdentity:
    source = _record(value, "dataset_identity")
    _exact_keys(
        source,
        {"dataset_key", "version_label", "program"},
        "dataset_identity",
    )
    dataset_key = _required_string(source.get("dataset_key"), "dataset_key", 256)
    if _DATASET_KEY.fullmatch(dataset_key) is None:
        _invalid("dataset_key")
    version_label = _optional_string(
        source.get("version_label", _MISSING),
        "version_label",
        64,
    )
    program = _optional_string(source.get("program", _MISSING), "program", 64)
    if program is not None and _PROGRAM.fullmatch(program) is None:
        _invalid("program")

    output: _DatasetIdentity = {"dataset_key": dataset_key}
    if version_label is not None:
        output["version_label"] = version_label
    if program is not None:
        output["program"] = program
    return output


def _string_array(
    value: object,
    field: str,
    maximum: int,
    *,
    lowercase: bool = False,
) -> list[str] | None:
    if value is _MISSING:
        return None
    if type(value) is not list or len(value) > 256:
        _invalid(field)

    output: list[str] = []
    for item in cast(list[object], value):
        if not isinstance(item, str):
            _invalid(field)
        text = _trim(item)
        if not text:
            continue
        if _js_length(text) > maximum:
            _invalid(field)
        output.append(text.lower() if lowercase else text)
    return output


def _rules(value: object) -> _DatasetRules:
    source = _record(value, "rules")
    _exact_keys(
        source,
        {
            "path_normalization",
            "follow_symlinks",
            "redact_paths",
            "ordering",
            "merkle_rule",
            "include_globs",
            "exclude_globs",
            "allowed_suffixes",
        },
        "rules",
    )

    include = _string_array(
        source.get("include_globs", _MISSING),
        "include_globs",
        256,
    )
    exclude = _string_array(
        source.get("exclude_globs", _MISSING),
        "exclude_globs",
        256,
    )
    suffixes = _string_array(
        source.get("allowed_suffixes", _MISSING),
        "allowed_suffixes",
        64,
        lowercase=True,
    )

    output: _DatasetRules = {
        "path_normalization": _literal(
            source.get("path_normalization"),
            "posix_rel_no_dotdot",
            "path_normalization",
        ),
        "follow_symlinks": _flag(
            source.get("follow_symlinks"),
            "follow_symlinks",
        ),
        "redact_paths": _flag(source.get("redact_paths"), "redact_paths"),
        "ordering": _literal(
            source.get("ordering"),
            "path_rel_ascii_asc",
            "ordering",
        ),
        "merkle_rule": _literal(
            source.get("merkle_rule"),
            "dup_last_on_odd",
            "merkle_rule",
        ),
    }

    if include is not None:
        output["include_globs"] = include
    if exclude is not None:
        output["exclude_globs"] = exclude
    if suffixes is not None:
        output["allowed_suffixes"] = suffixes
    return output


def _parse_file(value: object, redact: bool) -> _DatasetFile:
    source = _record(value, "file")
    _exact_keys(
        source,
        {"path_rel", "path_hash", "bytes", "sha3_512", "leaf_hash"},
        "file",
    )

    path_rel = _optional_string(
        source.get("path_rel", _MISSING),
        "path_rel",
        4096,
    )
    raw_path_hash = source.get("path_hash", _MISSING)
    path_hash = (
        None
        if raw_path_hash is _MISSING
        else _digest(raw_path_hash, "path_hash")
    )

    if bool(path_rel) == bool(path_hash):
        _invalid("file.path_variant")
    if redact != bool(path_hash):
        _invalid("file.redact_paths")

    output: _DatasetFile = {
        "bytes": _count(source.get("bytes"), "file.bytes"),
        "sha3_512": _digest(source.get("sha3_512"), "file.sha3_512"),
        "leaf_hash": _digest(source.get("leaf_hash"), "file.leaf_hash"),
    }
    if path_rel is not None:
        output["path_rel"] = path_rel
    if path_hash is not None:
        output["path_hash"] = path_hash
    return output


def _utf16_key(value: str) -> bytes:
    return value.encode("utf-16-be", "surrogatepass")


def _parse_bundle(value: object) -> _DatasetBundle:
    source = _record(value, "bundle")
    _exact_keys(
        source,
        {
            "bundle_version",
            "hash_contract",
            "dataset_identity",
            "rules",
            "files",
            "merkle",
            "summary",
        },
        "bundle",
    )
    _literal(source.get("bundle_version"), "v1", "bundle_version")

    contract = _record(source.get("hash_contract"), "hash_contract")
    _exact_keys(contract, set(_HASH_CONTRACT), "hash_contract")
    for key, expected in _HASH_CONTRACT.items():
        if contract.get(key) != expected:
            _invalid(f"hash_contract.{key}")

    parsed_identity = _identity(source.get("dataset_identity"))
    parsed_rules = _rules(source.get("rules"))

    raw_files = source.get("files")
    if (
        type(raw_files) is not list
        or not raw_files
        or len(raw_files) > _MAX_FILES
    ):
        _invalid("files")

    files = [
        _parse_file(item, parsed_rules["redact_paths"])
        for item in cast(list[object], raw_files)
    ]

    if not parsed_rules["redact_paths"]:
        for index in range(1, len(files)):
            previous = files[index - 1].get("path_rel", "")
            current = files[index].get("path_rel", "")
            if _utf16_key(previous) >= _utf16_key(current):
                _invalid("files.path_order")

    merkle_source = _record(source.get("merkle"), "merkle")
    _exact_keys(merkle_source, {"leaf_count", "root"}, "merkle")

    summary_source = _record(source.get("summary"), "summary")
    _exact_keys(
        summary_source,
        {"file_count", "total_bytes"},
        "summary",
    )

    return {
        "bundle_version": "v1",
        "hash_contract": dict(_HASH_CONTRACT),
        "dataset_identity": parsed_identity,
        "rules": parsed_rules,
        "files": files,
        "merkle": {
            "leaf_count": _count(
                merkle_source.get("leaf_count"),
                "merkle.leaf_count",
            ),
            "root": _digest(merkle_source.get("root"), "merkle.root"),
        },
        "summary": {
            "file_count": _count(
                summary_source.get("file_count"),
                "summary.file_count",
            ),
            "total_bytes": _count(
                summary_source.get("total_bytes"),
                "summary.total_bytes",
            ),
        },
    }


def _json_value(value: object, depth: int, budget: list[int]) -> object:
    budget[0] += 1
    if budget[0] > _MAX_METADATA_NODES or depth > _MAX_JSON_DEPTH:
        _invalid("receipt.metadata_limit")

    if value is None or isinstance(value, (str, bool)):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, float) and math.isfinite(value):
        return value

    if type(value) is list:
        array = cast(list[object], value)
        if len(array) > 256:
            _invalid("receipt.metadata_array")
        return [_json_value(item, depth + 1, budget) for item in array]

    source = _record(value, "receipt.metadata")
    output: dict[str, object] = {}
    for key, item in source.items():
        if key in {"__proto__", "prototype", "constructor"}:
            _invalid("receipt.metadata_key")
        output[key] = _json_value(item, depth + 1, budget)
    return output


def _optional_network(value: object) -> str | None:
    if value is _MISSING or value is None or value == "":
        return None
    if not isinstance(value, str):
        _invalid("hedera_network")

    network = _trim(value).lower()
    if network not in {"testnet", "mainnet"}:
        _invalid("hedera_network")
    return network


def _parse_receipt(value: object) -> _ParsedReceipt:
    source = _record(value, "receipt")
    _exact_keys(
        source,
        {
            "v",
            "kind",
            "receipt_id",
            "mode",
            "hedera_network",
            "dataset_identity",
            "rules",
            "evidence",
            "pointers",
            "core",
        },
        "receipt",
    )

    _literal(source.get("v"), "v1", "v")
    _literal(source.get("kind"), "dataset_anchor_receipt", "kind")

    receipt_id = _digest(source.get("receipt_id"), "receipt_id")
    mode = source.get("mode")
    if mode not in {"hash_only", "register_and_anchor"}:
        _invalid("mode")

    network = _optional_network(source.get("hedera_network", _MISSING))
    if mode == "hash_only" and network is not None:
        _invalid("hash_only.hedera_network")

    parsed_identity = _identity(source.get("dataset_identity"))

    receipt_rules = _json_value(source.get("rules"), 0, [0])
    _record(receipt_rules, "receipt.rules")

    raw_evidence = _record(source.get("evidence"), "receipt.evidence")
    _exact_keys(
        raw_evidence,
        {
            "dataset_fingerprint",
            "bundle_digest",
            "merkle_root",
            "idempotency_key",
            "file_count",
            "total_bytes",
        },
        "receipt.evidence",
    )

    evidence: _ReceiptEvidence = {
        "dataset_fingerprint": _digest(
            raw_evidence.get("dataset_fingerprint"),
            "evidence.dataset_fingerprint",
        ),
        "bundle_digest": _digest(
            raw_evidence.get("bundle_digest"),
            "evidence.bundle_digest",
        ),
        "merkle_root": _digest(
            raw_evidence.get("merkle_root"),
            "evidence.merkle_root",
        ),
        "idempotency_key": _digest(
            raw_evidence.get("idempotency_key"),
            "evidence.idempotency_key",
        ),
        "file_count": _count(
            raw_evidence.get("file_count"),
            "evidence.file_count",
        ),
        "total_bytes": _count(
            raw_evidence.get("total_bytes"),
            "evidence.total_bytes",
        ),
    }

    body: dict[str, object] = {
        "v": "v1",
        "kind": "dataset_anchor_receipt",
        "receipt_id": receipt_id,
        "mode": mode,
        "dataset_identity": parsed_identity,
        "rules": receipt_rules,
        "evidence": evidence,
    }
    if network is not None:
        body["hedera_network"] = network

    if "pointers" in source:
        raw_pointers = _record(source["pointers"], "receipt.pointers")
        _exact_keys(
            raw_pointers,
            {"evidence_pointer"},
            "receipt.pointers",
        )
        pointer = _optional_string(
            raw_pointers.get("evidence_pointer", _MISSING),
            "evidence_pointer",
            2048,
        )
        body["pointers"] = (
            {} if pointer is None else {"evidence_pointer": pointer}
        )

    if "core" in source and source["core"] is not None:
        body["core"] = _json_value(source["core"], 0, [0])

    return _ParsedReceipt(
        body=body,
        dataset_identity=parsed_identity,
        evidence=evidence,
        hedera_network=network,
    )


def _json_digest(domain: str, value: object) -> str:
    return hash_hf_v1(
        {
            "material": "json",
            "domain": domain,
            "value": value,
        }
    )


def _idempotency_key(dataset_key: str, fingerprint: str) -> str:
    return _json_digest(
        "va:dataset:idem:v1",
        {
            "dataset_key": dataset_key,
            "fingerprint": fingerprint,
            "sep": "\u0000",
            "combined": f"{dataset_key}\u0000{fingerprint}",
        },
    )


def _mismatch(
    field: str,
    expected: object,
    actual: object,
) -> DatasetV1Mismatch:
    return DatasetV1Mismatch(field, expected, actual)


def verify_dataset_v1_bundle(
    value: object,
) -> DatasetV1VerificationResult[DatasetV1BundleComputed]:
    bundle = _parse_bundle(value)
    mismatches: list[DatasetV1Mismatch] = []
    leaves: list[str] = []
    total_bytes = 0

    for index, file in enumerate(bundle["files"]):
        leaf_value: dict[str, object] = {}
        if "path_rel" in file:
            leaf_value["path_rel"] = file["path_rel"]
        if "path_hash" in file:
            leaf_value["path_hash"] = file["path_hash"]
        leaf_value["bytes"] = file["bytes"]
        leaf_value["sha3_512"] = file["sha3_512"]

        recomputed = _json_digest("va:dataset:leaf:v1", leaf_value)
        if file["leaf_hash"] != recomputed:
            mismatches.append(
                _mismatch(
                    f"files[{index}].leaf_hash",
                    recomputed,
                    file["leaf_hash"],
                )
            )

        leaves.append(recomputed)
        total_bytes += file["bytes"]
        if total_bytes > _MAX_SAFE_INTEGER:
            _invalid("summary.total_bytes_overflow")

    level = leaves
    while len(level) > 1:
        next_level: list[str] = []
        for index in range(0, len(level), 2):
            left = level[index]
            right = level[index + 1] if index + 1 < len(level) else left
            next_level.append(
                hash_hf_v1(
                    {
                        "material": "raw",
                        "domain": "va:dataset:node:v1",
                        "bytes": bytes.fromhex(left + right),
                    }
                )
            )
        level = next_level

    if not level:
        _invalid("merkle.empty")

    merkle_root = level[0]
    bundle_digest = _json_digest("va:dataset:bundle:v1", bundle)
    fingerprint = _json_digest("va:dataset:fingerprint:v1", bundle)
    identity = bundle["dataset_identity"]
    idempotency = _idempotency_key(
        identity["dataset_key"],
        fingerprint,
    )

    if bundle["merkle"]["leaf_count"] != len(bundle["files"]):
        mismatches.append(
            _mismatch(
                "merkle.leaf_count",
                len(bundle["files"]),
                bundle["merkle"]["leaf_count"],
            )
        )
    if bundle["merkle"]["root"] != merkle_root:
        mismatches.append(
            _mismatch(
                "merkle.root",
                merkle_root,
                bundle["merkle"]["root"],
            )
        )
    if bundle["summary"]["file_count"] != len(bundle["files"]):
        mismatches.append(
            _mismatch(
                "summary.file_count",
                len(bundle["files"]),
                bundle["summary"]["file_count"],
            )
        )
    if bundle["summary"]["total_bytes"] != total_bytes:
        mismatches.append(
            _mismatch(
                "summary.total_bytes",
                total_bytes,
                bundle["summary"]["total_bytes"],
            )
        )

    return DatasetV1VerificationResult(
        ok=not mismatches,
        mismatches=tuple(mismatches),
        computed=DatasetV1BundleComputed(
            dataset_key=identity["dataset_key"],
            program=identity.get("program"),
            version_label=identity.get("version_label"),
            bundle_digest=bundle_digest,
            dataset_fingerprint=fingerprint,
            merkle_root=merkle_root,
            idempotency_key=idempotency,
            file_count=len(bundle["files"]),
            total_bytes=total_bytes,
        ),
    )


def verify_dataset_v1_receipt(
    value: object,
) -> DatasetV1VerificationResult[DatasetV1ReceiptComputed]:
    parsed = _parse_receipt(value)
    receipt_id = cast(str, parsed.body["receipt_id"])
    body = {
        key: item
        for key, item in parsed.body.items()
        if key != "receipt_id"
    }

    recalculated_receipt_id = _json_digest(
        "va:dataset:receipt:v1",
        body,
    )
    recalculated_idempotency = _idempotency_key(
        parsed.dataset_identity["dataset_key"],
        parsed.evidence["dataset_fingerprint"],
    )

    mismatches: list[DatasetV1Mismatch] = []
    if receipt_id != recalculated_receipt_id:
        mismatches.append(
            _mismatch(
                "receipt_id",
                recalculated_receipt_id,
                receipt_id,
            )
        )
    if parsed.evidence["idempotency_key"] != recalculated_idempotency:
        mismatches.append(
            _mismatch(
                "evidence.idempotency_key",
                recalculated_idempotency,
                parsed.evidence["idempotency_key"],
            )
        )

    return DatasetV1VerificationResult(
        ok=not mismatches,
        mismatches=tuple(mismatches),
        computed=DatasetV1ReceiptComputed(
            dataset_key=parsed.dataset_identity["dataset_key"],
            program=parsed.dataset_identity.get("program"),
            version_label=parsed.dataset_identity.get("version_label"),
            receipt_id=recalculated_receipt_id,
            hedera_network=parsed.hedera_network,
            idempotency_key=recalculated_idempotency,
            dataset_fingerprint=parsed.evidence["dataset_fingerprint"],
            bundle_digest=parsed.evidence["bundle_digest"],
            merkle_root=parsed.evidence["merkle_root"],
            file_count=parsed.evidence["file_count"],
            total_bytes=parsed.evidence["total_bytes"],
        ),
    )