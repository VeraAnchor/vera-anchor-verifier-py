"""Ingest v1 offline verification."""

import math
import re
from dataclasses import dataclass
from typing import Literal, NoReturn, cast

from ...hf import hash_hf_v1

_HEX = re.compile(r"^[0-9a-f]{128}$", re.ASCII)
_OBJECT_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$", re.ASCII)
_PROGRAM = re.compile(r"^[a-z][a-z0-9_:-]{1,63}$", re.ASCII)
_YMD = re.compile(r"^\d{4}-\d{2}-\d{2}$", re.ASCII)

_MAX_ITEMS = 5_000
_MAX_META_DEPTH = 8
_MAX_META_NODES = 20_000
_MAX_SAFE_INTEGER = (1 << 53) - 1

_ECMASCRIPT_TRIM = (
    "\u0009\u000b\u000c\u0020\u00a0\u1680"
    "\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a"
    "\u2028\u2029\u202f\u205f\u3000\ufeff\u000a\u000d"
)
_MISSING = object()

type Network = Literal["testnet", "mainnet"]
type ObjectKind = Literal["json", "text", "file", "file_set"]
type ItemKind = Literal["json", "text", "file"]
type Record = dict[str, object]


@dataclass(frozen=True, slots=True)
class IngestV1Mismatch:
    field: str
    expected: object
    actual: object


@dataclass(frozen=True, slots=True)
class IngestV1BundleComputed:
    object_key: str
    object_kind: ObjectKind
    program: str | None
    version_label: str | None
    bundle_digest: str
    fingerprint: str
    idempotency_key: str
    merkle_root: str | None
    item_count: int
    total_bytes: int


@dataclass(frozen=True, slots=True)
class IngestV1ReceiptComputed:
    hedera_network: Network | None
    object_key: str
    object_kind: ObjectKind
    program: str | None
    version_label: str | None
    receipt_id: str
    idempotency_key: str
    fingerprint: str
    bundle_digest: str
    merkle_root: str | None
    item_count: int
    total_bytes: int
    receipt_anchor_id: object
    receipt_anchor_hash: object
    receipt_leaf_id: object
    receipt_leaf_hash: object
    receipt_payload_hash: object
    receipt_hcs_transaction_id: object
    receipt_hcs_message_id: object
    root_anchor_id: object
    root_anchor_hash: object
    root_id: object
    anchored_root_hash: object
    root_hcs_transaction_id: object
    root_hcs_message_id: object


@dataclass(frozen=True, slots=True)
class IngestV1PairComputed:
    bundle: IngestV1BundleComputed
    receipt: IngestV1ReceiptComputed


@dataclass(frozen=True, slots=True)
class IngestV1Result[T]:
    ok: bool
    mismatches: tuple[IngestV1Mismatch, ...]
    computed: T


@dataclass(frozen=True, slots=True)
class _ParsedBundle:
    identity: Record
    rules: Record
    items: tuple[Record, ...]
    merkle: Record | None
    summary: Record
    normalized: Record


@dataclass(frozen=True, slots=True)
class _ParsedReceipt:
    body: Record
    receipt_id: str
    hedera_network: Network | None
    identity: Record
    rules: Record
    evidence: Record
    receipt_anchor: Record | None
    root_anchor: Record | None


_HASH_CONTRACT = {
    "contract_id": "hf-contract-v1",
    "frame": "hf:frame:v1",
    "canonical_json": "hf:canonical-json:v1",
    "algorithm": "sha3-512",
    "encoding": "hex_lower",
}


def _invalid(field: str) -> NoReturn:
    raise TypeError(f"Invalid Ingest v1 evidence: {field}")


def _record(value: object, field: str) -> Record:
    if type(value) is not dict:
        _invalid(field)
    return cast(Record, value)


def _keys(value: Record, allowed: set[str], field: str) -> None:
    for key in value:
        if key not in allowed:
            _invalid(f"{field}.{key}")


def _js_length(value: str) -> int:
    return len(value.encode("utf-16-le", "surrogatepass")) // 2


def _trim(value: str) -> str:
    return value.strip(_ECMASCRIPT_TRIM)


def _text(value: object, field: str, maximum: int) -> str:
    if not isinstance(value, str):
        _invalid(field)
    text = _trim(value)
    if not text or _js_length(text) > maximum:
        _invalid(field)
    return text


def _optional_text(value: object, field: str, maximum: int) -> str | None:
    if value is _MISSING or value is None:
        return None
    if not isinstance(value, str):
        _invalid(field)
    text = _trim(value)
    if _js_length(text) > maximum:
        _invalid(field)
    return text or None


def _digest(value: object, field: str) -> str:
    text = _text(value, field, 128).lower()
    if _HEX.fullmatch(text) is None:
        _invalid(field)
    return text


def _integer(value: object, field: str) -> int:
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


def _bool(value: object, field: str) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        text = _trim(value).lower()
        if text == "true":
            return True
        if text == "false":
            return False
    _invalid(field)


def _kind(value: object) -> ObjectKind:
    if value not in ("json", "text", "file", "file_set"):
        _invalid("object_kind")
    return value


def _identity(value: object) -> Record:
    source = _record(value, "identity")
    _keys(source, {"object_key", "object_kind", "version_label", "program"}, "identity")

    object_key = _text(source.get("object_key"), "identity.object_key", 256)
    if _OBJECT_KEY.fullmatch(object_key) is None:
        _invalid("identity.object_key")

    object_kind = _kind(source.get("object_kind"))
    version_label = _optional_text(
        source.get("version_label", _MISSING), "identity.version_label", 64
    )
    program = _optional_text(source.get("program", _MISSING), "identity.program", 64)
    if program is not None and _PROGRAM.fullmatch(program) is None:
        _invalid("identity.program")

    result: Record = {"object_key": object_key, "object_kind": object_kind}
    if version_label is not None:
        result["version_label"] = version_label
    if program is not None:
        result["program"] = program
    return result


def _string_array(
    value: object,
    field: str,
    maximum: int,
    *,
    lowercase: bool = False,
) -> list[str] | None:
    if value is _MISSING or value is None:
        return None
    if type(value) is not list or len(value) > 256:
        _invalid(field)

    result: list[str] = []
    for item in cast(list[object], value):
        if not isinstance(item, str):
            _invalid(field)
        text = _trim(item)
        if not text:
            continue
        if _js_length(text) > maximum:
            _invalid(field)
        result.append(text.lower() if lowercase else text)
    return result


def _rules(value: object) -> Record:
    source = _record(value, "rules")
    _keys(
        source,
        {
            "path_normalization",
            "follow_symlinks",
            "redact_paths",
            "normalize_line_endings",
            "ordering",
            "merkle_rule",
            "include_globs",
            "exclude_globs",
            "allowed_suffixes",
        },
        "rules",
    )

    include = _string_array(
        source.get("include_globs", _MISSING), "rules.include_globs", 256
    )
    exclude = _string_array(
        source.get("exclude_globs", _MISSING), "rules.exclude_globs", 256
    )
    suffixes = _string_array(
        source.get("allowed_suffixes", _MISSING),
        "rules.allowed_suffixes",
        64,
        lowercase=True,
    )
    if suffixes is not None and any(not suffix.startswith(".") for suffix in suffixes):
        _invalid("rules.allowed_suffixes")

    if source.get("path_normalization") != "posix_rel_no_dotdot":
        _invalid("rules.path_normalization")
    if source.get("ordering") != "deterministic_sort_v1":
        _invalid("rules.ordering")
    if source.get("merkle_rule") != "dup_last_on_odd":
        _invalid("rules.merkle_rule")

    result: Record = {
        "path_normalization": "posix_rel_no_dotdot",
        "follow_symlinks": _bool(source.get("follow_symlinks"), "rules.follow_symlinks"),
        "redact_paths": _bool(source.get("redact_paths"), "rules.redact_paths"),
        "normalize_line_endings": _bool(
            source.get("normalize_line_endings"), "rules.normalize_line_endings"
        ),
        "ordering": "deterministic_sort_v1",
        "merkle_rule": "dup_last_on_odd",
    }
    if include is not None:
        result["include_globs"] = include
    if exclude is not None:
        result["exclude_globs"] = exclude
    if suffixes is not None:
        result["allowed_suffixes"] = suffixes
    return result


def _normalized_path(value: object) -> str:
    path = _text(value, "item.path_rel", 1024).replace("\\", "/")
    segments = path.split("/")
    if (
        path.startswith("/")
        or any(not segment or segment in (".", "..") for segment in segments)
        or "\x00" in path
        or ".." in path
    ):
        _invalid("item.path_rel")
    return path


def _item(value: object, redact: bool) -> Record:
    source = _record(value, "item")
    _keys(
        source,
        {"item_kind", "path_rel", "path_hash", "media_type", "bytes", "sha3_512", "leaf_hash"},
        "item",
    )

    item_kind = _kind(source.get("item_kind"))
    if item_kind == "file_set":
        _invalid("item.item_kind")

    raw_path = source.get("path_rel", _MISSING)
    path_rel = None if raw_path is _MISSING or raw_path is None else _normalized_path(raw_path)

    raw_path_hash = source.get("path_hash", _MISSING)
    path_hash = (
        None
        if raw_path_hash is _MISSING or raw_path_hash is None
        else _digest(raw_path_hash, "item.path_hash")
    )
    media_type = _optional_text(
        source.get("media_type", _MISSING), "item.media_type", 256
    )

    if item_kind == "file":
        if bool(path_rel) == bool(path_hash):
            _invalid("item.path_variant")
        if redact != bool(path_hash):
            _invalid("item.redact_paths")
    elif path_rel or path_hash:
        _invalid("item.path_variant")

    result: Record = {
        "item_kind": item_kind,
        "bytes": _integer(source.get("bytes"), "item.bytes"),
        "sha3_512": _digest(source.get("sha3_512"), "item.sha3_512"),
        "leaf_hash": _digest(source.get("leaf_hash"), "item.leaf_hash"),
    }
    if path_rel:
        result["path_rel"] = path_rel
    if path_hash:
        result["path_hash"] = path_hash
    if media_type:
        result["media_type"] = media_type
    return result


def _json_value(value: object, depth: int, budget: list[int]) -> object:
    budget[0] += 1
    if budget[0] > _MAX_META_NODES or depth > _MAX_META_DEPTH:
        _invalid("json.limit")

    if value is None or isinstance(value, (str, bool)):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, float) and math.isfinite(value):
        return value

    if type(value) is list:
        values = cast(list[object], value)
        if len(values) > 256:
            _invalid("json.array")
        return [_json_value(item, depth + 1, budget) for item in values]

    source = _record(value, "json")
    result: Record = {}
    for key, item in source.items():
        if key in {"__proto__", "prototype", "constructor"} or _js_length(key) > 256:
            _invalid("json.key")
        result[key] = _json_value(item, depth + 1, budget)
    return result


def _bundle(value: object) -> _ParsedBundle:
    source = _record(value, "bundle")
    _keys(
        source,
        {"bundle_version", "hash_contract", "identity", "rules", "items", "merkle", "summary"},
        "bundle",
    )
    if source.get("bundle_version") != "v1":
        _invalid("bundle_version")

    contract = _record(source.get("hash_contract"), "hash_contract")
    _keys(contract, set(_HASH_CONTRACT), "hash_contract")
    for name, expected in _HASH_CONTRACT.items():
        if contract.get(name) != expected:
            _invalid(f"hash_contract.{name}")

    identity = _identity(source.get("identity"))
    rules = _rules(source.get("rules"))

    raw_items = source.get("items")
    if type(raw_items) is not list or not raw_items or len(raw_items) > _MAX_ITEMS:
        _invalid("items")
    items = tuple(
        _item(item, cast(bool, rules["redact_paths"]))
        for item in cast(list[object], raw_items)
    )

    object_kind = cast(ObjectKind, identity["object_kind"])
    if object_kind == "file_set":
        if any(item["item_kind"] != "file" for item in items):
            _invalid("items.item_kind")
    elif len(items) != 1 or items[0]["item_kind"] != object_kind:
        _invalid("items.item_kind")

    summary_source = _record(source.get("summary"), "summary")
    _keys(summary_source, {"item_count", "total_bytes"}, "summary")
    summary: Record = {
        "item_count": _integer(summary_source.get("item_count"), "summary.item_count"),
        "total_bytes": _integer(summary_source.get("total_bytes"), "summary.total_bytes"),
    }

    merkle: Record | None = None
    if "merkle" in source:
        merkle_source = _record(source["merkle"], "merkle")
        _keys(merkle_source, {"leaf_count", "root"}, "merkle")
        merkle = {
            "leaf_count": _integer(merkle_source.get("leaf_count"), "merkle.leaf_count"),
            "root": _digest(merkle_source.get("root"), "merkle.root"),
        }

    normalized: Record = {
        "bundle_version": "v1",
        "hash_contract": dict(_HASH_CONTRACT),
        "identity": identity,
        "rules": rules,
        "items": list(items),
        "summary": summary,
    }
    if merkle is not None:
        normalized["merkle"] = merkle

    return _ParsedBundle(identity, rules, items, merkle, summary, normalized)


def _network(value: object) -> Network | None:
    if value is _MISSING or value is None:
        return None
    if not isinstance(value, str):
        _invalid("hedera_network")
    network = _trim(value).lower()
    if network not in {"mainnet", "testnet"}:
        _invalid("hedera_network")
    return cast(Network, network)


def _receipt(value: object) -> _ParsedReceipt:
    source = _record(value, "receipt")
    _keys(
        source,
        {
            "v", "kind", "receipt_id", "hedera_network", "mode", "identity", "rules",
            "evidence", "anchor", "pointers", "metadata", "core",
        },
        "receipt",
    )
    if source.get("v") != "v1":
        _invalid("receipt.v")
    if source.get("kind") != "ingest_receipt":
        _invalid("receipt.kind")

    receipt_id = _digest(source.get("receipt_id"), "receipt.receipt_id")
    mode = source.get("mode")
    if mode not in {"hash_only", "merkle_only", "register_and_anchor"}:
        _invalid("receipt.mode")

    network = _network(source.get("hedera_network", _MISSING))
    if network is not None and mode != "register_and_anchor":
        _invalid("receipt.local_network")

    identity = _identity(source.get("identity"))
    rules = _rules(source.get("rules"))

    raw_evidence = _record(source.get("evidence"), "receipt.evidence")
    _keys(
        raw_evidence,
        {
            "fingerprint",
            "bundle_digest",
            "merkle_root",
            "idempotency_key",
            "item_count",
            "total_bytes",
        },
        "receipt.evidence",
    )
    evidence: Record = {
        "fingerprint": _digest(raw_evidence.get("fingerprint"), "evidence.fingerprint"),
        "bundle_digest": _digest(raw_evidence.get("bundle_digest"), "evidence.bundle_digest"),
        "idempotency_key": _digest(raw_evidence.get("idempotency_key"), "evidence.idempotency_key"),
        "item_count": _integer(raw_evidence.get("item_count"), "evidence.item_count"),
        "total_bytes": _integer(raw_evidence.get("total_bytes"), "evidence.total_bytes"),
    }
    if "merkle_root" in raw_evidence:
        evidence["merkle_root"] = _digest(
            raw_evidence["merkle_root"], "evidence.merkle_root"
        )

    body: Record = {
        "v": "v1",
        "kind": "ingest_receipt",
        "mode": mode,
        "identity": identity,
        "rules": rules,
        "evidence": evidence,
    }
    if network is not None:
        body["hedera_network"] = network

    if "anchor" in source:
        raw_anchor = _record(source["anchor"], "receipt.anchor")
        _keys(raw_anchor, {"domain", "proof_date"}, "receipt.anchor")
        domain = _optional_text(raw_anchor.get("domain", _MISSING), "anchor.domain", 256)
        proof_date = _optional_text(
            raw_anchor.get("proof_date", _MISSING), "anchor.proof_date", 10
        )
        if proof_date and _YMD.fullmatch(proof_date) is None:
            _invalid("anchor.proof_date")
        body["anchor"] = {
            **({"domain": domain} if domain else {}),
            **({"proof_date": proof_date} if proof_date else {}),
        }

    if mode == "register_and_anchor":
        anchor = body.get("anchor")
        if type(anchor) is not dict:
            _invalid("receipt.anchor_required")
        anchor_record = cast(Record, anchor)
        if not anchor_record.get("domain") or not anchor_record.get("proof_date"):
            _invalid("receipt.anchor_required")

    if "pointers" in source:
        raw_pointers = _record(source["pointers"], "receipt.pointers")
        _keys(raw_pointers, {"evidence_pointer"}, "receipt.pointers")
        pointer = _optional_text(
            raw_pointers.get("evidence_pointer", _MISSING),
            "pointers.evidence_pointer",
            2048,
        )
        if pointer:
            body["pointers"] = {"evidence_pointer": pointer}

    if "metadata" in source:
        body["metadata"] = _json_value(source["metadata"], 0, [0])

    receipt_anchor: Record | None = None
    root_anchor: Record | None = None
    if "core" in source:
        raw_core = _record(source["core"], "receipt.core")
        _keys(raw_core, {"receipt_anchor", "root_anchor"}, "receipt.core")
        projected: Record = {}

        if "receipt_anchor" in raw_core:
            receipt_anchor = _record(
                _json_value(raw_core["receipt_anchor"], 0, [0]),
                "core.receipt_anchor",
            )
            projected["receipt_anchor"] = receipt_anchor

        if "root_anchor" in raw_core:
            root_anchor = _record(
                _json_value(raw_core["root_anchor"], 0, [0]),
                "core.root_anchor",
            )
            projected["root_anchor"] = root_anchor

        if projected:
            body["core"] = projected

    return _ParsedReceipt(
        body,
        receipt_id,
        network,
        identity,
        rules,
        evidence,
        receipt_anchor,
        root_anchor,
    )


def _json_hash(domain: str, value: object) -> str:
    return hash_hf_v1({"material": "json", "domain": domain, "value": value})


def _idempotency_key(object_key: str, fingerprint: str) -> str:
    return _json_hash(
        "va:ingest:idem:v1",
        {
            "object_key": object_key,
            "fingerprint": fingerprint,
            "sep": "\u0000",
            "combined": f"{object_key}\u0000{fingerprint}",
        },
    )


def _computed_root(items: tuple[Record, ...]) -> str:
    level = [cast(str, item["leaf_hash"]) for item in items]
    while len(level) > 1:
        level = [
            hash_hf_v1(
                {
                    "material": "raw",
                    "domain": "va:ingest:node:v1",
                    "bytes": bytes.fromhex(
                        level[index]
                        + (level[index + 1] if index + 1 < len(level) else level[index])
                    ),
                }
            )
            for index in range(0, len(level), 2)
        ]
    if not level:
        _invalid("merkle.empty")
    return level[0]


def verify_ingest_v1_bundle(value: object) -> IngestV1Result[IngestV1BundleComputed]:
    parsed = _bundle(value)
    mismatches: list[IngestV1Mismatch] = []
    recomputed: list[Record] = []

    for index, item in enumerate(parsed.items):
        leaf_value: Record = {"item_kind": item["item_kind"]}
        for field in ("path_rel", "path_hash", "media_type"):
            if field in item:
                leaf_value[field] = item[field]
        leaf_value["bytes"] = item["bytes"]
        leaf_value["sha3_512"] = item["sha3_512"]

        leaf_hash = _json_hash("va:ingest:leaf:v1", leaf_value)
        if item["leaf_hash"] != leaf_hash:
            mismatches.append(
                IngestV1Mismatch(f"items[{index}].leaf_hash", leaf_hash, item["leaf_hash"])
            )

        normalized = dict(item)
        normalized["leaf_hash"] = leaf_hash
        recomputed.append(normalized)

    root = _computed_root(tuple(recomputed)) if parsed.merkle is not None else None
    total_bytes = 0
    for item in parsed.items:
        total_bytes += cast(int, item["bytes"])
        if total_bytes > _MAX_SAFE_INTEGER:
            _invalid("summary.total_bytes_overflow")

    if parsed.summary["item_count"] != len(parsed.items):
        mismatches.append(
            IngestV1Mismatch(
                "summary.item_count", len(parsed.items), parsed.summary["item_count"]
            )
        )
    if parsed.summary["total_bytes"] != total_bytes:
        mismatches.append(
            IngestV1Mismatch(
                "summary.total_bytes", total_bytes, parsed.summary["total_bytes"]
            )
        )
    if parsed.merkle is not None:
        if parsed.merkle["leaf_count"] != len(parsed.items):
            mismatches.append(
                IngestV1Mismatch(
                    "merkle.leaf_count", len(parsed.items), parsed.merkle["leaf_count"]
                )
            )
        if parsed.merkle["root"] != root:
            mismatches.append(
                IngestV1Mismatch("merkle.root", root, parsed.merkle["root"])
            )

    fingerprint = _json_hash("va:ingest:fingerprint:v1", parsed.normalized)
    object_key = cast(str, parsed.identity["object_key"])

    return IngestV1Result(
        ok=not mismatches,
        mismatches=tuple(mismatches),
        computed=IngestV1BundleComputed(
            object_key=object_key,
            object_kind=cast(ObjectKind, parsed.identity["object_kind"]),
            program=cast(str | None, parsed.identity.get("program")),
            version_label=cast(str | None, parsed.identity.get("version_label")),
            bundle_digest=_json_hash("va:ingest:bundle:v1", parsed.normalized),
            fingerprint=fingerprint,
            idempotency_key=_idempotency_key(object_key, fingerprint),
            merkle_root=root,
            item_count=len(parsed.items),
            total_bytes=total_bytes,
        ),
    )


def _embedded_network(
    mismatches: list[IngestV1Mismatch],
    expected: Network | None,
    field: str,
    source: Record | None,
) -> None:
    if expected is None or source is None:
        return

    if "hedera_network" in source:
        raw = source.get("hedera_network")
        actual = "" if raw is None else _trim(str(raw)).lower()
        if actual != expected:
            mismatches.append(
                IngestV1Mismatch(f"{field}.hedera_network", expected, raw)
            )

    if "publish" in source:
        publish = _record(source["publish"], f"{field}.publish")
        if "hedera_network" in publish:
            raw = publish.get("hedera_network")
            actual = "" if raw is None else _trim(str(raw)).lower()
            if actual != expected:
                mismatches.append(
                    IngestV1Mismatch(
                        f"{field}.publish.hedera_network", expected, raw
                    )
                )


def _anchor(source: Record | None, field: str) -> object:
    return None if source is None else source.get(field)


def verify_ingest_v1_receipt(value: object) -> IngestV1Result[IngestV1ReceiptComputed]:
    parsed = _receipt(value)
    receipt_id = _json_hash("va:ingest:receipt:v1", parsed.body)
    object_key = cast(str, parsed.identity["object_key"])
    fingerprint = cast(str, parsed.evidence["fingerprint"])
    idempotency = _idempotency_key(object_key, fingerprint)

    mismatches: list[IngestV1Mismatch] = []
    if parsed.receipt_id != receipt_id:
        mismatches.append(IngestV1Mismatch("receipt_id", receipt_id, parsed.receipt_id))
    if parsed.evidence["idempotency_key"] != idempotency:
        mismatches.append(
            IngestV1Mismatch(
                "evidence.idempotency_key",
                idempotency,
                parsed.evidence["idempotency_key"],
            )
        )

    _embedded_network(
        mismatches, parsed.hedera_network, "core.receipt_anchor", parsed.receipt_anchor
    )
    _embedded_network(
        mismatches, parsed.hedera_network, "core.root_anchor", parsed.root_anchor
    )

    ra, root = parsed.receipt_anchor, parsed.root_anchor
    return IngestV1Result(
        ok=not mismatches,
        mismatches=tuple(mismatches),
        computed=IngestV1ReceiptComputed(
            hedera_network=parsed.hedera_network,
            object_key=object_key,
            object_kind=cast(ObjectKind, parsed.identity["object_kind"]),
            program=cast(str | None, parsed.identity.get("program")),
            version_label=cast(str | None, parsed.identity.get("version_label")),
            receipt_id=receipt_id,
            idempotency_key=idempotency,
            fingerprint=fingerprint,
            bundle_digest=cast(str, parsed.evidence["bundle_digest"]),
            merkle_root=cast(str | None, parsed.evidence.get("merkle_root")),
            item_count=cast(int, parsed.evidence["item_count"]),
            total_bytes=cast(int, parsed.evidence["total_bytes"]),
            receipt_anchor_id=_anchor(ra, "id"),
            receipt_anchor_hash=_anchor(ra, "anchor_hash"),
            receipt_leaf_id=_anchor(ra, "leaf_id"),
            receipt_leaf_hash=_anchor(ra, "leaf_hash"),
            receipt_payload_hash=_anchor(ra, "payload_hash"),
            receipt_hcs_transaction_id=_anchor(ra, "hcs_transaction_id"),
            receipt_hcs_message_id=_anchor(ra, "hcs_message_id"),
            root_anchor_id=_anchor(root, "id"),
            root_anchor_hash=_anchor(root, "anchor_hash"),
            root_id=_anchor(root, "root_id"),
            anchored_root_hash=_anchor(root, "root_hash"),
            root_hcs_transaction_id=_anchor(root, "hcs_transaction_id"),
            root_hcs_message_id=_anchor(root, "hcs_message_id"),
        ),
    )


def verify_ingest_v1_pair(
    *,
    bundle: object,
    receipt: object,
) -> IngestV1Result[IngestV1PairComputed]:
    bundle_result = verify_ingest_v1_bundle(bundle)
    receipt_result = verify_ingest_v1_receipt(receipt)
    parsed_bundle = _bundle(bundle)
    parsed_receipt = _receipt(receipt)

    mismatches = [
        IngestV1Mismatch(f"bundle.{m.field}", m.expected, m.actual)
        for m in bundle_result.mismatches
    ]
    mismatches.extend(
        IngestV1Mismatch(f"receipt.{m.field}", m.expected, m.actual)
        for m in receipt_result.mismatches
    )

    expected, actual = bundle_result.computed, receipt_result.computed
    for field in (
        "object_key",
        "object_kind",
        "program",
        "version_label",
        "fingerprint",
        "bundle_digest",
        "merkle_root",
        "idempotency_key",
        "item_count",
        "total_bytes",
    ):
        left, right = getattr(expected, field), getattr(actual, field)
        if left != right:
            mismatches.append(IngestV1Mismatch(f"binding.{field}", left, right))

    if _json_hash("va:ingest:bundle:v1", parsed_bundle.rules) != _json_hash(
        "va:ingest:bundle:v1", parsed_receipt.rules
    ):
        mismatches.append(
            IngestV1Mismatch("binding.rules", "matches bundle rules", "mismatch")
        )

    return IngestV1Result(
        ok=not mismatches,
        mismatches=tuple(mismatches),
        computed=IngestV1PairComputed(expected, actual),
    )