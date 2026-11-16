"""Bind actual source files to Dataset v1 evidence."""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import cast

from ...crypto import ByteChunkSource
from ...hf import canonicalize_hf_v1_json
from ..source_v1_helpers import (
    SourceV1File,
    SourceV1Limits,
    SourceV1Mismatch,
    source_v1_compare,
    source_v1_hash_file,
    source_v1_leaf,
    source_v1_limits,
    source_v1_mismatch,
    source_v1_path,
    source_v1_path_digest,
    source_v1_root,
    source_v1_sort_key,
)
from .v1 import (
    DatasetV1BundleComputed,
    DatasetV1ReceiptComputed,
    verify_dataset_v1_bundle,
    verify_dataset_v1_receipt,
)

_MISSING = object()


@dataclass(frozen=True, slots=True)
class DatasetV1SourceComputed:
    bundle: DatasetV1BundleComputed
    receipt: DatasetV1ReceiptComputed | None
    source_merkle_root: str | None
    source_file_count: int
    source_total_bytes: int


@dataclass(frozen=True, slots=True)
class DatasetV1SourceResult:
    ok: bool
    mismatches: tuple[SourceV1Mismatch, ...]
    computed: DatasetV1SourceComputed


async def verify_dataset_v1_sources(
    *,
    bundle: object,
    files: list[SourceV1File],
    receipt: object = _MISSING,
    limits: SourceV1Limits | None = None,
) -> DatasetV1SourceResult:
    checked_bundle = verify_dataset_v1_bundle(bundle)
    bundle_view = cast(dict[str, object], bundle)
    rules = cast(dict[str, object], bundle_view["rules"])
    declared_files = cast(list[dict[str, object]], bundle_view["files"])
    merkle = cast(dict[str, object], bundle_view["merkle"])

    mismatches = [
        source_v1_mismatch(
            f"bundle.{entry.field}",
            entry.expected,
            entry.actual,
        )
        for entry in checked_bundle.mismatches
    ]

    if type(files) is not list:
        raise TypeError("Dataset source files must be an array")

    max_total, max_file = source_v1_limits(limits)

    if len(files) > 5_000:
        raise ValueError("Too many Dataset source files")

    seen: set[str] = set()
    sources: list[tuple[str, object]] = []

    for entry in files:
        if not isinstance(entry, Mapping):
            raise TypeError("Dataset source file must be an object")

        path = source_v1_path(entry.get("path_rel"), 4096)

        if ".." in path:
            raise TypeError("Dataset source path is not producer-canonical")

        if path in seen:
            raise TypeError("Duplicate Dataset source path")

        seen.add(path)
        sources.append((path, entry.get("source")))

    sources.sort(key=lambda entry: source_v1_sort_key(entry[0]))

    source_v1_compare(
        mismatches,
        "sources.file_count",
        len(declared_files),
        len(sources),
    )

    leaves: list[str] = []
    total_bytes = 0
    redact_paths = bool(rules["redact_paths"])

    for index, (path, source) in enumerate(sources):
        declared = declared_files[index] if index < len(declared_files) else None
        remaining = max_total - total_bytes

        hashed = await source_v1_hash_file(
            cast(ByteChunkSource, source),
            min(max_file, remaining),
            False,
        )

        total_bytes += hashed.bytes

        path_key = "path_hash" if redact_paths else "path_rel"
        path_value = (
            source_v1_path_digest(path, "dataset")
            if redact_paths
            else path
        )

        actual_path = None if declared is None else declared.get(path_key)
        actual_bytes = None if declared is None else declared.get("bytes")
        actual_digest = None if declared is None else declared.get("sha3_512")
        actual_leaf = None if declared is None else declared.get("leaf_hash")

        source_v1_compare(
            mismatches,
            f"files[{index}].{path_key}",
            path_value,
            actual_path,
        )
        source_v1_compare(
            mismatches,
            f"files[{index}].bytes",
            hashed.bytes,
            actual_bytes,
        )
        source_v1_compare(
            mismatches,
            f"files[{index}].sha3_512",
            hashed.sha3_512,
            actual_digest,
        )

        leaf = source_v1_leaf(
            "dataset",
            path_hash=path_value if redact_paths else None,
            path_rel=None if redact_paths else path_value,
            bytes_count=hashed.bytes,
            sha3_512=hashed.sha3_512,
        )
        leaves.append(leaf)

        source_v1_compare(
            mismatches,
            f"files[{index}].leaf_hash",
            leaf,
            actual_leaf,
        )

    source_root = source_v1_root("dataset", leaves) if leaves else None

    source_v1_compare(
        mismatches,
        "sources.total_bytes",
        checked_bundle.computed.total_bytes,
        total_bytes,
    )

    if source_root is not None:
        source_v1_compare(
            mismatches,
            "sources.merkle_root",
            merkle["root"],
            source_root,
        )

    checked_receipt: DatasetV1ReceiptComputed | None = None

    if receipt is not _MISSING:
        receipt_result = verify_dataset_v1_receipt(receipt)
        checked_receipt = receipt_result.computed

        mismatches.extend(
            source_v1_mismatch(
                f"receipt.{entry.field}",
                entry.expected,
                entry.actual,
            )
            for entry in receipt_result.mismatches
        )

        for field in (
            "dataset_key",
            "program",
            "version_label",
            "bundle_digest",
            "dataset_fingerprint",
            "merkle_root",
            "idempotency_key",
            "file_count",
            "total_bytes",
        ):
            source_v1_compare(
                mismatches,
                f"binding.{field}",
                getattr(checked_bundle.computed, field),
                getattr(checked_receipt, field),
            )

        receipt_view = cast(dict[str, object], receipt)
        receipt_rules = receipt_view["rules"]

        bundle_rules_digest = canonicalize_hf_v1_json(rules).hex()
        receipt_rules_digest = canonicalize_hf_v1_json(receipt_rules).hex()

        if bundle_rules_digest != receipt_rules_digest:
            mismatches.append(
                source_v1_mismatch(
                    "binding.rules",
                    "matches bundle rules",
                    "mismatch",
                )
            )

    return DatasetV1SourceResult(
        ok=not mismatches,
        mismatches=tuple(mismatches),
        computed=DatasetV1SourceComputed(
            bundle=checked_bundle.computed,
            receipt=checked_receipt,
            source_merkle_root=source_root,
            source_file_count=len(sources),
            source_total_bytes=total_bytes,
        ),
    )