"""Bind actual source material to Ingest v1 evidence."""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import cast

from ...crypto import ByteChunkSource
from ..source_v1_helpers import (
    SourceV1Limits,
    SourceV1Mismatch,
    source_v1_compare,
    source_v1_hash_file,
    source_v1_json_material,
    source_v1_leaf,
    source_v1_limits,
    source_v1_media_type,
    source_v1_mismatch,
    source_v1_path,
    source_v1_path_digest,
    source_v1_root,
    source_v1_sort_key,
    source_v1_text_file,
    source_v1_text_material,
    source_v1_trim,
)
from .v1 import (
    IngestV1BundleComputed,
    IngestV1ReceiptComputed,
    verify_ingest_v1_bundle,
    verify_ingest_v1_pair,
)

_MISSING = object()


@dataclass(frozen=True, slots=True)
class IngestV1SourceComputed:
    bundle: IngestV1BundleComputed
    receipt: IngestV1ReceiptComputed | None
    source_merkle_root: str
    source_item_count: int
    source_total_bytes: int


@dataclass(frozen=True, slots=True)
class IngestV1SourceResult:
    ok: bool
    mismatches: tuple[SourceV1Mismatch, ...]
    computed: IngestV1SourceComputed


async def verify_ingest_v1_sources(
    *,
    bundle: object,
    material: object,
    receipt: object = _MISSING,
    limits: SourceV1Limits | None = None,
) -> IngestV1SourceResult:
    if receipt is _MISSING:
        bundle_result = verify_ingest_v1_bundle(bundle)
        checked_bundle = bundle_result.computed
        checked_receipt: IngestV1ReceiptComputed | None = None
        mismatches = [
            source_v1_mismatch(entry.field, entry.expected, entry.actual)
            for entry in bundle_result.mismatches
        ]
    else:
        pair_result = verify_ingest_v1_pair(
            bundle=bundle,
            receipt=receipt,
        )
        checked_bundle = pair_result.computed.bundle
        checked_receipt = pair_result.computed.receipt
        mismatches = [
            source_v1_mismatch(entry.field, entry.expected, entry.actual)
            for entry in pair_result.mismatches
        ]

    bundle_view = cast(dict[str, object], bundle)
    identity = cast(dict[str, object], bundle_view["identity"])
    rules = cast(dict[str, object], bundle_view["rules"])
    declared_items = cast(list[dict[str, object]], bundle_view["items"])

    if not isinstance(material, Mapping):
        raise TypeError("Ingest material kind does not match bundle identity")

    material_kind = material.get("kind")

    if material_kind != identity["object_kind"]:
        raise TypeError("Ingest material kind does not match bundle identity")

    max_total, max_file = source_v1_limits(limits)
    computed_items: list[dict[str, object]] = []
    total_bytes = 0

    if material_kind == "json":
        hashed = source_v1_json_material(material.get("value"))

        if hashed.bytes > max_file or hashed.bytes > max_total:
            raise ValueError("Ingest source material exceeds byte limit")

        total_bytes = hashed.bytes
        json_item: dict[str, object] = {
            "item_kind": "json",
            "media_type": "application/json",
            "bytes": hashed.bytes,
            "sha3_512": hashed.sha3_512,
        }
        json_item["leaf_hash"] = source_v1_leaf(
            "ingest",
            item_kind="json",
            media_type="application/json",
            bytes_count=hashed.bytes,
            sha3_512=hashed.sha3_512,
        )
        computed_items.append(json_item)

    elif material_kind == "text":
        hashed = source_v1_text_material(material.get("text"))

        if hashed.bytes > max_file or hashed.bytes > max_total:
            raise ValueError("Ingest source material exceeds byte limit")

        total_bytes = hashed.bytes
        raw_media_type = material.get("media_type")

        if raw_media_type is not None and not isinstance(raw_media_type, str):
            raise TypeError("Invalid Ingest text media type")

        media_type = (
            source_v1_trim(raw_media_type)
            if isinstance(raw_media_type, str)
            else ""
        )

        text_item: dict[str, object] = {
            "item_kind": "text",
            "bytes": hashed.bytes,
            "sha3_512": hashed.sha3_512,
        }

        if media_type:
            text_item["media_type"] = media_type

        text_item["leaf_hash"] = source_v1_leaf(
            "ingest",
            item_kind="text",
            media_type=media_type or None,
            bytes_count=hashed.bytes,
            sha3_512=hashed.sha3_512,
        )
        computed_items.append(text_item)

    else:
        if material_kind == "file":
            provided_files: object = [material.get("file")]
        else:
            provided_files = material.get("files")

        if (
            type(provided_files) is not list
            or not provided_files
            or len(provided_files) > 5_000
        ):
            raise TypeError(
                "Ingest source files must be a nonempty bounded array"
            )

        seen: set[str] = set()

        for raw_entry in cast(list[object], provided_files):
            if not isinstance(raw_entry, Mapping):
                raise TypeError("Ingest source file must be an object")

            path = source_v1_path(raw_entry.get("path_rel"), 1024)

            if path in seen:
                raise TypeError("Duplicate Ingest source path")

            if material_kind == "file" and "/" in path:
                raise TypeError(
                    "Single-file Ingest source must use a basename"
                )

            seen.add(path)

            normalize_text = (
                material_kind == "file_set"
                and bool(rules["normalize_line_endings"])
                and source_v1_text_file(path)
            )

            hashed = await source_v1_hash_file(
                cast(ByteChunkSource, raw_entry.get("source")),
                min(max_file, max_total - total_bytes),
                normalize_text,
            )
            total_bytes += hashed.bytes

            path_rel: str | None = None
            path_hash: str | None = None

            if material_kind == "file_set" and bool(rules["redact_paths"]):
                path_hash = source_v1_path_digest(path, "ingest")
            else:
                path_rel = path

            detected_media_type = source_v1_media_type(path)

            file_item: dict[str, object] = {
                "item_kind": "file",
                "bytes": hashed.bytes,
                "sha3_512": hashed.sha3_512,
            }

            if path_rel is not None:
                file_item["path_rel"] = path_rel
            if path_hash is not None:
                file_item["path_hash"] = path_hash
            if detected_media_type is not None:
                file_item["media_type"] = detected_media_type

            file_item["leaf_hash"] = source_v1_leaf(
                "ingest",
                item_kind="file",
                path_rel=path_rel,
                path_hash=path_hash,
                media_type=detected_media_type,
                bytes_count=hashed.bytes,
                sha3_512=hashed.sha3_512,
            )
            computed_items.append(file_item)

    computed_items.sort(
        key=lambda item: (
            source_v1_sort_key(
                cast(
                    str,
                    item.get("path_rel")
                    or item.get("path_hash")
                    or "",
                )
            ),
            source_v1_sort_key(cast(str, item["item_kind"])),
            source_v1_sort_key(cast(str, item["sha3_512"])),
        )
    )

    source_v1_compare(
        mismatches,
        "sources.item_count",
        len(declared_items),
        len(computed_items),
    )
    source_v1_compare(
        mismatches,
        "sources.total_bytes",
        checked_bundle.total_bytes,
        total_bytes,
    )

    for index, computed in enumerate(computed_items):
        declared = (
            declared_items[index]
            if index < len(declared_items)
            else None
        )

        for field in (
            "item_kind",
            "path_rel",
            "path_hash",
            "media_type",
            "bytes",
            "sha3_512",
            "leaf_hash",
        ):
            source_v1_compare(
                mismatches,
                f"items[{index}].{field}",
                computed.get(field),
                None if declared is None else declared.get(field),
            )

    source_root = source_v1_root(
        "ingest",
        [
            cast(str, item["leaf_hash"])
            for item in computed_items
        ],
    )

    raw_merkle = bundle_view.get("merkle")

    if isinstance(raw_merkle, Mapping):
        source_v1_compare(
            mismatches,
            "sources.merkle_root",
            raw_merkle.get("root"),
            source_root,
        )

    if checked_receipt is not None:
        source_v1_compare(
            mismatches,
            "sources.receipt_merkle_root",
            checked_receipt.merkle_root,
            source_root,
        )

    return IngestV1SourceResult(
        ok=not mismatches,
        mismatches=tuple(mismatches),
        computed=IngestV1SourceComputed(
            bundle=checked_bundle,
            receipt=checked_receipt,
            source_merkle_root=source_root,
            source_item_count=len(computed_items),
            source_total_bytes=total_bytes,
        ),
    )