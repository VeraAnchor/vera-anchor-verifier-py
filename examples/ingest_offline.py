"""Minimal offline Ingest verification example."""

import asyncio
import json
import sys
from dataclasses import asdict
from pathlib import Path

from vera_anchor_verifier import verify_ingest_v1_with_intent


def read_json(path: str) -> object:
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def read_material(path: str) -> object:
    material = read_json(path)

    if (
        not isinstance(material, dict)
        or material.get("kind") not in {"json", "text"}
    ):
        raise TypeError(
            "This example supports JSON and text Ingest material. "
            "Use the library API directly for file and file-set sources."
        )

    return material


async def main() -> int:
    if len(sys.argv) != 5:
        print(
            "Usage: python examples/ingest_offline.py "
            "<bundle.json> <material.json> <receipt.json> <intent.json>",
            file=sys.stderr,
        )
        return 64

    bundle_path, material_path, receipt_path, intent_path = sys.argv[1:]

    report = await verify_ingest_v1_with_intent(
        bundle=read_json(bundle_path),
        material=read_material(material_path),
        receipt=read_json(receipt_path),
        intent=read_json(intent_path),
    )

    print(json.dumps(asdict(report), indent=2))

    return 1 if any(finding.outcome == "fail" for finding in report.findings) else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))