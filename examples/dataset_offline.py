"""Minimal offline Dataset verification example."""

import asyncio
import json
import sys
from dataclasses import asdict
from pathlib import Path
from typing import cast

from vera_anchor_verifier import HederaNetwork, SourceV1File, verify_dataset_v1_with_intent


def read_json(path: str) -> object:
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


async def main() -> int:
    if len(sys.argv) != 7:
        print(
            "Usage: python examples/dataset_offline.py "
            "<bundle.json> <receipt.json> <source-file> <producer-relative-path> "
            "<dataset-key> <mainnet|testnet>",
            file=sys.stderr,
        )
        return 64

    bundle_path, receipt_path, source_path, path_rel, dataset_key, network = sys.argv[1:]

    if network not in {"mainnet", "testnet"}:
        print("Network must be mainnet or testnet", file=sys.stderr)
        return 64

    bundle = read_json(bundle_path)
    receipt = read_json(receipt_path)
    source_bytes = Path(source_path).read_bytes()

    files: list[SourceV1File] = [
        {
            "path_rel": path_rel,
            "source": [source_bytes],
        }
    ]

    report = await verify_dataset_v1_with_intent(
        bundle=bundle,
        receipt=receipt,
        files=files,
        intent={
            "subject": {
                "kind": "dataset",
                "id": dataset_key,
                "hedera_network": cast(HederaNetwork, network),
            },
            "expected": [],
        },
    )

    print(json.dumps(asdict(report), indent=2))

    return 1 if any(finding.outcome == "fail" for finding in report.findings) else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))