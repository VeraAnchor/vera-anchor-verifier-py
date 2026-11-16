"""Minimal offline Dataset verification with relying-party policy."""

import asyncio
import json
import sys
from dataclasses import asdict
from pathlib import Path
from typing import cast

from vera_anchor_verifier import (
    PortableVerificationReportKindV1,
    SourceV1File,
    VerificationPolicyAssuranceV1,
    VerificationPolicyV1,
    VerificationSubject,
    verify_dataset_with_policy_v1,
)


def read_json(path: str) -> object:
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def read_policy(path: str) -> VerificationPolicyV1:
    value = read_json(path)

    if not isinstance(value, dict):
        raise TypeError("Policy must be a JSON object")

    return VerificationPolicyV1(
        schema_version="va.verification-policy.v1",
        subject=cast(VerificationSubject, value["subject"]),
        report_kind=cast(PortableVerificationReportKindV1, value["report_kind"]),
        required_checks=tuple(value["required_checks"]),
        required_assurance=cast(
            tuple[VerificationPolicyAssuranceV1, ...],
            tuple(value.get("required_assurance", [])),
        ),
        on_unresolved=cast(str, value.get("on_unresolved", "review")),
    )


async def main() -> int:
    if len(sys.argv) != 7:
        print(
            "Usage: python examples/dataset_policy.py "
            "<bundle.json> <receipt.json> <source-file> <producer-relative-path> "
            "<intent.json> <policy.json>",
            file=sys.stderr,
        )
        return 64

    bundle_path, receipt_path, source_path, path_rel, intent_path, policy_path = sys.argv[1:]

    files: list[SourceV1File] = [
        {
            "path_rel": path_rel,
            "source": [Path(source_path).read_bytes()],
        }
    ]

    result = await verify_dataset_with_policy_v1(
        bundle=read_json(bundle_path),
        receipt=read_json(receipt_path),
        files=files,
        intent=read_json(intent_path),
        policy=read_policy(policy_path),
    )

    print(json.dumps(asdict(result), indent=2))

    return 0 if result.policy.decision == "allow" else (
        2 if result.policy.decision == "review" else 1
    )


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))