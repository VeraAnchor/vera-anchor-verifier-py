"""Authenticated Dataset verification with relying-party policy."""

import asyncio
import json
import os
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Literal, cast

from vera_anchor_verifier import (
    AuthorizedDatasetTriangulationV1Input,
    AuthorizedHcsObservationsV1Config,
    CoreAuthorizedV1Config,
    PortableVerificationReportKindV1,
    SourceV1File,
    VerificationPolicyAssuranceV1,
    VerificationPolicyV1,
    VerificationSubject,
    create_static_bearer_auth_provider_v1,
    triangulate_authorized_dataset_with_policy_v1,
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
        report_kind=cast(
            PortableVerificationReportKindV1,
            value["report_kind"],
        ),
        required_checks=tuple(cast(list[str], value["required_checks"])),
        required_assurance=cast(
            tuple[VerificationPolicyAssuranceV1, ...],
            tuple(value.get("required_assurance", [])),
        ),
        on_unresolved=cast(
            Literal["review", "deny"],
            value.get("on_unresolved", "review"),
        ),
    )


async def main() -> int:
    if len(sys.argv) != 8:
        print(
            "Usage: VERA_ANCHOR_CORE_URL=<url> VERA_ANCHOR_API_KEY=<key> "
            "python examples/authorized_dataset_policy.py "
            "<bundle.json> <receipt.json> <source-file> <producer-relative-path> "
            "<intent.json> <policy.json> <message-id>",
            file=sys.stderr,
        )
        return 64

    core_url = os.environ.get("VERA_ANCHOR_CORE_URL")
    api_key = os.environ.get("VERA_ANCHOR_API_KEY")
    if not core_url or not api_key:
        print(
            "VERA_ANCHOR_CORE_URL and VERA_ANCHOR_API_KEY are required",
            file=sys.stderr,
        )
        return 64

    (
        bundle_path,
        receipt_path,
        source_path,
        path_rel,
        intent_path,
        policy_path,
        message_id,
    ) = sys.argv[1:]

    files: list[SourceV1File] = [
        {
            "path_rel": path_rel,
            "source": [Path(source_path).read_bytes()],
        }
    ]
    input: AuthorizedDatasetTriangulationV1Input = {
        "bundle": read_json(bundle_path),
        "receipt": read_json(receipt_path),
        "files": files,
        "intent": read_json(intent_path),
        "hcs_reference": {"message_id": message_id},
    }
    config = AuthorizedHcsObservationsV1Config(
        core=CoreAuthorizedV1Config(
            base_url=core_url,
            auth_provider=create_static_bearer_auth_provider_v1(api_key),
        )
    )

    result = await triangulate_authorized_dataset_with_policy_v1(
        config,
        input,
        read_policy(policy_path),
    )

    print(json.dumps(asdict(result), indent=2))

    return (
        0
        if result.policy.decision == "allow"
        else 2
        if result.policy.decision == "review"
        else 1
    )


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))