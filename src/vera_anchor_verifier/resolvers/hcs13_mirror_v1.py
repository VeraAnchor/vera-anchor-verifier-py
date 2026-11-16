"""Exact historical HCS-13 registry to HCS-1 schema resolution."""

import re
from dataclasses import dataclass
from typing import Literal

from ..contracts import HederaNetwork
from ..standards.hcs.hcs1_v1 import Hcs1V1ContentOptions, parse_hcs1_reference_v1
from ..standards.hcs.hcs13_v1 import (
    Hcs13ReferenceV1,
    Hcs13SchemaVerificationInput,
    Hcs13V1Error,
    parse_hcs13_reference_v1,
    parse_hcs13_schema_v1,
    verify_hcs13_schema_v1,
)
from .hcs1_mirror_v1 import Hcs1MirrorV1Config, Hcs1MirrorV1Request, resolve_hcs1_file_v1
from .hcs2_mirror_v1 import Hcs2MirrorV1Request, resolve_hcs2_register_v1

_SHA256_RE = re.compile("^[0-9a-f]{64}$", re.ASCII)

type Hcs13MirrorStatusV1 = Literal["resolved", "conflict", "invalid", "unavailable", "unsupported"]


@dataclass(frozen=True, slots=True)
class Hcs13MirrorV1Request:
    hedera_network: HederaNetwork
    reference: str
    expected_hcs1_reference: str | None = None
    expected_schema_sha256: str | None = None


@dataclass(frozen=True, slots=True)
class Hcs13MirrorV1Result:
    status: Hcs13MirrorStatusV1
    reason_code: str | None
    hedera_network: HederaNetwork
    resolver_id: Literal["hedera.mirror-rest.hcs13.v1"]
    reference: Hcs13ReferenceV1
    registry_consensus_timestamp_exact: str | None
    registry_memo_temporal_scope: Literal["current_observation"]
    schema_hcs1_reference: str | None
    content_sha256: str | None
    schema_sha256: str | None
    schema: dict[str, object] | None
    assurance: Literal["mirror_corroborated"]


def _validate_request(request: Hcs13MirrorV1Request) -> Hcs13ReferenceV1:
    network: object = request.hedera_network
    if network not in {"mainnet", "testnet"}:
        raise TypeError("HCS13_NETWORK_INVALID")

    reference = parse_hcs13_reference_v1(request.reference)
    expected_reference: object = request.expected_hcs1_reference

    if expected_reference is not None:
        parse_hcs1_reference_v1(expected_reference)

    expected_sha: object = request.expected_schema_sha256
    if (
        expected_sha is not None
        and (not isinstance(expected_sha, str) or _SHA256_RE.fullmatch(expected_sha) is None)
    ):
        raise TypeError("HCS13_EXPECTED_CHECKSUM_INVALID")

    return reference


async def resolve_hcs13_schema_v1(
    config: Hcs1MirrorV1Config,
    request: Hcs13MirrorV1Request,
    decode_options: Hcs1V1ContentOptions | None = None,
) -> Hcs13MirrorV1Result:
    """
    Resolve one exact historical HCS-13 schema through Hedera Mirror.

    This does not reconstruct current registry state, perform JSON Schema
    instance validation, authenticate a publisher, or prove Hedera consensus.
    """
    reference = _validate_request(request)
    registry_time: str | None = None
    content_reference: str | None = None
    content_sha256: str | None = None
    schema_sha256: str | None = None
    schema: dict[str, object] | None = None

    def result(
        status: Hcs13MirrorStatusV1,
        reason_code: str | None,
    ) -> Hcs13MirrorV1Result:
        return Hcs13MirrorV1Result(
            status=status,
            reason_code=reason_code,
            hedera_network=request.hedera_network,
            resolver_id="hedera.mirror-rest.hcs13.v1",
            reference=reference,
            registry_consensus_timestamp_exact=registry_time,
            registry_memo_temporal_scope="current_observation",
            schema_hcs1_reference=content_reference,
            content_sha256=content_sha256,
            schema_sha256=schema_sha256,
            schema=schema,
            assurance="mirror_corroborated",
        )

    expected_topic: str | None = None
    if request.expected_hcs1_reference is not None:
        expected_topic = parse_hcs1_reference_v1(request.expected_hcs1_reference).topic_id

    registry = await resolve_hcs2_register_v1(
        config,
        Hcs2MirrorV1Request(
            hedera_network=request.hedera_network,
            registry_topic_id=reference.registry_topic_id,
            sequence_number=reference.sequence_number,
            expected_t_id=expected_topic,
        ),
    )

    if (
        registry.status != "resolved"
        or registry.verification is None
        or registry.verification.register is None
        or registry.consensus_timestamp is None
    ):
        if registry.status == "conflict":
            mapped_registry: Hcs13MirrorStatusV1 = "conflict"
        elif registry.status == "invalid":
            mapped_registry = "invalid"
        else:
            mapped_registry = "unavailable"

        return result(
            mapped_registry,
            registry.reason_code or "HCS13_REGISTRY_ENTRY_UNAVAILABLE",
        )

    registry_time = registry.consensus_timestamp
    content_reference = f"hcs://1/{registry.verification.register.t_id}"

    content = await resolve_hcs1_file_v1(
        config,
        Hcs1MirrorV1Request(
            network=request.hedera_network,
            reference=content_reference,
            expected_sha256=request.expected_schema_sha256,
        ),
        decode_options,
    )

    if (
        content.status != "resolved"
        or content.verification is None
        or content.verification.bytes is None
        or content.verification.sha256 is None
    ):
        if content.reason_code == "HCS1_EXPECTED_CHECKSUM_MISMATCH":
            mapped_content: Hcs13MirrorStatusV1 = "conflict"
        elif content.reason_code == "HCS1_CHECKSUM_MISMATCH":
            mapped_content = "invalid"
        elif content.status == "unsupported":
            mapped_content = "unsupported"
        elif content.status == "invalid":
            mapped_content = "invalid"
        elif content.status == "conflict":
            mapped_content = "conflict"
        else:
            mapped_content = "unavailable"

        return result(
            mapped_content,
            content.reason_code or "HCS13_SCHEMA_CONTENT_UNAVAILABLE",
        )

    content_sha256 = content.verification.sha256
    verification = verify_hcs13_schema_v1(
        Hcs13SchemaVerificationInput(
            reference=reference.ref,
            schema=content.verification.bytes,
            expected_sha256=request.expected_schema_sha256,
        )
    )

    if verification.status != "pass":
        return result(
            (
                "conflict"
                if verification.reason_code == "HCS13_CHECKSUM_MISMATCH"
                else "invalid"
            ),
            verification.reason_code,
        )

    try:
        parsed = parse_hcs13_schema_v1(content.verification.bytes)
        schema_sha256 = parsed.sha256
        canonical_bytes = parsed.canonical_payload.encode("utf-8")

        if canonical_bytes != content.verification.bytes:
            return result(
                "unsupported",
                "HCS13_SCHEMA_CONTENT_NOT_CANONICAL",
            )

        if schema_sha256 != content_sha256:
            return result(
                "conflict",
                "HCS13_CANONICAL_CONTENT_MISMATCH",
            )

        schema = parsed.schema
        return result("resolved", None)

    except Hcs13V1Error as exc:
        return result("invalid", exc.code)