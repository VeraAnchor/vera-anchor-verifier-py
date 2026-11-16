"""Exact historical HCS-26 skill resolution through Hedera Mirror."""

import re
import time
from dataclasses import dataclass, replace
from typing import Literal, cast

from ..contracts import HederaNetwork
from ..standards.hcs.hcs1_v1 import Hcs1V1ContentOptions, parse_hcs1_reference_v1
from ..standards.hcs.hcs26_v1 import (
    Hcs26V1Error,
    Hcs26VersionRegisterV1,
    Hcs26VersionVerificationInput,
    parse_hcs26_discovery_register_v1,
    parse_hcs26_skill_manifest_v1,
    parse_hcs26_version_register_v1,
    verify_hcs26_skill_version_v1,
)
from .hcs1_mirror_v1 import Hcs1MirrorV1Config, Hcs1MirrorV1Request, resolve_hcs1_file_v1
from .hcs26_registry_mirror_v1 import (
    Hcs26RegistryRequestV1,
    read_hcs26_registry_message_v1,
)

_TOPIC_RE = re.compile(r"^0\.0\.[0-9]+$", re.ASCII)
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$", re.ASCII)

_MAX_SAFE_INTEGER = (1 << 53) - 1
_MAX_MANIFEST_FILES = 256
_MAX_MANIFEST_FILES_TOTAL_BYTES = 32 * 1024 * 1024
_MANIFEST_FILES_TOTAL_TIMEOUT_MS = 60_000

type Hcs26MirrorStatusV1 = Literal[
    "resolved",
    "conflict",
    "invalid",
    "unavailable",
    "unsupported",
]


@dataclass(frozen=True, slots=True)
class Hcs26MirrorV1Request:
    hedera_network: HederaNetwork
    discovery_topic_id: str
    discovery_sequence_number: int
    version_sequence_number: int
    expected_skill_uid: int | None = None
    expected_account_id: str | None = None
    expected_version_topic_id: str | None = None
    expected_version: str | None = None
    expected_manifest_reference: str | None = None
    expected_manifest_sha256: str | None = None


@dataclass(frozen=True, slots=True)
class Hcs26ManifestFileResolutionV1:
    path: str
    reference: str
    expected_sha256: str
    observed_sha256: str | None
    byte_length: int | None
    status: Hcs26MirrorStatusV1
    reason_code: str | None


@dataclass(frozen=True, slots=True)
class Hcs26ManifestFilesResolutionV1:
    status: Hcs26MirrorStatusV1
    reason_code: str | None
    declared_file_count: int
    resolved_file_count: int
    total_bytes: int
    files: tuple[Hcs26ManifestFileResolutionV1, ...]


@dataclass(frozen=True, slots=True)
class Hcs26MirrorV1Result:
    status: Hcs26MirrorStatusV1
    reason_code: str | None
    hedera_network: HederaNetwork
    resolver_id: Literal["hedera.mirror-rest.hcs26.v1"]
    discovery_topic_id: str
    discovery_sequence_number: int
    discovery_consensus_timestamp_exact: str | None
    publisher_account_id: str | None
    version_topic_id: str | None
    registry_memo_temporal_scope: Literal["current_observation"]
    version_sequence_number: int
    version_consensus_timestamp_exact: str | None
    historical_version_status: Literal[
        "active",
        "deprecated",
        "yanked",
    ] | None
    skill_uid: int | None
    version: str | None
    manifest_reference: str | None
    content_sha256: str | None
    manifest_sha256: str | None
    manifest: dict[str, object] | None
    manifest_files: Hcs26ManifestFilesResolutionV1 | None
    assurance: Literal["mirror_corroborated"]


@dataclass(frozen=True, slots=True)
class _ManifestFileDeclaration:
    path: str
    hrl: str
    sha256: str


def _js_length(value: str) -> int:
    return len(value.encode("utf-16-le", "surrogatepass")) // 2


def _safe_positive(value: object) -> bool:
    return (
        not isinstance(value, bool)
        and isinstance(value, int)
        and 1 <= value <= _MAX_SAFE_INTEGER
    )


def _validate_request(request: Hcs26MirrorV1Request) -> None:
    if (
        request.hedera_network not in {"mainnet", "testnet"}
        or not isinstance(request.discovery_topic_id, str)
        or _TOPIC_RE.fullmatch(request.discovery_topic_id) is None
        or not _safe_positive(request.discovery_sequence_number)
        or not _safe_positive(request.version_sequence_number)
        or (
            request.expected_skill_uid is not None
            and not _safe_positive(request.expected_skill_uid)
        )
        or (
            request.expected_account_id is not None
            and (
                not isinstance(request.expected_account_id, str)
                or _TOPIC_RE.fullmatch(request.expected_account_id) is None
            )
        )
        or (
            request.expected_version_topic_id is not None
            and (
                not isinstance(request.expected_version_topic_id, str)
                or _TOPIC_RE.fullmatch(
                    request.expected_version_topic_id
                ) is None
            )
        )
        or (
            request.expected_manifest_sha256 is not None
            and (
                not isinstance(request.expected_manifest_sha256, str)
                or _SHA256_RE.fullmatch(
                    request.expected_manifest_sha256
                ) is None
            )
        )
    ):
        raise TypeError("HCS26_VERIFICATION_LOCATOR_INVALID")

    if request.expected_manifest_reference is not None:
        parse_hcs1_reference_v1(
            request.expected_manifest_reference
        )

    if (
        request.expected_version is not None
        and (
            not isinstance(request.expected_version, str)
            or not request.expected_version
            or _js_length(request.expected_version) > 64
        )
    ):
        raise TypeError("HCS26_EXPECTED_VERSION_INVALID")


def _manifest_files_of(
    manifest: dict[str, object],
) -> tuple[_ManifestFileDeclaration, ...]:
    entries = manifest.get("files")

    if (
        type(entries) is not list
        or not 1 <= len(entries) <= _MAX_MANIFEST_FILES
    ):
        raise Hcs26V1Error("HCS26_FILES_INVALID")

    output: list[_ManifestFileDeclaration] = []

    for entry in cast(list[object], entries):
        if type(entry) is not dict:
            raise Hcs26V1Error("HCS26_FILES_INVALID")

        row = cast(dict[str, object], entry)
        path = row.get("path")
        hrl = row.get("hrl")
        sha256 = row.get("sha256")

        if (
            not isinstance(path, str)
            or not path
            or _js_length(path) > 512
            or not isinstance(hrl, str)
            or not isinstance(sha256, str)
            or _SHA256_RE.fullmatch(sha256) is None
        ):
            raise Hcs26V1Error("HCS26_FILES_INVALID")

        reference = parse_hcs1_reference_v1(hrl).reference
        output.append(
            _ManifestFileDeclaration(
                path=path,
                hrl=reference,
                sha256=sha256,
            )
        )

    return tuple(output)


def _file_result(
    file: _ManifestFileDeclaration,
    status: Hcs26MirrorStatusV1,
    reason_code: str | None,
    observed_sha256: str | None = None,
    byte_length: int | None = None,
) -> Hcs26ManifestFileResolutionV1:
    return Hcs26ManifestFileResolutionV1(
        path=file.path,
        reference=file.hrl,
        expected_sha256=file.sha256,
        observed_sha256=observed_sha256,
        byte_length=byte_length,
        status=status,
        reason_code=reason_code,
    )


async def _resolve_manifest_files_v1(
    config: Hcs1MirrorV1Config,
    network: HederaNetwork,
    manifest: dict[str, object],
    decode_options: Hcs1V1ContentOptions,
) -> Hcs26ManifestFilesResolutionV1:
    declarations = _manifest_files_of(manifest)
    files: list[Hcs26ManifestFileResolutionV1] = []
    deadline = (
        time.monotonic()
        + _MANIFEST_FILES_TOTAL_TIMEOUT_MS / 1000
    )
    configured_file_limit = decode_options.max_file_bytes
    total_bytes = 0

    def output(
        status: Hcs26MirrorStatusV1,
        reason_code: str | None,
    ) -> Hcs26ManifestFilesResolutionV1:
        return Hcs26ManifestFilesResolutionV1(
            status=status,
            reason_code=reason_code,
            declared_file_count=len(declarations),
            resolved_file_count=sum(
                file.status == "resolved"
                for file in files
            ),
            total_bytes=total_bytes,
            files=tuple(files),
        )

    # Sequential by design: one outstanding HCS-1 read, deterministic manifest
    # order, and strict aggregate time/byte budgets.
    for file in declarations:
        remaining_ms = int(
            (deadline - time.monotonic()) * 1000
        )

        if remaining_ms < 250:
            return output(
                "unavailable",
                "HCS26_MANIFEST_FILES_TIMEOUT",
            )

        remaining_bytes = (
            _MAX_MANIFEST_FILES_TOTAL_BYTES
            - total_bytes
        )

        if remaining_bytes < 1:
            return output(
                "unsupported",
                "HCS26_MANIFEST_FILES_TOTAL_BYTES_EXCEEDED",
            )

        effective_file_limit = min(
            configured_file_limit,
            remaining_bytes,
        )
        read_config = replace(
            config,
            total_timeout_ms=min(
                config.total_timeout_ms,
                remaining_ms,
            ),
        )
        file_decode_options = replace(
            decode_options,
            max_file_bytes=effective_file_limit,
        )

        observed = await resolve_hcs1_file_v1(
            read_config,
            Hcs1MirrorV1Request(
                network=network,
                reference=file.hrl,
            ),
            file_decode_options,
        )

        if (
            observed.status != "resolved"
            or observed.verification is None
            or observed.verification.bytes is None
            or observed.verification.sha256 is None
        ):
            aggregate_limited = (
                effective_file_limit < configured_file_limit
                and observed.reason_code
                == "HCS1_FILE_TOO_LARGE"
            )
            timed_out = (
                time.monotonic() >= deadline
                and observed.status == "unavailable"
            )

            if aggregate_limited:
                status: Hcs26MirrorStatusV1 = "unsupported"
                reason = (
                    "HCS26_MANIFEST_FILES_TOTAL_BYTES_EXCEEDED"
                )
            elif timed_out:
                status = "unavailable"
                reason = "HCS26_MANIFEST_FILES_TIMEOUT"
            elif observed.status == "resolved":
                status = "invalid"
                reason = (
                    "HCS26_MANIFEST_FILE_OBSERVATION_INVALID"
                )
            else:
                status = observed.status
                reason = (
                    observed.reason_code
                    or "HCS26_MANIFEST_FILE_UNAVAILABLE"
                )

            files.append(
                _file_result(
                    file,
                    status,
                    reason,
                )
            )
            return output(status, reason)

        observed_hash = observed.verification.sha256
        byte_length = len(observed.verification.bytes)

        if observed_hash != file.sha256:
            reason = (
                "HCS26_MANIFEST_FILE_CHECKSUM_MISMATCH"
            )
            files.append(
                _file_result(
                    file,
                    "conflict",
                    reason,
                    observed_hash,
                    byte_length,
                )
            )
            return output("conflict", reason)

        total_bytes += byte_length
        files.append(
            _file_result(
                file,
                "resolved",
                None,
                observed_hash,
                byte_length,
            )
        )

    return output("resolved", None)


async def resolve_hcs26_skill_version_v1(
    config: Hcs1MirrorV1Config,
    request: Hcs26MirrorV1Request,
    decode_options: Hcs1V1ContentOptions | None = None,
) -> Hcs26MirrorV1Result:
    """
    Resolve exact historical HCS-26 discovery/version entries and pinned files.

    This does not reconstruct current registry state, authenticate a publisher,
    or authenticate Hedera consensus.
    """
    _validate_request(request)
    options = decode_options or Hcs1V1ContentOptions()

    discovery_time: str | None = None
    publisher_account: str | None = None
    version_topic: str | None = None
    version_time: str | None = None
    register: Hcs26VersionRegisterV1 | None = None
    manifest_ref: str | None = None
    content_hash: str | None = None
    manifest_hash: str | None = None
    manifest: dict[str, object] | None = None
    manifest_files: Hcs26ManifestFilesResolutionV1 | None = None

    def output(
        status: Hcs26MirrorStatusV1,
        reason_code: str | None,
    ) -> Hcs26MirrorV1Result:
        return Hcs26MirrorV1Result(
            status=status,
            reason_code=reason_code,
            hedera_network=request.hedera_network,
            resolver_id="hedera.mirror-rest.hcs26.v1",
            discovery_topic_id=request.discovery_topic_id,
            discovery_sequence_number=(
                request.discovery_sequence_number
            ),
            discovery_consensus_timestamp_exact=(
                discovery_time
            ),
            publisher_account_id=publisher_account,
            version_topic_id=version_topic,
            registry_memo_temporal_scope=(
                "current_observation"
            ),
            version_sequence_number=(
                request.version_sequence_number
            ),
            version_consensus_timestamp_exact=version_time,
            historical_version_status=(
                register.status
                if register is not None
                else None
            ),
            skill_uid=(
                register.skill_uid
                if register is not None
                else None
            ),
            version=(
                register.version
                if register is not None
                else None
            ),
            manifest_reference=manifest_ref,
            content_sha256=content_hash,
            manifest_sha256=manifest_hash,
            manifest=manifest,
            manifest_files=manifest_files,
            assurance="mirror_corroborated",
        )

    if (
        request.expected_skill_uid is not None
        and request.expected_skill_uid
        != request.discovery_sequence_number
    ):
        return output(
            "conflict",
            "HCS26_SKILL_UID_MISMATCH",
        )

    discovery = await read_hcs26_registry_message_v1(
        config,
        Hcs26RegistryRequestV1(
            hedera_network=request.hedera_network,
            topic_id=request.discovery_topic_id,
            sequence_number=request.discovery_sequence_number,
            registry_type="discovery",
        ),
    )

    if (
        discovery.status != "resolved"
        or discovery.evidence is None
    ):
        return output(
            discovery.status,
            discovery.reason_code
            or "HCS26_DISCOVERY_UNAVAILABLE",
        )

    discovery_time = discovery.evidence.consensus_timestamp

    try:
        decoded_discovery = parse_hcs26_discovery_register_v1(
            discovery.evidence.message
        )
    except Hcs26V1Error as exc:
        return output("invalid", exc.code)

    version_topic = cast(
        str,
        decoded_discovery["t_id"],
    )
    publisher_account = cast(
        str,
        decoded_discovery["account_id"],
    )

    if (
        request.expected_version_topic_id is not None
        and version_topic
        != request.expected_version_topic_id
    ):
        return output(
            "conflict",
            "HCS26_VERSION_TOPIC_MISMATCH",
        )

    if (
        request.expected_account_id is not None
        and publisher_account
        != request.expected_account_id
    ):
        return output(
            "conflict",
            "HCS26_PUBLISHER_ACCOUNT_MISMATCH",
        )

    version = await read_hcs26_registry_message_v1(
        config,
        Hcs26RegistryRequestV1(
            hedera_network=request.hedera_network,
            topic_id=version_topic,
            sequence_number=request.version_sequence_number,
            registry_type="version",
        ),
    )

    if version.status != "resolved" or version.evidence is None:
        return output(
            version.status,
            version.reason_code
            or "HCS26_VERSION_UNAVAILABLE",
        )

    version_time = version.evidence.consensus_timestamp

    try:
        register = parse_hcs26_version_register_v1(
            version.evidence.message
        )
    except Hcs26V1Error as exc:
        return output("invalid", exc.code)

    if register.skill_uid != request.discovery_sequence_number:
        return output(
            "conflict",
            "HCS26_SKILL_UID_MISMATCH",
        )

    if (
        request.expected_version is not None
        and register.version != request.expected_version
    ):
        return output(
            "conflict",
            "HCS26_VERSION_MISMATCH",
        )

    manifest_ref = f"hcs://1/{register.t_id}"

    if (
        request.expected_manifest_reference is not None
        and manifest_ref
        != request.expected_manifest_reference
    ):
        return output(
            "conflict",
            "HCS26_MANIFEST_REFERENCE_MISMATCH",
        )

    content = await resolve_hcs1_file_v1(
        config,
        Hcs1MirrorV1Request(
            network=request.hedera_network,
            reference=manifest_ref,
            expected_sha256=request.expected_manifest_sha256,
        ),
        options,
    )

    if (
        content.status != "resolved"
        or content.verification is None
        or content.verification.bytes is None
        or content.verification.sha256 is None
    ):
        status: Hcs26MirrorStatusV1 = (
            "conflict"
            if content.reason_code
            == "HCS1_EXPECTED_CHECKSUM_MISMATCH"
            else content.status
        )
        return output(
            status,
            content.reason_code
            or "HCS26_MANIFEST_UNAVAILABLE",
        )

    content_hash = content.verification.sha256

    verified = verify_hcs26_skill_version_v1(
        Hcs26VersionVerificationInput(
            version_register=version.evidence.message,
            manifest=content.verification.bytes,
            expected_skill_uid=request.discovery_sequence_number,
            expected_version=request.expected_version,
            expected_sha256=request.expected_manifest_sha256,
        )
    )

    manifest_hash = verified.sha256

    if verified.status != "pass":
        status = (
            "conflict"
            if verified.reason_code
            in {
                "HCS26_CHECKSUM_MISMATCH",
                "HCS26_VERSION_MISMATCH",
                "HCS26_EXPECTED_CHECKSUM_MISMATCH",
            }
            else "invalid"
        )
        return output(
            status,
            verified.reason_code,
        )

    try:
        parsed = parse_hcs26_skill_manifest_v1(
            content.verification.bytes
        )
        manifest_hash = parsed.sha256

        if (
            parsed.canonical_payload.encode("utf-8")
            != content.verification.bytes
        ):
            return output(
                "unsupported",
                "HCS26_MANIFEST_CONTENT_NOT_CANONICAL",
            )

        if manifest_hash != content_hash:
            return output(
                "conflict",
                "HCS26_CANONICAL_CONTENT_MISMATCH",
            )

        manifest = parsed.manifest

        manifest_files = await _resolve_manifest_files_v1(
            config,
            request.hedera_network,
            manifest,
            options,
        )

        if manifest_files.status != "resolved":
            return output(
                manifest_files.status,
                manifest_files.reason_code,
            )

        return output("resolved", None)

    except Hcs26V1Error as exc:
        return output("invalid", exc.code)