"""Normalize bounded Explorer Dataset, Ingest, and Merkle public records."""

import math
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal, cast
from urllib.parse import quote

from ..contracts import (
    HederaNetwork,
    VerificationFact,
    VerificationObservation,
    VerificationSubject,
)
from .explorer_transport_v1 import ExplorerPublicTransportV1, read_explorer_public_v1

_HASH_RE = re.compile(r"^[0-9a-f]{128}$", re.IGNORECASE | re.ASCII)
_KEY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$", re.ASCII)
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$",
    re.IGNORECASE | re.ASCII,
)
_TOPIC_RE = re.compile(r"^0\.0\.[1-9][0-9]*$", re.ASCII)
_MESSAGE_ID_RE = re.compile(r"^(?:(\d+)@(0\.0\.\d+)|(0\.0\.\d+)@(\d+))$", re.ASCII)

_MAX_VALUE = 4096
_MAX_SAFE_INTEGER = (1 << 53) - 1
_RESOLVER_ID = "explorer.public-http.v1"

_ECMASCRIPT_TRIM = (
    "\u0009\u000b\u000c\u0020\u00a0\u1680"
    "\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a"
    "\u2028\u2029\u202f\u205f\u3000\ufeff\u000a\u000d"
)

type ExplorerPublicationEntityKindV1 = Literal[
    "dataset",
    "dataset_version",
    "merkle_anchor",
    "merkle_root",
]
type ExplorerPublicRecordStatusV1 = Literal[
    "resolved",
    "not_found",
    "unavailable",
    "invalid",
    "conflict",
]


@dataclass(frozen=True, slots=True)
class ExplorerPublicationV1:
    hedera_network: HederaNetwork
    entity_kind: ExplorerPublicationEntityKindV1
    entity_id: str
    transaction_id: str | None
    message_id: str | None
    topic_id: str | None
    sequence_number: int | None


@dataclass(frozen=True, slots=True)
class ExplorerPublicRecordV1:
    status: ExplorerPublicRecordStatusV1
    reason_code: str | None
    observation: VerificationObservation | None
    publication: ExplorerPublicationV1 | None


@dataclass(frozen=True, slots=True)
class ExplorerDatasetV1Request:
    dataset_key: str
    network: HederaNetwork


@dataclass(frozen=True, slots=True)
class ExplorerIngestV1Request:
    anchor_request_id: str
    ingest_object_key: str
    network: HederaNetwork


@dataclass(frozen=True, slots=True)
class ExplorerMerkleRootV1Request:
    root_id: str
    network: HederaNetwork


def _js_length(value: str) -> int:
    return len(value.encode("utf-16-le", "surrogatepass")) // 2


def _trim(value: str) -> str:
    return value.strip(_ECMASCRIPT_TRIM)


def _record(value: object) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise TypeError("Invalid Explorer public record")
    return cast(Mapping[str, object], value)


def _string(value: object, maximum: int = _MAX_VALUE) -> str | None:
    if value is None or value == "":
        return None

    if not isinstance(value, str) or _js_length(value) > maximum:
        raise TypeError("Invalid Explorer public string")

    trimmed = _trim(value)

    if not trimmed:
        raise TypeError("Invalid Explorer public string")

    return trimmed


def _hash(value: object) -> str | None:
    normalized = _string(value, 128)

    if normalized is None:
        return None

    if _HASH_RE.fullmatch(normalized) is None:
        raise TypeError("Invalid Explorer SHA3-512 commitment")

    return normalized.lower()


def _number(value: object) -> float:
    if isinstance(value, bool):
        return math.nan

    if isinstance(value, (int, float)):
        return float(value)

    if not isinstance(value, str):
        return math.nan

    normalized = _trim(value)

    if not normalized:
        return 0.0

    lowered = normalized.lower()

    try:
        if lowered.startswith("0x") and len(normalized) > 2:
            return float(int(normalized[2:], 16))

        if lowered.startswith("0b") and len(normalized) > 2:
            return float(int(normalized[2:], 2))

        if lowered.startswith("0o") and len(normalized) > 2:
            return float(int(normalized[2:], 8))

        return float(normalized)
    except ValueError:
        return math.nan


def _safe_integer(value: object) -> int | None:
    number = _number(value)

    if (
        not math.isfinite(number) or not number.is_integer()
        or abs(number) > _MAX_SAFE_INTEGER
    ):
        return None

    return int(number)


def _positive_int(value: object) -> int | None:
    if value is None or value == "":
        return None

    number = _safe_integer(value)

    if number is None or number < 1:
        raise TypeError("Invalid Explorer sequence number")

    return number


def _count(value: object) -> int | None:
    if value is None or value == "":
        return None

    number = _safe_integer(value)

    if number is None or number < 0:
        raise TypeError("Invalid Explorer count")

    return number


def _available(
    key: str,
    value: str | int | None,
    reason: str = "PUBLIC_FIELD_UNAVAILABLE",
) -> VerificationFact:
    if value is None:
        return VerificationFact(key=key, state="unavailable", reason_code=reason)

    return VerificationFact(key=key, state="available", value=value)


def _observation(
    subject: VerificationSubject,
    observation_id: str,
    facts: list[VerificationFact],
) -> VerificationObservation:
    return VerificationObservation(
        id=observation_id,
        subject=cast(VerificationSubject, dict(subject)),
        source="public_record",
        resolver_id=_RESOLVER_ID,
        facts=tuple(facts),
    )


def _outcome(
    status: ExplorerPublicRecordStatusV1,
    reason: str | None,
) -> ExplorerPublicRecordV1:
    return ExplorerPublicRecordV1(
        status=status,
        reason_code=reason,
        observation=None,
        publication=None,
    )


def _publication(
    row: Mapping[str, object],
    prefix: str,
    kind: ExplorerPublicationEntityKindV1,
    entity_id: str | None,
    network: HederaNetwork,
) -> ExplorerPublicationV1 | None:
    transaction = _string(row.get(f"{prefix}transaction_id"), 256)
    message = _string(row.get(f"{prefix}message_id"), 256)
    topic = _string(row.get(f"{prefix}topic_id"), 64)
    sequence = _positive_int(row.get(f"{prefix}sequence_number"))

    if transaction is None and message is None and topic is None and sequence is None:
        return None

    if (
        entity_id is None or (
            transaction is None and message is None
            and not (topic is not None and sequence is not None)
        ) or (topic is not None and _TOPIC_RE.fullmatch(topic) is None)
        or ((topic is None) != (sequence is None))
    ):
        raise TypeError("Invalid Explorer publication locator")

    if message is not None:
        match = _MESSAGE_ID_RE.fullmatch(message)

        if match is None:
            raise TypeError("Invalid Explorer publication message id")

        message_topic = match.group(2) or match.group(3)
        raw_sequence = match.group(1) or match.group(4)
        message_sequence = _positive_int(raw_sequence)

        if (
            message_topic is None or message_sequence is None
            or _TOPIC_RE.fullmatch(message_topic) is None
            or (topic is not None and message_topic != topic)
            or (sequence is not None and sequence != message_sequence)
        ):
            raise TypeError("Inconsistent Explorer publication message identity")

        return ExplorerPublicationV1(
            hedera_network=network,
            entity_kind=kind,
            entity_id=entity_id,
            transaction_id=transaction,
            message_id=f"{message_sequence}@{message_topic}",
            topic_id=topic if topic is not None else message_topic,
            sequence_number=sequence if sequence is not None else message_sequence,
        )

    return ExplorerPublicationV1(
        hedera_network=network,
        entity_kind=kind,
        entity_id=entity_id,
        transaction_id=transaction,
        message_id=(
            f"{sequence}@{topic}"
            if topic is not None and sequence is not None
            else None
        ),
        topic_id=topic,
        sequence_number=sequence,
    )


def _required_network(row: Mapping[str, object], network: HederaNetwork) -> None:
    if row.get("hedera_network") != network:
        raise TypeError("Explorer public record network mismatch")


def _materialize(
    subject: VerificationSubject,
    observation_id: str,
    facts: list[VerificationFact],
    publication: ExplorerPublicationV1 | None,
) -> ExplorerPublicRecordV1:
    facts.extend(
        (
            _available(
                "publication.entity_kind",
                (None if publication is None else publication.entity_kind),
                "PUBLICATION_ANCHOR_UNAVAILABLE",
            ),
            _available(
                "publication.entity_id",
                (None if publication is None else publication.entity_id),
                "PUBLICATION_ANCHOR_UNAVAILABLE",
            ),
            _available(
                "publication.topic_id",
                (None if publication is None else publication.topic_id),
                "PUBLICATION_ANCHOR_UNAVAILABLE",
            ),
            _available(
                "publication.sequence_number",
                (None if publication is None else publication.sequence_number),
                "PUBLICATION_ANCHOR_UNAVAILABLE",
            ),
        )
    )

    return ExplorerPublicRecordV1(
        status="resolved",
        reason_code=None,
        observation=_observation(subject, observation_id, facts),
        publication=publication,
    )


def _validated_input(
    identifier: object,
    network: object,
    pattern: re.Pattern[str],
) -> str:
    if (
        not isinstance(identifier, str) or pattern.fullmatch(identifier) is None
        or network not in ("testnet", "mainnet")
    ):
        raise TypeError("Invalid Explorer public lookup input")

    return identifier


def _transport_outcome(status: str, reason: str | None) -> ExplorerPublicRecordV1:
    if status == "not_found":
        return _outcome("not_found", reason)

    if status == "unavailable":
        return _outcome("unavailable", reason)

    if status == "invalid":
        return _outcome("invalid", reason)

    raise TypeError("Invalid Explorer transport status")


async def resolve_explorer_dataset_v1(
    config: ExplorerPublicTransportV1,
    request: ExplorerDatasetV1Request,
) -> ExplorerPublicRecordV1:
    """Resolve an active Dataset manifest without inferring bundle digest."""
    dataset_key = _validated_input(request.dataset_key, request.network, _KEY_RE)

    read = await read_explorer_public_v1(
        config,
        f"/v1/datasets/{quote(dataset_key, safe='')}",
        request.network,
    )

    if read.status != "ok":
        return _transport_outcome(read.status, read.reason_code)

    try:
        row = _record(read.body)
        _required_network(row, request.network)

        public_key = row.get("dataset_key")

        if public_key is None:
            return _outcome("unavailable", "PUBLIC_DATASET_KEY_UNAVAILABLE")

        if public_key != dataset_key:
            return _outcome("conflict", "PUBLIC_DATASET_KEY_MISMATCH")

        version_id = _string(row.get("dataset_version_id"), 128)
        dataset_id = _string(row.get("dataset_id"), 128)

        version_publication = _publication(
            row,
            "publication_version_",
            "dataset_version",
            version_id,
            request.network,
        )
        dataset_publication = _publication(
            row,
            "publication_dataset_",
            "dataset",
            dataset_id,
            request.network,
        )

        selected_publication = (
            version_publication
            if version_publication is not None
            else dataset_publication
        )

        subject: VerificationSubject = {
            "kind": "dataset",
            "id": dataset_key,
            "hedera_network": request.network,
        }

        return _materialize(
            subject,
            "dataset.public_record",
            [
                _available("dataset_key", dataset_key),
                _available(
                    "dataset_fingerprint",
                    _hash(row.get("dataset_fingerprint")),
                ),
                _available("dataset.manifest_hash", _hash(row.get("manifest_hash"))),
                _available("dataset.version_id", version_id),
                _available("dataset.dataset_id", dataset_id),
            ],
            selected_publication,
        )

    except (TypeError, ValueError):
        return _outcome("invalid", "PUBLIC_DATASET_RESPONSE_INVALID")


async def resolve_explorer_ingest_v1(
    config: ExplorerPublicTransportV1,
    request: ExplorerIngestV1Request,
) -> ExplorerPublicRecordV1:
    """Resolve an explicit public Merkle anchor for an Ingest object."""
    anchor_request_id = _validated_input(
        request.anchor_request_id,
        request.network,
        _UUID_RE,
    )
    ingest_object_key = _validated_input(
        request.ingest_object_key,
        request.network,
        _KEY_RE,
    )

    read = await read_explorer_public_v1(
        config,
        f"/v1/merkle/anchors/{anchor_request_id}",
        request.network,
    )

    if read.status != "ok":
        return _transport_outcome(read.status, read.reason_code)

    try:
        row = _record(read.body)
        _required_network(row, request.network)

        public_anchor_id = row.get("anchor_request_id")

        if public_anchor_id is None:
            return _outcome("unavailable", "PUBLIC_ANCHOR_ID_UNAVAILABLE")

        if public_anchor_id != anchor_request_id:
            return _outcome("conflict", "PUBLIC_ANCHOR_ID_MISMATCH")

        public_object_key = row.get("ingest_object_key")

        if public_object_key is None:
            return _outcome("unavailable", "PUBLIC_INGEST_OBJECT_UNAVAILABLE")

        if public_object_key != ingest_object_key:
            return _outcome("conflict", "PUBLIC_INGEST_OBJECT_MISMATCH")

        publication = _publication(
            row,
            "publication_anchor_",
            "merkle_anchor",
            anchor_request_id,
            request.network,
        )

        subject: VerificationSubject = {
            "kind": "ingest",
            "id": ingest_object_key,
            "hedera_network": request.network,
        }

        return _materialize(
            subject,
            "ingest.public_record",
            [
                _available("ingest.object_key", ingest_object_key),
                _available("fingerprint", _hash(row.get("ingest_fingerprint"))),
                _available("bundle_digest", _hash(row.get("ingest_bundle_digest"))),
                _available("ingest.merkle_root", _hash(row.get("ingest_merkle_root"))),
                _available(
                    "ingest.total_bytes",
                    _count(row.get("ingest_total_bytes")),
                ),
                _available("merkle.anchor_request_id", anchor_request_id),
                _available("merkle.root_id", _string(row.get("root_id"), 128)),
                _available("merkle.root_hash", _hash(row.get("root_hash"))),
            ],
            publication,
        )

    except (TypeError, ValueError):
        return _outcome("invalid", "PUBLIC_INGEST_RESPONSE_INVALID")


async def resolve_explorer_merkle_root_v1(
    config: ExplorerPublicTransportV1,
    request: ExplorerMerkleRootV1Request,
) -> ExplorerPublicRecordV1:
    """Resolve Core-generated Merkle-root evidence by explicit root ID."""
    root_id = _validated_input(request.root_id, request.network, _UUID_RE)

    read = await read_explorer_public_v1(
        config,
        f"/v1/merkle/roots/{root_id}",
        request.network,
    )

    if read.status != "ok":
        return _transport_outcome(read.status, read.reason_code)

    try:
        row = _record(read.body)
        _required_network(row, request.network)

        public_root_id = row.get("id")

        if public_root_id is None:
            return _outcome("unavailable", "PUBLIC_ROOT_ID_UNAVAILABLE")

        if public_root_id != root_id:
            return _outcome("conflict", "PUBLIC_ROOT_ID_MISMATCH")

        publication = _publication(
            row,
            "publication_root_",
            "merkle_root",
            root_id,
            request.network,
        )

        subject: VerificationSubject = {
            "kind": "merkle_root",
            "id": root_id,
            "hedera_network": request.network,
        }

        return _materialize(
            subject,
            "merkle_root.public_record",
            [
                _available("merkle.root_id", root_id),
                _available("merkle.root_hash", _hash(row.get("root_hash"))),
                _available("merkle.leaf_count", _count(row.get("leaf_count"))),
                _available("merkle.hash_alg", _string(row.get("hash_alg"), 64)),
                _available("merkle.tree_alg", _string(row.get("tree_alg"), 64)),
            ],
            publication,
        )

    except (TypeError, ValueError):
        return _outcome("invalid", "PUBLIC_MERKLE_RESPONSE_INVALID")