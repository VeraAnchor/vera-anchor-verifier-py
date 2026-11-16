"""Scoped Explorer-assisted publication disclosure."""

import json
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal, cast

from ..contracts import VerificationFact, VerificationObservation
from ..triangulation.message_observation_v1 import (
    CoreMessageBindingV1Input,
    observe_core_message_binding_v1,
)
from .explorer_public_v1 import (
    ExplorerDatasetV1Request,
    ExplorerIngestV1Request,
    ExplorerMerkleRootV1Request,
    ExplorerPublicationV1,
    ExplorerPublicRecordV1,
    resolve_explorer_dataset_v1,
    resolve_explorer_ingest_v1,
    resolve_explorer_merkle_root_v1,
)
from .explorer_transport_v1 import ExplorerPublicTransportV1, read_explorer_public_v1

_HASH_RE = re.compile(r"^[0-9a-f]{128}$", re.IGNORECASE | re.ASCII)
_MAX_RECEIPT_BYTES = 128 * 1024
_MAX_SAFE_INTEGER = (1 << 53) - 1
_SCHEMA = "va:explorer_publication_receipt:v1"

_ECMASCRIPT_TRIM = (
    "\u0009\u000b\u000c\u0020\u00a0\u1680"
    "\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a"
    "\u2028\u2029\u202f\u205f\u3000\ufeff\u000a\u000d"
)

type ExplorerPublicationDisclosureStatusV1 = Literal[
    "resolved",
    "unavailable",
    "invalid",
    "conflict",
    "unsupported",
]


@dataclass(frozen=True, slots=True)
class ExplorerPublicationDisclosureV1:
    status: ExplorerPublicationDisclosureStatusV1
    reason_code: str | None
    receipt_observation: VerificationObservation | None
    message_binding_observation: VerificationObservation | None


@dataclass(frozen=True, slots=True)
class ExplorerPublishedEvidenceV1:
    public_record: ExplorerPublicRecordV1
    disclosure: ExplorerPublicationDisclosureV1


def _js_length(value: str) -> int:
    return len(value.encode("utf-16-le", "surrogatepass")) // 2


def _trim(value: str) -> str:
    return value.strip(_ECMASCRIPT_TRIM)


def _result(
    status: ExplorerPublicationDisclosureStatusV1,
    reason: str | None,
) -> ExplorerPublicationDisclosureV1:
    return ExplorerPublicationDisclosureV1(
        status=status,
        reason_code=reason,
        receipt_observation=None,
        message_binding_observation=None,
    )


def _record(value: object) -> Mapping[str, object] | None:
    if not isinstance(value, Mapping):
        return None
    return cast(Mapping[str, object], value)


def _text(value: object, maximum: int = 512) -> str | None:
    if value is None or value == "":
        return None

    if not isinstance(value, str) or _js_length(value) > maximum:
        return None

    normalized = _trim(value)

    if not normalized:
        return None

    return normalized


def _digest(value: object) -> str | None:
    normalized = _text(value, 128)

    if normalized is None:
        return None

    if _HASH_RE.fullmatch(normalized) is None:
        return None

    return normalized.lower()


def _optional_digest(value: object) -> str | None:
    if value is None or value == "":
        return None

    parsed = _digest(value)

    if parsed is None:
        raise TypeError("Invalid publication proof digest")

    return parsed


def _fact(key: str, value: str | int | float | None) -> VerificationFact:
    if value is None:
        return VerificationFact(
            key=key,
            state="unavailable",
            reason_code="PUBLICATION_RECEIPT_FIELD_UNAVAILABLE",
        )

    return VerificationFact(key=key, state="available", value=value)


def _optional_number(value: object) -> int | float | None:
    if value is None or value == "":
        return None

    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError("Invalid publication receipt numeric commitment")

    try:
        number = float(value)
    except OverflowError as exc:
        raise TypeError("Invalid publication receipt numeric commitment") from exc

    if (
        not math.isfinite(number) or not number.is_integer()
        or abs(number) > _MAX_SAFE_INTEGER or number < 0
    ):
        raise TypeError("Invalid publication receipt numeric commitment")

    return value


def _json_truthy(value: object) -> bool:
    if value is None or value is False:
        return False

    if isinstance(value, str):
        return bool(value)

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        try:
            number = float(value)
        except OverflowError:
            return True

        return number != 0 and not math.isnan(number)

    return True


def _public_receipt(
    payload: object,
    claim: ExplorerPublicationV1,
) -> Mapping[str, object] | None:
    raw = payload

    if isinstance(payload, str):
        if len(payload.encode("utf-8")) > _MAX_RECEIPT_BYTES:
            return None

        try:
            raw = json.loads(payload)
        except (json.JSONDecodeError, ValueError):
            return None

    receipt = _record(raw)

    if receipt is None:
        return None

    try:
        encoded = json.dumps(
            dict(receipt),
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError):
        return None

    if len(encoded) > _MAX_RECEIPT_BYTES:
        return None

    event_version = receipt.get("event_version")

    if (
        receipt.get("schema") != _SCHEMA or receipt.get("event_type") != "published"
        or receipt.get("entity_kind") != claim.entity_kind
        or receipt.get("entity_id") != claim.entity_id
        or receipt.get("visibility") != "public" or isinstance(event_version, bool)
        or event_version != 1
    ):
        return None

    if "proof" in receipt and _record(receipt.get("proof")) is None:
        return None

    return receipt


async def _resolve_explorer_publication_v1(
    config: ExplorerPublicTransportV1,
    public_record: ExplorerPublicRecordV1,
) -> ExplorerPublicationDisclosureV1:
    if (
        public_record.status != "resolved" or public_record.observation is None
        or public_record.observation.source != "public_record"
        or public_record.publication is None
    ):
        return _result("unavailable", "PUBLICATION_ANCHOR_UNAVAILABLE")

    locator = public_record.publication
    subject = public_record.observation.subject

    if (
        locator.hedera_network != subject.get("hedera_network") or not locator.entity_id
        or not locator.entity_kind
        or (locator.transaction_id is None and locator.message_id is None)
    ):
        return _result("invalid", "PUBLICATION_REFERENCE_INVALID")

    body: dict[str, object] = {
        "hedera_network": locator.hedera_network,
        "mode": "decrypt_and_verify",
        "include_decrypted": True,
    }

    if locator.transaction_id is not None:
        body["transaction_id"] = locator.transaction_id
    else:
        body["message_id"] = locator.message_id

    read = await read_explorer_public_v1(
        config,
        "/v1/hcs/verify-decrypt",
        locator.hedera_network,
        post_body=body,
    )

    if read.status != "ok":
        return _result(
            "unavailable",
            read.reason_code or "PUBLICATION_DECRYPT_UNAVAILABLE",
        )

    response = _record(read.body)

    if response is None:
        return _result("invalid", "PUBLICATION_DECRYPT_RESPONSE_INVALID")

    if response.get("hedera_network") != locator.hedera_network:
        return _result("conflict", "PUBLICATION_NETWORK_MISMATCH")

    tx = _record(response.get("tx"))
    topic = _record(response.get("topic"))

    if locator.transaction_id is not None:
        raw_transaction = None if tx is None else tx.get("transaction_id")
        returned_transaction = _text(raw_transaction, 256)

        if returned_transaction != locator.transaction_id:
            return _result(
                ("conflict" if _json_truthy(raw_transaction) else "invalid"),
                "PUBLICATION_TRANSACTION_MISMATCH",
            )

    if locator.message_id is not None:
        raw_message = None if tx is None else tx.get("message_id")

        if not _json_truthy(raw_message) and locator.transaction_id is None:
            return _result("unavailable", "PUBLICATION_MESSAGE_REFERENCE_UNAVAILABLE")

        returned_message = _text(raw_message, 256)
        alternate_message = (
            (f"{locator.topic_id}@" f"{locator.sequence_number}")
            if (locator.topic_id is not None and locator.sequence_number is not None)
            else None
        )

        if (
            returned_message is not None and returned_message != locator.message_id
            and returned_message != alternate_message
        ):
            return _result("conflict", "PUBLICATION_MESSAGE_MISMATCH")

        if returned_message is None and locator.transaction_id is None:
            return _result("invalid", "PUBLICATION_MESSAGE_UNAVAILABLE")

    if locator.topic_id is not None:
        raw_topic = None if topic is None else topic.get("topic_id")
        returned_topic = _text(raw_topic, 64)

        if returned_topic != locator.topic_id:
            return _result(
                ("conflict" if _json_truthy(raw_topic) else "invalid"),
                "PUBLICATION_TOPIC_MISMATCH",
            )

    hash_result = _record(response.get("hash"))
    hash_match = None if hash_result is None else hash_result.get("match")
    verified = response.get("verified")

    if hash_match is False or verified is False:
        return _result("unavailable", "PUBLICATION_PROVIDER_VERIFICATION_FAILED")

    if hash_match is not True or verified is not True:
        return _result("unavailable", "PUBLICATION_PROVIDER_VERIFICATION_UNAVAILABLE")

    payload = response.get("payload")
    payload_record = _record(payload)

    if (
        payload_record is not None and "schema" in payload_record
        and payload_record.get("schema") != _SCHEMA
    ):
        return _result("unsupported", "PUBLICATION_RECEIPT_UNSUPPORTED_SCHEMA")

    receipt = _public_receipt(payload, locator)

    if receipt is None:
        return _result("invalid", "PUBLICATION_RECEIPT_INVALID")

    try:
        proof = _record(receipt.get("proof")) or {}

        facts = (
            _fact("publication.receipt.schema", _SCHEMA),
            _fact("publication.receipt.entity_kind", locator.entity_kind),
            _fact("publication.receipt.entity_id", locator.entity_id),
            _fact("publication.receipt.event_type", "published"),
            _fact(
                "publication.proof.dataset_key",
                _text(proof.get("dataset_key"), 256),
            ),
            _fact(
                "publication.proof.fingerprint",
                _optional_digest(proof.get("fingerprint")),
            ),
            _fact(
                "publication.proof.manifest_hash",
                _optional_digest(proof.get("manifest_hash")),
            ),
            _fact(
                "publication.proof.merkle_root",
                _optional_digest(proof.get("merkle_root")),
            ),
            _fact(
                "publication.proof.ingest_object_key",
                _text(proof.get("ingest_object_key"), 256),
            ),
            _fact(
                "publication.proof.ingest_fingerprint",
                _optional_digest(proof.get("ingest_fingerprint")),
            ),
            _fact(
                "publication.proof.ingest_bundle_digest",
                _optional_digest(proof.get("ingest_bundle_digest")),
            ),
            _fact(
                "publication.proof.ingest_merkle_root",
                _optional_digest(proof.get("ingest_merkle_root")),
            ),
            _fact(
                "publication.proof.ingest_item_count",
                _optional_number(proof.get("ingest_item_count")),
            ),
            _fact(
                "publication.proof.ingest_total_bytes",
                _optional_number(proof.get("ingest_total_bytes")),
            ),
        )

        disclosure = VerificationObservation(
            id=f"{subject['kind']}.publication_receipt",
            subject=subject,
            source="public_record",
            resolver_id="explorer.public-disclosure.v1",
            facts=facts,
        )

        binding = observe_core_message_binding_v1(
            CoreMessageBindingV1Input(
                id=f"{subject['kind']}.core_binding",
                subject=subject,
                binding=response.get("message_binding"),
            )
        )

        return ExplorerPublicationDisclosureV1(
            status="resolved",
            reason_code=None,
            receipt_observation=disclosure,
            message_binding_observation=binding,
        )

    except (TypeError, ValueError):
        return _result("invalid", "PUBLICATION_RECEIPT_INVALID")


async def _with_disclosure(
    config: ExplorerPublicTransportV1,
    public_record: ExplorerPublicRecordV1,
) -> ExplorerPublishedEvidenceV1:
    return ExplorerPublishedEvidenceV1(
        public_record=public_record,
        disclosure=await _resolve_explorer_publication_v1(config, public_record),
    )


async def resolve_explorer_dataset_publication_v1(
    config: ExplorerPublicTransportV1,
    request: ExplorerDatasetV1Request,
) -> ExplorerPublishedEvidenceV1:
    return await _with_disclosure(
        config,
        await resolve_explorer_dataset_v1(config, request),
    )


async def resolve_explorer_ingest_publication_v1(
    config: ExplorerPublicTransportV1,
    request: ExplorerIngestV1Request,
) -> ExplorerPublishedEvidenceV1:
    return await _with_disclosure(
        config,
        await resolve_explorer_ingest_v1(config, request),
    )


async def resolve_explorer_merkle_root_publication_v1(
    config: ExplorerPublicTransportV1,
    request: ExplorerMerkleRootV1Request,
) -> ExplorerPublishedEvidenceV1:
    return await _with_disclosure(
        config,
        await resolve_explorer_merkle_root_v1(config, request),
    )