"""Authenticated Ingest receipt evidence triangulation."""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal, Never, NotRequired, TypedDict, cast

from ..contracts import (
    EvidenceConsistency,
    HederaNetwork,
    VerificationFact,
    VerificationFinding,
    VerificationObservation,
    VerificationOutcome,
    VerificationReport,
    VerificationSubject,
)
from ..profiles.ingest.v1 import IngestV1ReceiptComputed, verify_ingest_v1_receipt
from ..profiles.source_v1_helpers import SourceV1Limits
from ..resolvers.authorized_observation_v1 import (
    AuthorizedHcsObservationsV1Config,
    AuthorizedHcsObservationsV1Input,
    AuthorizedMirrorResolutionV1,
    resolve_authorized_hcs_observations_v1,
)
from ..resolvers.core_authorized_v1 import (
    AuthorizedHcsEvidenceStatusV1,
    AuthorizedHcsEvidenceV1Request,
)
from ..verification.source_intent_v1 import verify_ingest_v1_with_intent
from .authorized_hcs_v1 import (
    AuthorizedHcsTriangulationV1Input,
    triangulate_authorized_hcs_v1,
)
from .compare_v1 import (
    TriangulationFactPlanV1,
    TriangulationRelationshipPlanV1,
    TriangulationRelationshipResultV1,
    TriangulationV1Input,
    compare_evidence_triangulation_v1,
)

_LOCAL_OBSERVATION_ID = "ingest.local_commitments"
_RECEIPT_OBSERVATION_ID = "ingest.receipt"
_SOURCE_OBSERVATION_ID = "ingest.source"
_BUNDLE_OBSERVATION_ID = "ingest.bundle"
_MAX_REFERENCE_LENGTH = 256

type AuthorizedIngestReceiptStatusV1 = Literal[
    "resolved", "unavailable", "unsupported", "invalid", "conflict"
]


class AuthorizedIngestMessageReferenceV1(TypedDict):
    message_id: str
    transaction_id: NotRequired[Never]


class AuthorizedIngestTransactionReferenceV1(TypedDict):
    transaction_id: str
    message_id: NotRequired[Never]


type AuthorizedIngestHcsReferenceV1 = (
    AuthorizedIngestMessageReferenceV1 | AuthorizedIngestTransactionReferenceV1
)
type AuthorizedIngestTriangulationV1Config = AuthorizedHcsObservationsV1Config


class AuthorizedIngestTriangulationV1Input(TypedDict):
    bundle: object
    material: object
    intent: object
    hcs_reference: AuthorizedIngestHcsReferenceV1
    receipt: NotRequired[Never]
    limits: NotRequired[SourceV1Limits]


@dataclass(frozen=True, slots=True)
class AuthorizedIngestReceiptV1Result:
    status: AuthorizedIngestReceiptStatusV1
    reason_code: str | None
    receipt: IngestV1ReceiptComputed | None


@dataclass(frozen=True, slots=True)
class AuthorizedIngestTriangulationResolutionV1:
    authorized_core: AuthorizedHcsEvidenceStatusV1
    hedera_mirror: AuthorizedMirrorResolutionV1
    ingest_receipt: AuthorizedIngestReceiptStatusV1


@dataclass(frozen=True, slots=True)
class AuthorizedIngestTriangulationV1Result:
    consistency: EvidenceConsistency
    relationships: tuple[TriangulationRelationshipResultV1, ...]
    report: VerificationReport
    resolution: AuthorizedIngestTriangulationResolutionV1


def _object(value: object) -> Mapping[str, object] | None:
    if not isinstance(value, dict):
        return None
    return cast(Mapping[str, object], value)


def _available(key: str, value: str | int | float) -> VerificationFact:
    return VerificationFact(key=key, state="available", value=value)


def _unavailable(key: str, reason: str) -> VerificationFact:
    return VerificationFact(key=key, state="unavailable", reason_code=reason)


def _value(
    report: VerificationReport,
    observation_id: str,
    key: str,
) -> str | int | float | None:
    observation = next(
        (entry for entry in report.observations if entry.id == observation_id),
        None,
    )
    if observation is None:
        raise TypeError(f"Ingest source report is missing {observation_id}")
    if observation.source != "local_computation":
        raise TypeError(
            f"Ingest source observation {observation_id} must be local computation"
        )

    fact = next((entry for entry in observation.facts if entry.key == key), None)
    if fact is None or fact.state != "available":
        return None

    value = fact.value
    if isinstance(value, bool):
        return None
    if isinstance(value, (str, int, float)):
        return value
    return None


def _local_observation(report: VerificationReport) -> VerificationObservation:
    fingerprint = _value(report, _BUNDLE_OBSERVATION_ID, "fingerprint")
    bundle_digest = _value(report, _BUNDLE_OBSERVATION_ID, "bundle_digest")
    idempotency_key = _value(report, _BUNDLE_OBSERVATION_ID, "idempotency_key")
    item_count = _value(report, _BUNDLE_OBSERVATION_ID, "declared_file_or_item_count")
    total_bytes = _value(report, _BUNDLE_OBSERVATION_ID, "declared_total_bytes")
    merkle_root = _value(report, _SOURCE_OBSERVATION_ID, "source_merkle_root")

    def fact(
        key: str,
        entry: str | int | float | None,
        reason: str,
    ) -> VerificationFact:
        if entry is None:
            return _unavailable(key, reason)
        return _available(key, entry)

    return VerificationObservation(
        id=_LOCAL_OBSERVATION_ID,
        subject=report.intent["subject"],
        source="local_computation",
        facts=(
            _available("ingest.local.object_key", report.intent["subject"]["id"]),
            fact(
                "ingest.local.fingerprint",
                fingerprint,
                "INGEST_LOCAL_FINGERPRINT_UNAVAILABLE",
            ),
            fact(
                "ingest.local.bundle_digest",
                bundle_digest,
                "INGEST_LOCAL_BUNDLE_DIGEST_UNAVAILABLE",
            ),
            fact(
                "ingest.local.merkle_root",
                merkle_root,
                "INGEST_LOCAL_MERKLE_ROOT_UNAVAILABLE",
            ),
            fact(
                "ingest.local.idempotency_key",
                idempotency_key,
                "INGEST_LOCAL_IDEMPOTENCY_KEY_UNAVAILABLE",
            ),
            fact("ingest.local.item_count", item_count, "INGEST_LOCAL_ITEM_COUNT_UNAVAILABLE"),
            fact("ingest.local.total_bytes", total_bytes, "INGEST_LOCAL_TOTAL_BYTES_UNAVAILABLE"),
        ),
    )


def _receipt_result(
    status: AuthorizedIngestReceiptStatusV1,
    reason_code: str,
) -> AuthorizedIngestReceiptV1Result:
    return AuthorizedIngestReceiptV1Result(
        status=status,
        reason_code=reason_code,
        receipt=None,
    )


def parse_authorized_ingest_receipt_v1(
    payload: object,
    expected_network: HederaNetwork,
) -> AuthorizedIngestReceiptV1Result:
    """Validate an authorized deterministic Ingest receipt."""
    if payload is None:
        return _receipt_result("unavailable", "AUTHORIZED_INGEST_RECEIPT_UNAVAILABLE")

    raw = _object(payload)
    if raw is None:
        return _receipt_result("invalid", "AUTHORIZED_INGEST_RECEIPT_INVALID")
    if raw.get("v") != "v1" or raw.get("kind") != "ingest_receipt":
        return _receipt_result("unsupported", "AUTHORIZED_INGEST_RECEIPT_UNSUPPORTED")
    if raw.get("mode") != "register_and_anchor":
        return _receipt_result(
            "unsupported", "AUTHORIZED_INGEST_RECEIPT_MODE_UNSUPPORTED"
        )

    try:
        verified = verify_ingest_v1_receipt(payload)
    except (TypeError, ValueError, OverflowError):
        return _receipt_result("invalid", "AUTHORIZED_INGEST_RECEIPT_INVALID")

    if not verified.ok:
        return _receipt_result(
            "conflict", "AUTHORIZED_INGEST_RECEIPT_SELF_INCONSISTENT"
        )

    receipt = verified.computed
    if receipt.hedera_network is not None and receipt.hedera_network != expected_network:
        return _receipt_result(
            "conflict", "AUTHORIZED_INGEST_RECEIPT_NETWORK_MISMATCH"
        )

    return AuthorizedIngestReceiptV1Result(
        status="resolved",
        reason_code=None,
        receipt=receipt,
    )


def _source_report_with_authorized_receipt(
    report: VerificationReport,
    parsed: AuthorizedIngestReceiptV1Result,
) -> VerificationReport:
    if parsed.status != "resolved" or parsed.receipt is None:
        return report

    receipt = parsed.receipt
    found = False
    observations: list[VerificationObservation] = []

    for entry in report.observations:
        if entry.id != _RECEIPT_OBSERVATION_ID:
            observations.append(entry)
            continue
        if entry.source != "provided_evidence":
            raise TypeError(
                "Authenticated Ingest receipt observation must originate from "
                "verifier-supplied evidence"
            )

        found = True
        merkle_root = (
            _unavailable(
                "ingest.receipt.merkle_root",
                "AUTHORIZED_INGEST_MERKLE_ROOT_UNAVAILABLE",
            )
            if receipt.merkle_root is None
            else _available("ingest.receipt.merkle_root", receipt.merkle_root)
        )
        network = (
            _unavailable(
                "ingest.receipt.declared_network",
                "AUTHORIZED_INGEST_RECEIPT_NETWORK_NOT_EMBEDDED",
            )
            if receipt.hedera_network is None
            else _available("ingest.receipt.declared_network", receipt.hedera_network)
        )

        observations.append(
            VerificationObservation(
                id=entry.id,
                subject=entry.subject,
                source="authorized_service",
                resolver_id="core.authorized-hcs.v1",
                observed_at=entry.observed_at,
                facts=(
                    *entry.facts,
                    _available("ingest.receipt.object_key", receipt.object_key),
                    _available("ingest.receipt.fingerprint", receipt.fingerprint),
                    _available("ingest.receipt.bundle_digest", receipt.bundle_digest),
                    merkle_root,
                    _available("ingest.receipt.idempotency_key", receipt.idempotency_key),
                    _available("ingest.receipt.item_count", receipt.item_count),
                    _available("ingest.receipt.total_bytes", receipt.total_bytes),
                    network,
                ),
            )
        )

    if not found:
        raise TypeError(
            "Authenticated Ingest verifier report is missing ingest.receipt observation"
        )

    return VerificationReport(
        intent=report.intent,
        findings=report.findings,
        observations=tuple(observations),
    )


def _profile_finding(parsed: AuthorizedIngestReceiptV1Result) -> VerificationFinding:
    outcome: VerificationOutcome
    observation_ids: tuple[str, ...]

    if parsed.status == "resolved":
        outcome = "pass"
        observation_ids = (_RECEIPT_OBSERVATION_ID,)
    elif parsed.status == "unavailable":
        outcome = "indeterminate"
        observation_ids = ()
    elif parsed.status == "unsupported":
        outcome = "unsupported"
        observation_ids = ()
    else:
        outcome = "fail"
        observation_ids = ()

    return VerificationFinding(
        check_id="triangulation.authorized_ingest.receipt_profile",
        outcome=outcome,
        reason_code=parsed.reason_code,
        observation_ids=observation_ids,
    )


def _aggregate(
    hcs: EvidenceConsistency,
    ingest: EvidenceConsistency,
    parsed: AuthorizedIngestReceiptV1Result,
) -> EvidenceConsistency:
    if hcs == "conflict" or ingest == "conflict" or parsed.status in ("invalid", "conflict"):
        return "conflict"
    if hcs != "consistent" or ingest != "consistent" or parsed.status != "resolved":
        return "incomplete"
    return "consistent"


def _js_length(value: str) -> int:
    return len(value.encode("utf-16-le", "surrogatepass")) // 2


def _checked_reference(reference: object) -> tuple[str | None, str | None]:
    if not isinstance(reference, Mapping):
        raise TypeError(
            "Authorized Ingest triangulation requires exactly one bounded HCS reference"
        )

    message = reference.get("message_id")
    transaction = reference.get("transaction_id")
    message_valid = isinstance(message, str)
    transaction_valid = isinstance(transaction, str)

    if message_valid == transaction_valid:
        raise TypeError(
            "Authorized Ingest triangulation requires exactly one bounded HCS reference"
        )
    if message_valid:
        assert isinstance(message, str)
        if not message or _js_length(message) > _MAX_REFERENCE_LENGTH or message.strip() != message:
            raise TypeError(
                "Authorized Ingest triangulation requires exactly one bounded HCS reference"
            )
        return message, None

    assert isinstance(transaction, str)
    if (
        not transaction
        or _js_length(transaction) > _MAX_REFERENCE_LENGTH
        or transaction.strip() != transaction
    ):
        raise TypeError(
            "Authorized Ingest triangulation requires exactly one bounded HCS reference"
        )
    return None, transaction


def _checked_subject(intent: object) -> tuple[VerificationSubject, HederaNetwork]:
    if not isinstance(intent, Mapping):
        raise TypeError(
            "Authorized Ingest triangulation requires Ingest intent and Core config"
        )

    raw_subject = intent.get("subject")
    if not isinstance(raw_subject, Mapping) or raw_subject.get("kind") != "ingest":
        raise TypeError(
            "Authorized Ingest triangulation requires Ingest intent and Core config"
        )

    network = raw_subject.get("hedera_network")
    if network not in ("mainnet", "testnet"):
        raise TypeError(
            "Authorized Ingest triangulation requires an explicit Hedera network"
        )

    return cast(VerificationSubject, dict(raw_subject)), network


async def _verify_source(
    input: AuthorizedIngestTriangulationV1Input,
    *,
    receipt: object | None,
    include_receipt: bool,
) -> VerificationReport:
    if include_receipt:
        return await verify_ingest_v1_with_intent(
            bundle=input["bundle"],
            material=input["material"],
            intent=input["intent"],
            receipt=receipt,
            limits=input.get("limits"),
        )
    return await verify_ingest_v1_with_intent(
        bundle=input["bundle"],
        material=input["material"],
        intent=input["intent"],
        limits=input.get("limits"),
    )


async def triangulate_authorized_ingest_v1(
    config: AuthorizedIngestTriangulationV1Config,
    input: AuthorizedIngestTriangulationV1Input,
) -> AuthorizedIngestTriangulationV1Result:
    """Triangulate local Ingest commitments with an authorized receipt."""
    if "receipt" in input:
        raise TypeError(
            "Authorized Ingest triangulation does not accept caller-supplied receipt authority"
        )

    subject, network = _checked_subject(input["intent"])
    message_id, transaction_id = _checked_reference(input["hcs_reference"])
    resolution = await resolve_authorized_hcs_observations_v1(
        config,
        AuthorizedHcsObservationsV1Input(
            subject=subject,
            request=AuthorizedHcsEvidenceV1Request(
                network=network,
                message_id=message_id,
                transaction_id=transaction_id,
                include_decrypted=True,
            ),
        ),
    )

    evidence = resolution.core.evidence
    payload = (
        evidence.payload
        if evidence is not None and evidence.payload_included is True
        else None
    )
    parsed = parse_authorized_ingest_receipt_v1(payload, network)
    verified_source = await _verify_source(
        input,
        receipt=payload,
        include_receipt=parsed.status == "resolved",
    )
    source = _source_report_with_authorized_receipt(verified_source, parsed)
    hcs = triangulate_authorized_hcs_v1(
        AuthorizedHcsTriangulationV1Input(source_report=source, resolution=resolution)
    )
    local = _local_observation(hcs.report)

    relationship = TriangulationRelationshipPlanV1(
        id="provided_authorized",
        left_observation_id=_LOCAL_OBSERVATION_ID,
        right_observation_id=_RECEIPT_OBSERVATION_ID,
        comparisons=(
            TriangulationFactPlanV1(
                key="object_key",
                left_key="ingest.local.object_key",
                right_key="ingest.receipt.object_key",
            ),
            TriangulationFactPlanV1(
                key="fingerprint",
                left_key="ingest.local.fingerprint",
                right_key="ingest.receipt.fingerprint",
            ),
            TriangulationFactPlanV1(
                key="bundle_digest",
                left_key="ingest.local.bundle_digest",
                right_key="ingest.receipt.bundle_digest",
            ),
            TriangulationFactPlanV1(
                key="merkle_root",
                left_key="ingest.local.merkle_root",
                right_key="ingest.receipt.merkle_root",
            ),
            TriangulationFactPlanV1(
                key="idempotency_key",
                left_key="ingest.local.idempotency_key",
                right_key="ingest.receipt.idempotency_key",
            ),
            TriangulationFactPlanV1(
                key="item_count",
                left_key="ingest.local.item_count",
                right_key="ingest.receipt.item_count",
            ),
            TriangulationFactPlanV1(
                key="total_bytes",
                left_key="ingest.local.total_bytes",
                right_key="ingest.receipt.total_bytes",
            ),
        ),
    )
    source_with_local = VerificationReport(
        intent=hcs.report.intent,
        findings=hcs.report.findings,
        observations=(*hcs.report.observations, local),
    )
    compared = compare_evidence_triangulation_v1(
        TriangulationV1Input(
            source_report=source_with_local,
            observations=(),
            relationships=(relationship,),
        )
    )
    finding = _profile_finding(parsed)
    report = VerificationReport(
        intent=compared.report.intent,
        findings=(*compared.report.findings, finding),
        observations=compared.report.observations,
    )

    return AuthorizedIngestTriangulationV1Result(
        consistency=_aggregate(hcs.consistency, compared.consistency, parsed),
        relationships=(*hcs.relationships, *compared.relationships),
        report=report,
        resolution=AuthorizedIngestTriangulationResolutionV1(
            authorized_core=resolution.core.status,
            hedera_mirror=resolution.mirror_resolution,
            ingest_receipt=parsed.status,
        ),
    )