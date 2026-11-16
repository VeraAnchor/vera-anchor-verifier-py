"""Authenticated Dataset Registry evidence triangulation."""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import NotRequired, TypedDict, cast

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
from ..profiles.dataset.registry_event_v1 import (
    DatasetRegistryVersionCreatedV1Result,
    DatasetRegistryVersionCreatedV1Status,
    parse_dataset_registry_version_created_v1,
)
from ..profiles.source_v1_helpers import SourceV1File, SourceV1Limits
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
from ..verification.source_intent_v1 import verify_dataset_v1_with_intent
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

_REGISTRY_OBSERVATION_ID = "dataset.authorized_registry"
_BUNDLE_OBSERVATION_ID = "dataset.bundle"
_MAX_REFERENCE_LENGTH = 256


class AuthorizedDatasetMessageReferenceV1(TypedDict):
    message_id: str


class AuthorizedDatasetTransactionReferenceV1(TypedDict):
    transaction_id: str


type AuthorizedDatasetHcsReferenceV1 = (
    AuthorizedDatasetMessageReferenceV1 | AuthorizedDatasetTransactionReferenceV1
)
type AuthorizedDatasetTriangulationV1Config = AuthorizedHcsObservationsV1Config


class AuthorizedDatasetTriangulationV1Input(TypedDict):
    bundle: object
    files: list[SourceV1File]
    intent: object
    hcs_reference: AuthorizedDatasetHcsReferenceV1
    receipt: NotRequired[object]
    limits: NotRequired[SourceV1Limits]


@dataclass(frozen=True, slots=True)
class AuthorizedDatasetTriangulationResolutionV1:
    authorized_core: AuthorizedHcsEvidenceStatusV1
    hedera_mirror: AuthorizedMirrorResolutionV1
    dataset_registry_event: DatasetRegistryVersionCreatedV1Status


@dataclass(frozen=True, slots=True)
class AuthorizedDatasetTriangulationV1Result:
    consistency: EvidenceConsistency
    relationships: tuple[TriangulationRelationshipResultV1, ...]
    report: VerificationReport
    resolution: AuthorizedDatasetTriangulationResolutionV1


def _available(key: str, value: str | int) -> VerificationFact:
    return VerificationFact(key=key, state="available", value=value)


def _unavailable(key: str, reason: str) -> VerificationFact:
    return VerificationFact(key=key, state="unavailable", reason_code=reason)


def _registry_observation(
    parsed: DatasetRegistryVersionCreatedV1Result,
    source_report: VerificationReport,
) -> VerificationObservation | None:
    if parsed.status != "resolved" or parsed.event is None:
        return None

    event = parsed.event
    return VerificationObservation(
        id=_REGISTRY_OBSERVATION_ID,
        subject=source_report.intent["subject"],
        source="authorized_service",
        resolver_id="core.authorized-hcs.v1",
        facts=(
            _available("dataset.registry.schema", event.schema_version),
            _available("dataset.registry.event", event.event),
            _available("dataset.registry.entity_id", event.entity_id),
            _available("dataset.registry.dataset_version_id", event.dataset_version_id),
            _available("dataset.registry.dataset_key", event.dataset_key),
            _available("dataset.registry.version", event.version),
            _available("dataset.registry.dataset_fingerprint", event.dataset_fingerprint),
            _unavailable(
                "dataset.registry.manifest_hash",
                "AUTHORIZED_DATASET_MANIFEST_HASH_UNAVAILABLE",
            )
            if event.manifest_hash is None
            else _available("dataset.registry.manifest_hash", event.manifest_hash),
            _unavailable(
                "dataset.registry.schema_hash",
                "AUTHORIZED_DATASET_SCHEMA_HASH_UNAVAILABLE",
            )
            if event.schema_hash is None
            else _available("dataset.registry.schema_hash", event.schema_hash),
        ),
    )


def _source_report_with_subject_fact(report: VerificationReport) -> VerificationReport:
    found = False
    observations: list[VerificationObservation] = []

    for observation in report.observations:
        if observation.id != _BUNDLE_OBSERVATION_ID:
            observations.append(observation)
            continue
        if observation.source != "local_computation":
            raise TypeError("Dataset bundle observation must be local computation")

        found = True
        if any(fact.key == "source_subject_id" for fact in observation.facts):
            raise TypeError("Dataset bundle observation already contains source_subject_id")

        observations.append(
            VerificationObservation(
                id=observation.id,
                subject=observation.subject,
                source=observation.source,
                resolver_id=observation.resolver_id,
                facts=(
                    *observation.facts,
                    _available("source_subject_id", report.intent["subject"]["id"]),
                ),
            )
        )

    if not found:
        raise TypeError("Dataset source report is missing dataset.bundle observation")

    return VerificationReport(
        intent=report.intent,
        findings=report.findings,
        observations=tuple(observations),
    )


def _profile_finding(parsed: DatasetRegistryVersionCreatedV1Result) -> VerificationFinding:
    outcome: VerificationOutcome
    observation_ids: tuple[str, ...]

    if parsed.status == "resolved":
        outcome = "pass"
        observation_ids = (_REGISTRY_OBSERVATION_ID,)
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
        check_id="triangulation.authorized_dataset.registry_event_profile",
        outcome=outcome,
        reason_code=parsed.reason_code,
        observation_ids=observation_ids,
    )


def _aggregate(
    hcs: EvidenceConsistency,
    dataset: EvidenceConsistency,
    parsed: DatasetRegistryVersionCreatedV1Result,
) -> EvidenceConsistency:
    if hcs == "conflict" or dataset == "conflict" or parsed.status in ("invalid", "conflict"):
        return "conflict"
    if hcs != "consistent" or dataset != "consistent" or parsed.status != "resolved":
        return "incomplete"
    return "consistent"


def _js_length(value: str) -> int:
    return len(value.encode("utf-16-le", "surrogatepass")) // 2


def _checked_reference(reference: object) -> tuple[str | None, str | None]:
    if not isinstance(reference, Mapping):
        raise TypeError(
            "Authorized Dataset triangulation requires exactly one bounded HCS reference"
        )

    message = reference.get("message_id")
    transaction = reference.get("transaction_id")
    message_valid = isinstance(message, str)
    transaction_valid = isinstance(transaction, str)

    if message_valid == transaction_valid:
        raise TypeError(
            "Authorized Dataset triangulation requires exactly one bounded HCS reference"
        )
    if message_valid:
        assert isinstance(message, str)
        if not message or _js_length(message) > _MAX_REFERENCE_LENGTH or message.strip() != message:
            raise TypeError(
                "Authorized Dataset triangulation requires exactly one bounded HCS reference"
            )
        return message, None

    assert isinstance(transaction, str)
    if (
        not transaction
        or _js_length(transaction) > _MAX_REFERENCE_LENGTH
        or transaction.strip() != transaction
    ):
        raise TypeError(
            "Authorized Dataset triangulation requires exactly one bounded HCS reference"
        )
    return None, transaction


def _checked_subject(intent: object) -> tuple[VerificationSubject, HederaNetwork]:
    if not isinstance(intent, Mapping):
        raise TypeError("Authorized Dataset triangulation requires Dataset intent and Core config")

    raw_subject = intent.get("subject")
    if not isinstance(raw_subject, Mapping) or raw_subject.get("kind") != "dataset":
        raise TypeError("Authorized Dataset triangulation requires Dataset intent and Core config")

    network = raw_subject.get("hedera_network")
    if network not in ("mainnet", "testnet"):
        raise TypeError("Authorized Dataset triangulation requires an explicit Hedera network")

    return cast(VerificationSubject, dict(raw_subject)), cast(HederaNetwork, network)


async def _verify_source(input: AuthorizedDatasetTriangulationV1Input) -> VerificationReport:
    if "receipt" in input:
        return await verify_dataset_v1_with_intent(
            bundle=input["bundle"],
            files=input["files"],
            intent=input["intent"],
            receipt=input["receipt"],
            limits=input.get("limits"),
        )
    return await verify_dataset_v1_with_intent(
        bundle=input["bundle"],
        files=input["files"],
        intent=input["intent"],
        limits=input.get("limits"),
    )


async def triangulate_authorized_dataset_v1(
    config: AuthorizedDatasetTriangulationV1Config,
    input: AuthorizedDatasetTriangulationV1Input,
) -> AuthorizedDatasetTriangulationV1Result:
    """Triangulate local Dataset commitments with authorized registry evidence."""
    subject, network = _checked_subject(input["intent"])
    message_id, transaction_id = _checked_reference(input["hcs_reference"])
    source = _source_report_with_subject_fact(await _verify_source(input))

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
    hcs = triangulate_authorized_hcs_v1(
        AuthorizedHcsTriangulationV1Input(source_report=source, resolution=resolution)
    )

    evidence = resolution.core.evidence
    parsed = parse_dataset_registry_version_created_v1(
        evidence.payload if evidence is not None and evidence.payload_included is True else None,
        network,
    )
    registry = _registry_observation(parsed, hcs.report)
    relationship = TriangulationRelationshipPlanV1(
        id="provided_authorized",
        left_observation_id=_BUNDLE_OBSERVATION_ID,
        right_observation_id=_REGISTRY_OBSERVATION_ID,
        comparisons=(
            TriangulationFactPlanV1(
                key="dataset_key",
                left_key="source_subject_id",
                right_key="dataset.registry.dataset_key",
            ),
            TriangulationFactPlanV1(
                key="dataset_fingerprint",
                left_key="dataset_fingerprint",
                right_key="dataset.registry.dataset_fingerprint",
            ),
        ),
    )
    compared = compare_evidence_triangulation_v1(
        TriangulationV1Input(
            source_report=hcs.report,
            observations=() if registry is None else (registry,),
            relationships=(relationship,),
        )
    )
    profile_finding = _profile_finding(parsed)
    report = VerificationReport(
        intent=compared.report.intent,
        findings=(*compared.report.findings, profile_finding),
        observations=compared.report.observations,
    )

    return AuthorizedDatasetTriangulationV1Result(
        consistency=_aggregate(hcs.consistency, compared.consistency, parsed),
        relationships=(*hcs.relationships, *compared.relationships),
        report=report,
        resolution=AuthorizedDatasetTriangulationResolutionV1(
            authorized_core=resolution.core.status,
            hedera_mirror=resolution.mirror_resolution,
            dataset_registry_event=parsed.status,
        ),
    )