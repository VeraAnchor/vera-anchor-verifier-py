"""Public Dataset and Ingest evidence triangulation."""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal, NotRequired, TypedDict, cast

from ..contracts import (
    EvidenceConsistency,
    HederaNetwork,
    VerificationFact,
    VerificationFinding,
    VerificationObservation,
    VerificationReport,
    VerificationSubject,
)
from ..profiles.source_v1_helpers import SourceV1File, SourceV1Limits
from ..resolvers.explorer_public_v1 import (
    ExplorerDatasetV1Request,
    ExplorerIngestV1Request,
    ExplorerPublicationV1,
)
from ..resolvers.explorer_publication_v1 import (
    ExplorerPublishedEvidenceV1,
    resolve_explorer_dataset_publication_v1,
    resolve_explorer_ingest_publication_v1,
)
from ..resolvers.explorer_transport_v1 import ExplorerPublicTransportV1
from ..resolvers.hedera_mirror_v1 import (
    HederaMessageObservationV1,
    HederaMirrorV1Config,
    resolve_hedera_publication_v1,
)
from ..verification.source_intent_v1 import (
    verify_dataset_v1_with_intent,
    verify_ingest_v1_with_intent,
)
from .compare_v1 import (
    TriangulationFactPlanV1,
    TriangulationRelationshipPlanV1,
    TriangulationRelationshipResultV1,
    TriangulationV1Input,
    compare_evidence_triangulation_v1,
)

_PROOF_DATASET = "publication.proof.fingerprint"
_PROOF_INGEST_FINGERPRINT = "publication.proof.ingest_fingerprint"
_PROOF_INGEST_BUNDLE = "publication.proof.ingest_bundle_digest"
_MISSING = object()

type Profile = Literal["dataset", "ingest"]
type PublicRecordResolutionV1 = Literal[
    "resolved", "not_found", "unavailable", "invalid", "conflict"
]
type PublicationDisclosureResolutionV1 = Literal[
    "resolved", "unavailable", "invalid", "conflict", "unsupported"
]
type HederaMirrorResolutionV1 = Literal[
    "resolved", "unavailable", "invalid", "conflict", "not_requested"
]


class PublicIngestTriangulationV1Input(TypedDict):
    bundle: object
    material: object
    intent: object
    anchor_request_id: str
    receipt: NotRequired[object]
    limits: NotRequired[SourceV1Limits]


@dataclass(frozen=True, slots=True)
class PublicTriangulationV1Config:
    explorer: ExplorerPublicTransportV1
    mirror: HederaMirrorV1Config | None = None


@dataclass(frozen=True, slots=True)
class PublicTriangulationResolutionV1:
    public_record: PublicRecordResolutionV1
    publication_disclosure: PublicationDisclosureResolutionV1
    hedera_mirror: HederaMirrorResolutionV1


@dataclass(frozen=True, slots=True)
class PublicTriangulationV1Result:
    consistency: EvidenceConsistency
    relationships: tuple[TriangulationRelationshipResultV1, ...]
    report: VerificationReport
    resolution: PublicTriangulationResolutionV1


def _required_subject(intent: object) -> VerificationSubject:
    if not isinstance(intent, Mapping):
        raise TypeError(
            "Public triangulation requires an explicit Hedera network "
            "in verification intent"
        )
    raw_subject = intent.get("subject")
    if not isinstance(raw_subject, Mapping):
        raise TypeError(
            "Public triangulation requires an explicit Hedera network "
            "in verification intent"
        )
    return cast(VerificationSubject, dict(raw_subject))


def _required_network(subject: VerificationSubject) -> HederaNetwork:
    network = subject.get("hedera_network")
    if network not in ("mainnet", "testnet"):
        raise TypeError(
            "Public triangulation requires an explicit Hedera network "
            "in verification intent"
        )
    return network


def _not_available(key: str, reason: str) -> VerificationFact:
    return VerificationFact(key=key, state="unavailable", reason_code=reason)


def _available(key: str, value: str | int | float) -> VerificationFact:
    return VerificationFact(key=key, state="available", value=value)


def _merge_public_facts(
    profile: Profile,
    disclosure: ExplorerPublishedEvidenceV1,
) -> VerificationObservation | None:
    public_observation = disclosure.public_record.observation
    if public_observation is None:
        return None

    claims = disclosure.disclosure.receipt_observation
    if claims is not None:
        extra = claims.facts
    else:
        keys = (
            ("publication.proof.dataset_key", _PROOF_DATASET)
            if profile == "dataset"
            else (
                "publication.proof.ingest_object_key",
                _PROOF_INGEST_FINGERPRINT,
                _PROOF_INGEST_BUNDLE,
            )
        )
        reason = (
            disclosure.disclosure.reason_code
            or "PUBLICATION_DISCLOSURE_UNAVAILABLE"
        )
        extra = tuple(_not_available(key, reason) for key in keys)

    return VerificationObservation(
        id=public_observation.id,
        subject=public_observation.subject,
        source=public_observation.source,
        resolver_id=public_observation.resolver_id,
        facts=(*public_observation.facts, *extra),
    )


def _merge_binding_facts(
    subject: VerificationSubject,
    publication: ExplorerPublicationV1 | None,
    disclosure: ExplorerPublishedEvidenceV1,
) -> VerificationObservation:
    claim = disclosure.disclosure.message_binding_observation
    reason = (
        disclosure.disclosure.reason_code
        or "PUBLICATION_MESSAGE_BINDING_UNAVAILABLE"
    )
    binding = (
        claim.facts
        if claim is not None
        else (
            _not_available("publication.message_sha3_512", reason),
            _not_available("publication.message_bytes", reason),
        )
    )
    topic_fact = (
        _available("publication.topic_id", publication.topic_id)
        if publication is not None and publication.topic_id is not None
        else _not_available("publication.topic_id", "PUBLICATION_LOCATOR_UNAVAILABLE")
    )
    sequence_fact = (
        _available("publication.sequence_number", publication.sequence_number)
        if publication is not None and publication.sequence_number is not None
        else _not_available(
            "publication.sequence_number",
            "PUBLICATION_LOCATOR_UNAVAILABLE",
        )
    )
    return VerificationObservation(
        id=f"{subject['kind']}.core_binding",
        subject=cast(VerificationSubject, dict(subject)),
        source="public_record",
        resolver_id="explorer.publication-claims.v1",
        facts=(*binding, topic_fact, sequence_fact),
    )


def _plans(profile: Profile) -> tuple[TriangulationRelationshipPlanV1, ...]:
    public_comparisons: tuple[TriangulationFactPlanV1, ...]
    if profile == "dataset":
        public_comparisons = (
            TriangulationFactPlanV1(
                key="dataset_fingerprint",
                left_key="dataset_fingerprint",
                right_key="dataset_fingerprint",
            ),
            TriangulationFactPlanV1(
                key="publication_subject",
                left_key="source_subject_id",
                right_key="publication.proof.dataset_key",
            ),
            TriangulationFactPlanV1(
                key="publication_fingerprint",
                left_key="dataset_fingerprint",
                right_key=_PROOF_DATASET,
            ),
        )
    else:
        public_comparisons = (
            TriangulationFactPlanV1(
                key="ingest_fingerprint",
                left_key="fingerprint",
                right_key="fingerprint",
            ),
            TriangulationFactPlanV1(
                key="ingest_bundle_digest",
                left_key="bundle_digest",
                right_key="bundle_digest",
            ),
            TriangulationFactPlanV1(
                key="publication_subject",
                left_key="source_subject_id",
                right_key="publication.proof.ingest_object_key",
            ),
            TriangulationFactPlanV1(
                key="publication_fingerprint",
                left_key="fingerprint",
                right_key=_PROOF_INGEST_FINGERPRINT,
            ),
            TriangulationFactPlanV1(
                key="publication_bundle_digest",
                left_key="bundle_digest",
                right_key=_PROOF_INGEST_BUNDLE,
            ),
        )

    return (
        TriangulationRelationshipPlanV1(
            id="provided_public_record",
            left_observation_id=f"{profile}.bundle",
            right_observation_id=f"{profile}.public_record",
            comparisons=public_comparisons,
        ),
        TriangulationRelationshipPlanV1(
            id="public_record_hedera",
            left_observation_id=f"{profile}.core_binding",
            right_observation_id=f"{profile}.hedera_mirror",
            comparisons=(
                TriangulationFactPlanV1(
                    key="publication_topic",
                    left_key="publication.topic_id",
                    right_key="hedera.topic_id",
                ),
                TriangulationFactPlanV1(
                    key="publication_sequence",
                    left_key="publication.sequence_number",
                    right_key="hedera.sequence_number",
                ),
                TriangulationFactPlanV1(
                    key="message_sha3_512",
                    left_key="publication.message_sha3_512",
                    right_key="publication.message_sha3_512",
                ),
                TriangulationFactPlanV1(
                    key="message_bytes",
                    left_key="publication.message_bytes",
                    right_key="publication.message_bytes",
                ),
            ),
        ),
    )


def _scope_bundle_subject(
    profile: Profile,
    source_report: VerificationReport,
    subject: VerificationSubject,
) -> VerificationReport:
    observations: list[VerificationObservation] = []
    for observation in source_report.observations:
        if observation.id != f"{profile}.bundle":
            observations.append(observation)
            continue
        observations.append(
            VerificationObservation(
                id=observation.id,
                subject=observation.subject,
                source=observation.source,
                resolver_id=observation.resolver_id,
                facts=(
                    *observation.facts,
                    _available("source_subject_id", subject["id"]),
                ),
            )
        )

    return VerificationReport(
        intent=source_report.intent,
        findings=source_report.findings,
        observations=tuple(observations),
    )


def _conflict_finding(
    check_id: str,
    reason_code: str | None,
) -> VerificationFinding:
    return VerificationFinding(
        check_id=check_id,
        outcome="fail",
        reason_code=reason_code,
        observation_ids=(),
    )


async def _execute(
    config: PublicTriangulationV1Config,
    profile: Profile,
    source_report: VerificationReport,
    public_evidence: ExplorerPublishedEvidenceV1,
) -> PublicTriangulationV1Result:
    subject = source_report.intent["subject"]
    public_record = _merge_public_facts(profile, public_evidence)
    publication = public_evidence.public_record.publication
    mirror: HederaMessageObservationV1 | None = None

    if publication is not None:
        mirror = await resolve_hedera_publication_v1(
            config.mirror if config.mirror is not None else HederaMirrorV1Config(),
            publication,
            subject,
        )

    binding = _merge_binding_facts(subject, publication, public_evidence)
    disclosure_receipt = public_evidence.disclosure.receipt_observation
    observations: list[VerificationObservation] = []
    if public_record is not None:
        observations.append(public_record)
    observations.append(binding)
    if disclosure_receipt is not None:
        observations.append(disclosure_receipt)
    if mirror is not None and mirror.observation is not None:
        observations.append(mirror.observation)

    scoped_report = _scope_bundle_subject(profile, source_report, subject)
    compared = compare_evidence_triangulation_v1(
        TriangulationV1Input(
            source_report=scoped_report,
            observations=tuple(observations),
            relationships=_plans(profile),
        )
    )
    plaintext_binding = VerificationFinding(
        check_id="triangulation.plaintext_ciphertext_binding",
        outcome="indeterminate",
        reason_code=(
            "EXPLORER_ASSISTED_DECRYPTION"
            if disclosure_receipt is not None
            else "PUBLICATION_DISCLOSURE_UNAVAILABLE"
        ),
        observation_ids=(
            (disclosure_receipt.id,) if disclosure_receipt is not None else ()
        ),
    )

    conflicts: list[VerificationFinding] = []
    if public_evidence.public_record.status == "conflict":
        conflicts.append(
            _conflict_finding(
                "triangulation.public_record_scope",
                public_evidence.public_record.reason_code,
            )
        )
    if public_evidence.disclosure.status == "conflict":
        conflicts.append(
            _conflict_finding(
                "triangulation.publication_disclosure",
                public_evidence.disclosure.reason_code,
            )
        )
    if mirror is not None and mirror.status == "conflict":
        conflicts.append(
            _conflict_finding("triangulation.mirror_transaction", mirror.reason_code)
        )

    report = VerificationReport(
        intent=compared.report.intent,
        findings=(*compared.report.findings, plaintext_binding, *conflicts),
        observations=compared.report.observations,
    )
    consistency: EvidenceConsistency = "conflict" if conflicts else compared.consistency
    return PublicTriangulationV1Result(
        consistency=consistency,
        relationships=compared.relationships,
        report=report,
        resolution=PublicTriangulationResolutionV1(
            public_record=public_evidence.public_record.status,
            publication_disclosure=public_evidence.disclosure.status,
            hedera_mirror="not_requested" if mirror is None else mirror.status,
        ),
    )


async def triangulate_dataset_v1(
    config: PublicTriangulationV1Config,
    *,
    bundle: object,
    files: list[SourceV1File],
    intent: object,
    receipt: object = _MISSING,
    limits: SourceV1Limits | None = None,
) -> PublicTriangulationV1Result:
    """Recompute Dataset source evidence and triangulate public publication."""
    subject = _required_subject(intent)
    network = _required_network(subject)
    if subject.get("kind") != "dataset":
        raise TypeError("Dataset triangulation requires dataset intent")

    if receipt is _MISSING:
        source = await verify_dataset_v1_with_intent(
            bundle=bundle,
            files=files,
            intent=intent,
            limits=limits,
        )
    else:
        source = await verify_dataset_v1_with_intent(
            bundle=bundle,
            files=files,
            intent=intent,
            receipt=receipt,
            limits=limits,
        )

    published = await resolve_explorer_dataset_publication_v1(
        config.explorer,
        ExplorerDatasetV1Request(dataset_key=subject["id"], network=network),
    )
    return await _execute(config, "dataset", source, published)


async def triangulate_ingest_v1(
    config: PublicTriangulationV1Config,
    *,
    bundle: object,
    material: object,
    intent: object,
    anchor_request_id: str,
    receipt: object = _MISSING,
    limits: SourceV1Limits | None = None,
) -> PublicTriangulationV1Result:
    """Recompute Ingest source evidence and triangulate its public anchor."""
    subject = _required_subject(intent)
    network = _required_network(subject)
    if subject.get("kind") != "ingest":
        raise TypeError("Ingest triangulation requires ingest intent")

    if receipt is _MISSING:
        source = await verify_ingest_v1_with_intent(
            bundle=bundle,
            material=material,
            intent=intent,
            limits=limits,
        )
    else:
        source = await verify_ingest_v1_with_intent(
            bundle=bundle,
            material=material,
            intent=intent,
            receipt=receipt,
            limits=limits,
        )

    published = await resolve_explorer_ingest_publication_v1(
        config.explorer,
        ExplorerIngestV1Request(
            anchor_request_id=anchor_request_id,
            ingest_object_key=subject["id"],
            network=network,
        ),
    )
    return await _execute(config, "ingest", source, published)