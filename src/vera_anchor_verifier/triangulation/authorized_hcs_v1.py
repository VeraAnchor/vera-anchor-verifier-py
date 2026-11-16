"""Triangulate authorized Core and independent Hedera message evidence."""

import re
from dataclasses import dataclass
from typing import Literal

from ..contracts import (
    EvidenceConsistency,
    VerificationFinding,
    VerificationObservation,
    VerificationReport,
)
from ..resolvers.authorized_observation_v1 import (
    AuthorizedHcsObservationsV1Result,
    AuthorizedMirrorResolutionV1,
)
from ..resolvers.core_authorized_v1 import AuthorizedHcsEvidenceStatusV1
from .compare_v1 import (
    TriangulationFactPlanV1,
    TriangulationRelationshipPlanV1,
    TriangulationRelationshipResultV1,
    TriangulationV1Input,
    compare_evidence_triangulation_v1,
)

_OBSERVATION_ID_RE = re.compile(r"^[a-z][a-z0-9._:-]{0,127}$", re.ASCII)


@dataclass(frozen=True, slots=True)
class AuthorizedHcsTriangulationV1Input:
    source_report: VerificationReport
    resolution: AuthorizedHcsObservationsV1Result


@dataclass(frozen=True, slots=True)
class AuthorizedHcsTriangulationResolutionV1:
    authorized_core: AuthorizedHcsEvidenceStatusV1
    hedera_mirror: AuthorizedMirrorResolutionV1


@dataclass(frozen=True, slots=True)
class AuthorizedHcsTriangulationV1Result:
    consistency: EvidenceConsistency
    relationships: tuple[TriangulationRelationshipResultV1, ...]
    report: VerificationReport
    resolution: AuthorizedHcsTriangulationResolutionV1


def _expected_observation_id(
    kind: str,
    suffix: Literal["authorized_core", "hedera_mirror"],
) -> str:
    observation_id = f"{kind}.{suffix}"
    if _OBSERVATION_ID_RE.fullmatch(observation_id) is None:
        raise TypeError(
            "Authenticated HCS triangulation subject kind cannot form a valid observation id"
        )
    return observation_id


def _checked_observation(
    observation: VerificationObservation | None,
    expected_id: str,
    expected_source: Literal["authorized_service", "hedera_mirror"],
) -> VerificationObservation | None:
    if observation is None:
        return None
    if observation.id != expected_id or observation.source != expected_source:
        raise TypeError(
            "Authenticated HCS triangulation received an unexpected observation role"
        )
    return observation


def _mirror_conflict_finding(reason_code: str | None) -> VerificationFinding:
    return VerificationFinding(
        check_id="triangulation.authorized_hedera.mirror_resolution",
        outcome="fail",
        reason_code=reason_code,
        observation_ids=(),
    )


def triangulate_authorized_hcs_v1(
    input: AuthorizedHcsTriangulationV1Input,
) -> AuthorizedHcsTriangulationV1Result:
    """Compare authorized Core message binding with Hedera Mirror evidence."""
    subject = input.source_report.intent["subject"]
    kind = subject["kind"]
    authorized_id = _expected_observation_id(kind, "authorized_core")
    mirror_id = _expected_observation_id(kind, "hedera_mirror")

    authorized = _checked_observation(
        input.resolution.authorized_observation,
        authorized_id,
        "authorized_service",
    )
    mirror = _checked_observation(
        input.resolution.mirror.observation if input.resolution.mirror is not None else None,
        mirror_id,
        "hedera_mirror",
    )

    relationship = TriangulationRelationshipPlanV1(
        id="authorized_hedera",
        left_observation_id=authorized_id,
        right_observation_id=mirror_id,
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
    )
    observations = tuple(
        observation for observation in (authorized, mirror) if observation is not None
    )
    compared = compare_evidence_triangulation_v1(
        TriangulationV1Input(
            source_report=input.source_report,
            observations=observations,
            relationships=(relationship,),
        )
    )

    conflicts: tuple[VerificationFinding, ...] = ()
    if input.resolution.mirror is not None and input.resolution.mirror.status == "conflict":
        conflicts = (_mirror_conflict_finding(input.resolution.mirror.reason_code),)

    if conflicts:
        report = VerificationReport(
            intent=compared.report.intent,
            findings=(*compared.report.findings, *conflicts),
            observations=compared.report.observations,
        )
        consistency: EvidenceConsistency = "conflict"
    else:
        report = compared.report
        consistency = compared.consistency

    return AuthorizedHcsTriangulationV1Result(
        consistency=consistency,
        relationships=compared.relationships,
        report=report,
        resolution=AuthorizedHcsTriangulationResolutionV1(
            authorized_core=input.resolution.core.status,
            hedera_mirror=input.resolution.mirror_resolution,
        ),
    )