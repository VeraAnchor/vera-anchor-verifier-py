from typing import Literal, cast

import pytest

from vera_anchor_verifier.contracts import (
    VerificationFact,
    VerificationFinding,
    VerificationIntent,
    VerificationObservation,
    VerificationReport,
    VerificationSubject,
)
from vera_anchor_verifier.resolvers.authorized_observation_v1 import (
    AuthorizedHcsObservationsV1Result,
)
from vera_anchor_verifier.resolvers.core_authorized_v1 import (
    AuthorizedHcsEvidenceV1Result,
)
from vera_anchor_verifier.resolvers.hedera_mirror_v1 import (
    HederaMessageObservationV1,
)
from vera_anchor_verifier.triangulation.authorized_hcs_v1 import (
    AuthorizedHcsTriangulationV1Input,
    triangulate_authorized_hcs_v1,
)

SUBJECT = cast(
    VerificationSubject,
    {
        "kind": "dataset",
        "id": "research.dataset",
        "hedera_network": "testnet",
    },
)
DIGEST = "a" * 128


def source_report() -> VerificationReport:
    return VerificationReport(
        intent=cast(
            VerificationIntent,
            {
                "subject": SUBJECT,
                "expected": [],
            },
        ),
        findings=(
            VerificationFinding(
                check_id="dataset.source_binding",
                outcome="pass",
                reason_code=None,
                observation_ids=(),
            ),
            VerificationFinding(
                check_id="dataset.bundle_consistency",
                outcome="pass",
                reason_code=None,
                observation_ids=(),
            ),
            VerificationFinding(
                check_id="intent.subject",
                outcome="pass",
                reason_code=None,
                observation_ids=(),
            ),
        ),
        observations=(),
    )


def observation(
    source: Literal[
        "authorized_service",
        "hedera_mirror",
    ],
    digest: str = DIGEST,
) -> VerificationObservation:
    authorized = (
        source == "authorized_service"
    )

    return VerificationObservation(
        id=(
            "dataset.authorized_core"
            if authorized
            else "dataset.hedera_mirror"
        ),
        subject=SUBJECT,
        source=source,
        resolver_id=(
            "core.authorized-hcs.v1"
            if authorized
            else "hedera.mirror-rest.v1"
        ),
        facts=(
            VerificationFact(
                key=(
                    "publication.topic_id"
                    if authorized
                    else "hedera.topic_id"
                ),
                state="available",
                value="0.0.12345",
            ),
            VerificationFact(
                key=(
                    "publication.sequence_number"
                    if authorized
                    else "hedera.sequence_number"
                ),
                state="available",
                value=5,
            ),
            VerificationFact(
                key="publication.message_sha3_512",
                state="available",
                value=digest,
            ),
            VerificationFact(
                key="publication.message_bytes",
                state="available",
                value=42,
            ),
        ),
    )


def resolution(
    authorized: VerificationObservation | None = None,
    mirror_observation: VerificationObservation | None = None,
    mirror_status: Literal[
        "resolved",
        "unavailable",
        "invalid",
        "conflict",
    ] = "resolved",
) -> AuthorizedHcsObservationsV1Result:
    if authorized is None:
        authorized = observation(
            "authorized_service"
        )

    if mirror_observation is None and mirror_status == "resolved":
        mirror_observation = observation(
            "hedera_mirror"
        )

    core = AuthorizedHcsEvidenceV1Result(
        status="resolved",
        reason_code=None,
        evidence=None,
    )

    mirror = HederaMessageObservationV1(
        status=mirror_status,
        reason_code=(
            "MIRROR_TRANSACTION_FAILED"
            if mirror_status == "conflict"
            else (
                None
                if mirror_status == "resolved"
                else "MIRROR_UNAVAILABLE"
            )
        ),
        observation=(
            mirror_observation
            if mirror_status
            in ("resolved", "conflict")
            else None
        ),
    )

    return AuthorizedHcsObservationsV1Result(
        core=core,
        authorized_observation=authorized,
        mirror=mirror,
        mirror_resolution=mirror_status,
    )


def test_establishes_exact_authorized_to_hedera_consistency() -> None:
    result = triangulate_authorized_hcs_v1(
        AuthorizedHcsTriangulationV1Input(
            source_report=source_report(),
            resolution=resolution(),
        )
    )

    assert result.consistency == "consistent"
    assert len(result.relationships) == 1

    relationship = result.relationships[0]

    assert relationship.id == "authorized_hedera"
    assert all(
        comparison.outcome == "pass"
        for comparison
        in relationship.fact_comparisons
    )

    finding = next(
        entry
        for entry in result.report.findings
        if entry.check_id
        == (
            "triangulation.authorized_hedera."
            "message_sha3_512"
        )
    )

    assert finding.outcome == "pass"
    assert result.resolution.authorized_core == "resolved"
    assert result.resolution.hedera_mirror == "resolved"


def test_ciphertext_digest_mismatch_is_conflict() -> None:
    result = triangulate_authorized_hcs_v1(
        AuthorizedHcsTriangulationV1Input(
            source_report=source_report(),
            resolution=resolution(
                authorized=observation(
                    "authorized_service"
                ),
                mirror_observation=observation(
                    "hedera_mirror",
                    "b" * 128,
                ),
            ),
        )
    )

    assert result.consistency == "conflict"

    finding = next(
        entry
        for entry in result.report.findings
        if entry.check_id
        == (
            "triangulation.authorized_hedera."
            "message_sha3_512"
        )
    )

    assert finding.outcome == "fail"
    assert finding.reason_code == "FACT_MISMATCH"


def test_mirror_transaction_conflict_is_preserved() -> None:
    result = triangulate_authorized_hcs_v1(
        AuthorizedHcsTriangulationV1Input(
            source_report=source_report(),
            resolution=resolution(
                mirror_observation=None,
                mirror_status="conflict",
            ),
        )
    )

    assert result.consistency == "conflict"

    finding = next(
        entry
        for entry in result.report.findings
        if entry.check_id
        == (
            "triangulation.authorized_hedera."
            "mirror_resolution"
        )
    )

    assert finding.outcome == "fail"
    assert (
        finding.reason_code
        == "MIRROR_TRANSACTION_FAILED"
    )


def test_unavailable_mirror_evidence_remains_incomplete() -> None:
    result = triangulate_authorized_hcs_v1(
        AuthorizedHcsTriangulationV1Input(
            source_report=source_report(),
            resolution=resolution(
                mirror_observation=None,
                mirror_status="unavailable",
            ),
        )
    )

    assert result.consistency == "incomplete"
    assert (
        result.relationships[0].status
        == "incomplete"
    )


def test_rejects_authenticated_observation_role_substitution() -> None:
    original = observation(
        "authorized_service"
    )

    substituted = VerificationObservation(
        id=original.id,
        subject=original.subject,
        source="public_record",
        resolver_id=original.resolver_id,
        facts=original.facts,
    )

    with pytest.raises(
        TypeError,
        match="unexpected observation role",
    ):
        triangulate_authorized_hcs_v1(
            AuthorizedHcsTriangulationV1Input(
                source_report=source_report(),
                resolution=resolution(
                    authorized=substituted,
                ),
            )
        )


def test_unavailable_authorized_evidence_remains_incomplete() -> None:
    mirror = HederaMessageObservationV1(
        status="resolved",
        reason_code=None,
        observation=observation(
            "hedera_mirror"
        ),
    )

    unresolved = AuthorizedHcsObservationsV1Result(
        core=AuthorizedHcsEvidenceV1Result(
            status="unavailable",
            reason_code="CORE_AUTHORIZED_REQUEST_UNAVAILABLE",
            evidence=None,
        ),
        authorized_observation=None,
        mirror=mirror,
        mirror_resolution="resolved",
    )

    result = triangulate_authorized_hcs_v1(
        AuthorizedHcsTriangulationV1Input(
            source_report=source_report(),
            resolution=unresolved,
        )
    )

    assert result.consistency == "incomplete"
    assert (
        result.relationships[0].status
        == "incomplete"
    )