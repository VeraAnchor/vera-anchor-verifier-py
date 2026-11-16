from dataclasses import replace
from typing import Literal, cast

import pytest

from vera_anchor_verifier.contracts import (
    VerificationFinding,
    VerificationIntent,
    VerificationReport,
    VerificationSubject,
)
from vera_anchor_verifier.reports.portable_v1 import (
    PORTABLE_VERIFICATION_REPORT_SCHEMA_VERSION,
    PortableVerificationReportV1Input,
    canonicalize_portable_verification_report_v1,
    compute_portable_verification_report_digest_v1,
    create_portable_verification_report_v1,
)
from vera_anchor_verifier.triangulation.authorized_dataset_v1 import (
    AuthorizedDatasetTriangulationResolutionV1,
    AuthorizedDatasetTriangulationV1Result,
)
from vera_anchor_verifier.triangulation.authorized_ingest_v1 import (
    AuthorizedIngestTriangulationResolutionV1,
    AuthorizedIngestTriangulationV1Result,
)
from vera_anchor_verifier.triangulation.compare_v1 import (
    TriangulationFactResultV1,
    TriangulationRelationshipResultV1,
)


def report(
    kind: str = "dataset",
) -> VerificationReport:
    subject = cast(
        VerificationSubject,
        {
            "kind": kind,
            "id": (
                "research.dataset"
                if kind == "dataset"
                else "research.ingest"
            ),
            "hedera_network": "testnet",
        },
    )

    return VerificationReport(
        intent=cast(
            VerificationIntent,
            {
                "subject": subject,
                "expected": [],
            },
        ),
        findings=(),
        observations=(),
    )


def relationship(
    relationship_id: Literal[
        "provided_public_record",
        "public_record_hedera",
        "provided_hedera",
        "provided_authorized",
        "authorized_hedera",
    ],
    key: str,
) -> TriangulationRelationshipResultV1:
    return TriangulationRelationshipResultV1(
        id=relationship_id,
        status="consistent",
        fact_comparisons=(
            TriangulationFactResultV1(
                key=key,
                outcome="pass",
                reason_code=None,
            ),
        ),
    )


def with_relationship_findings(
    source: VerificationReport,
    relationships: tuple[
        TriangulationRelationshipResultV1,
        ...,
    ],
    profile_check: str,
) -> VerificationReport:
    findings = [
        VerificationFinding(
            check_id=profile_check,
            outcome="pass",
            reason_code=None,
            observation_ids=(),
        )
    ]

    for entry in relationships:
        for fact in entry.fact_comparisons:
            findings.append(
                VerificationFinding(
                    check_id=(
                        f"triangulation."
                        f"{entry.id}."
                        f"{fact.key}"
                    ),
                    outcome=fact.outcome,
                    reason_code=fact.reason_code,
                    observation_ids=(),
                )
            )

    return replace(
        source,
        findings=tuple(findings),
    )


def test_builds_versioned_verification_report() -> None:
    source = report()

    value = PortableVerificationReportV1Input(
        kind="verification",
        result=source,
    )

    portable = (
        create_portable_verification_report_v1(
            value
        )
    )

    assert (
        portable.schema_version
        == PORTABLE_VERIFICATION_REPORT_SCHEMA_VERSION
    )
    assert portable.kind == "verification"
    assert len(
        portable.core_sha3_512
    ) == 128
    assert len(
        portable.report_sha3_512
    ) == 128
    assert (
        portable.core_sha3_512
        != portable.report_sha3_512
    )


def test_is_deterministic_for_same_core() -> None:
    source = report()

    first = PortableVerificationReportV1Input(
        kind="verification",
        result=source,
    )
    second = PortableVerificationReportV1Input(
        kind="verification",
        result=replace(
            source,
            findings=tuple(
                reversed(
                    source.findings
                )
            ),
        ),
    )

    assert (
        canonicalize_portable_verification_report_v1(
            first
        )
        == canonicalize_portable_verification_report_v1(
            second
        )
    )

    assert (
        compute_portable_verification_report_digest_v1(
            first
        )
        == compute_portable_verification_report_digest_v1(
            second
        )
    )


def test_authorized_dataset_context_is_bound() -> None:
    relationships = (
        relationship(
            "authorized_hedera",
            "message_sha3_512",
        ),
        relationship(
            "provided_authorized",
            "dataset_fingerprint",
        ),
    )

    source = with_relationship_findings(
        report("dataset"),
        relationships,
        (
            "triangulation.authorized_dataset."
            "registry_event_profile"
        ),
    )

    result = (
        AuthorizedDatasetTriangulationV1Result(
            consistency="consistent",
            relationships=relationships,
            report=source,
            resolution=(
                AuthorizedDatasetTriangulationResolutionV1(
                    authorized_core="resolved",
                    hedera_mirror="resolved",
                    dataset_registry_event="resolved",
                )
            ),
        )
    )

    portable = (
        create_portable_verification_report_v1(
            PortableVerificationReportV1Input(
                kind=(
                    "authorized_dataset_triangulation"
                ),
                result=result,
            )
        )
    )

    assert (
        portable.context["consistency"]
        == "consistent"
    )

    assert portable.context[
        "resolution"
    ] == {
        "authorized_core": "resolved",
        "dataset_registry_event": "resolved",
        "hedera_mirror": "resolved",
    }


def test_authorized_ingest_context_is_bound() -> None:
    relationships = (
        relationship(
            "authorized_hedera",
            "message_sha3_512",
        ),
        relationship(
            "provided_authorized",
            "merkle_root",
        ),
    )

    source = with_relationship_findings(
        report("ingest"),
        relationships,
        (
            "triangulation.authorized_ingest."
            "receipt_profile"
        ),
    )

    result = (
        AuthorizedIngestTriangulationV1Result(
            consistency="consistent",
            relationships=relationships,
            report=source,
            resolution=(
                AuthorizedIngestTriangulationResolutionV1(
                    authorized_core="resolved",
                    hedera_mirror="resolved",
                    ingest_receipt="resolved",
                )
            ),
        )
    )

    portable = (
        create_portable_verification_report_v1(
            PortableVerificationReportV1Input(
                kind=(
                    "authorized_ingest_triangulation"
                ),
                result=result,
            )
        )
    )

    assert (
        portable.context["consistency"]
        == "consistent"
    )

    assert portable.context[
        "resolution"
    ] == {
        "authorized_core": "resolved",
        "hedera_mirror": "resolved",
        "ingest_receipt": "resolved",
    }


def test_rejects_missing_authorized_relationship() -> None:
    relationships = (
        relationship(
            "authorized_hedera",
            "message_sha3_512",
        ),
    )

    source = with_relationship_findings(
        report("dataset"),
        relationships,
        (
            "triangulation.authorized_dataset."
            "registry_event_profile"
        ),
    )

    result = (
        AuthorizedDatasetTriangulationV1Result(
            consistency="incomplete",
            relationships=relationships,
            report=source,
            resolution=(
                AuthorizedDatasetTriangulationResolutionV1(
                    authorized_core="resolved",
                    hedera_mirror="resolved",
                    dataset_registry_event="resolved",
                )
            ),
        )
    )

    with pytest.raises(
        TypeError,
        match="missing a required relationship",
    ):
        create_portable_verification_report_v1(
            PortableVerificationReportV1Input(
                kind=(
                    "authorized_dataset_triangulation"
                ),
                result=result,
            )
        )


def test_rejects_contradictory_authorized_aggregate() -> None:
    relationships = (
        relationship(
            "authorized_hedera",
            "message_sha3_512",
        ),
        relationship(
            "provided_authorized",
            "dataset_fingerprint",
        ),
    )

    source = with_relationship_findings(
        report("dataset"),
        relationships,
        (
            "triangulation.authorized_dataset."
            "registry_event_profile"
        ),
    )

    result = (
        AuthorizedDatasetTriangulationV1Result(
            consistency="incomplete",
            relationships=relationships,
            report=source,
            resolution=(
                AuthorizedDatasetTriangulationResolutionV1(
                    authorized_core="resolved",
                    hedera_mirror="resolved",
                    dataset_registry_event="resolved",
                )
            ),
        )
    )

    with pytest.raises(
        TypeError,
        match="Inconsistent authorized Dataset aggregate",
    ):
        create_portable_verification_report_v1(
            PortableVerificationReportV1Input(
                kind=(
                    "authorized_dataset_triangulation"
                ),
                result=result,
            )
        )