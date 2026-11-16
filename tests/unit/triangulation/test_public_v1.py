import asyncio
from typing import cast

import pytest

import vera_anchor_verifier.triangulation.public_v1 as public_v1
from vera_anchor_verifier import (
    VerificationFact,
    VerificationFinding,
    VerificationIntent,
    VerificationObservation,
    VerificationReport,
    VerificationSubject,
)
from vera_anchor_verifier.resolvers import (
    ExplorerPublicationDisclosureV1,
    ExplorerPublicationV1,
    ExplorerPublicRecordV1,
    ExplorerPublicTransportV1,
    ExplorerPublishedEvidenceV1,
    HederaMessageObservationV1,
)
from vera_anchor_verifier.triangulation.public_v1 import (
    PublicTriangulationV1Config,
    triangulate_dataset_v1,
    triangulate_ingest_v1,
)

DIGEST = "a" * 128
BUNDLE_DIGEST = "b" * 128
MESSAGE_DIGEST = "c" * 128

DATASET_SUBJECT = cast(
    VerificationSubject,
    {
        "kind": "dataset",
        "id": "dataset.alpha",
        "hedera_network": "testnet",
    },
)
INGEST_SUBJECT = cast(
    VerificationSubject,
    {
        "kind": "ingest",
        "id": "object.alpha",
        "hedera_network": "testnet",
    },
)


def run[T](coro) -> T:
    return asyncio.run(coro)


def fact(
    key: str,
    value: str | int,
) -> VerificationFact:
    return VerificationFact(
        key=key,
        state="available",
        value=value,
    )


def observation(
    observation_id: str,
    subject: VerificationSubject,
    source: str,
    facts: tuple[VerificationFact, ...],
    *,
    resolver_id: str | None = None,
) -> VerificationObservation:
    return VerificationObservation(
        id=observation_id,
        subject=subject,
        source=source,  # type: ignore[arg-type]
        resolver_id=resolver_id,
        facts=facts,
    )


def source_report(
    profile: str,
    subject: VerificationSubject,
) -> VerificationReport:
    fingerprint_key = (
        "dataset_fingerprint"
        if profile == "dataset"
        else "fingerprint"
    )

    intent = cast(
        VerificationIntent,
        {
            "subject": subject,
            "expected": [],
        },
    )

    content_subject = cast(
        VerificationSubject,
        {
            "kind": subject["kind"],
            "id": subject["id"],
        },
    )

    return VerificationReport(
        intent=intent,
        findings=(
            VerificationFinding(
                check_id=f"{profile}.source_binding",
                outcome="pass",
                reason_code=None,
                observation_ids=(
                    f"{profile}.source",
                    f"{profile}.bundle",
                ),
            ),
            VerificationFinding(
                check_id=f"{profile}.bundle_consistency",
                outcome="pass",
                reason_code=None,
                observation_ids=(f"{profile}.bundle",),
            ),
            VerificationFinding(
                check_id="intent.subject",
                outcome="pass",
                reason_code=None,
                observation_ids=(
                    f"{profile}.source",
                    f"{profile}.bundle",
                ),
            ),
        ),
        observations=(
            observation(
                f"{profile}.source",
                content_subject,
                "local_computation",
                (
                    fact("source_file_or_item_count", 1),
                    fact("source_total_bytes", 3),
                ),
            ),
            observation(
                f"{profile}.bundle",
                content_subject,
                "local_computation",
                (
                    fact(fingerprint_key, DIGEST),
                    fact("bundle_digest", BUNDLE_DIGEST),
                ),
            ),
        ),
    )


def publication() -> ExplorerPublicationV1:
    return ExplorerPublicationV1(
        hedera_network="testnet",
        entity_kind="dataset_version",
        entity_id="version-1",
        transaction_id=None,
        message_id="7@0.0.123",
        topic_id="0.0.123",
        sequence_number=7,
    )


def dataset_evidence() -> ExplorerPublishedEvidenceV1:
    subject = DATASET_SUBJECT

    public_record = ExplorerPublicRecordV1(
        status="resolved",
        reason_code=None,
        observation=observation(
            "dataset.public_record",
            subject,
            "public_record",
            (
                fact("dataset_fingerprint", DIGEST),
            ),
            resolver_id="explorer.public-http.v1",
        ),
        publication=publication(),
    )

    receipt = observation(
        "dataset.publication_receipt",
        subject,
        "public_record",
        (
            fact(
                "publication.proof.dataset_key",
                "dataset.alpha",
            ),
            fact(
                "publication.proof.fingerprint",
                DIGEST,
            ),
        ),
        resolver_id="explorer.public-disclosure.v1",
    )

    binding = observation(
        "dataset.core_binding",
        subject,
        "public_record",
        (
            fact(
                "publication.message_sha3_512",
                MESSAGE_DIGEST,
            ),
            fact(
                "publication.message_bytes",
                3,
            ),
        ),
    )

    return ExplorerPublishedEvidenceV1(
        public_record=public_record,
        disclosure=ExplorerPublicationDisclosureV1(
            status="resolved",
            reason_code=None,
            receipt_observation=receipt,
            message_binding_observation=binding,
        ),
    )


def mirror_result(
    subject: VerificationSubject,
    profile: str,
) -> HederaMessageObservationV1:
    return HederaMessageObservationV1(
        status="resolved",
        reason_code=None,
        observation=observation(
            f"{profile}.hedera_mirror",
            subject,
            "hedera_mirror",
            (
                fact("hedera.topic_id", "0.0.123"),
                fact("hedera.sequence_number", 7),
                fact(
                    "publication.message_sha3_512",
                    MESSAGE_DIGEST,
                ),
                fact(
                    "publication.message_bytes",
                    3,
                ),
            ),
            resolver_id="hedera.mirror-rest.v1",
        ),
    )


def config() -> PublicTriangulationV1Config:
    return PublicTriangulationV1Config(
        explorer=ExplorerPublicTransportV1(
            base_url="https://explorer.example",
        )
    )


def test_dataset_public_path_combines_all_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def verify(**kwargs):
        assert kwargs["bundle"] is BUNDLE
        assert kwargs["files"] == []
        return source_report(
            "dataset",
            DATASET_SUBJECT,
        )

    async def resolve_dataset(
        transport,
        request,
    ):
        assert transport is not None
        assert request.dataset_key == "dataset.alpha"
        assert request.network == "testnet"
        return dataset_evidence()

    async def resolve_mirror(
        mirror,
        pub,
        subject,
    ):
        assert pub.topic_id == "0.0.123"
        assert subject == DATASET_SUBJECT
        return mirror_result(
            DATASET_SUBJECT,
            "dataset",
        )

    monkeypatch.setattr(
        public_v1,
        "verify_dataset_v1_with_intent",
        verify,
    )
    monkeypatch.setattr(
        public_v1,
        "resolve_explorer_dataset_publication_v1",
        resolve_dataset,
    )
    monkeypatch.setattr(
        public_v1,
        "resolve_hedera_publication_v1",
        resolve_mirror,
    )

    result = run(
        triangulate_dataset_v1(
            config(),
            bundle=BUNDLE,
            files=[],
            intent={
                "subject": DATASET_SUBJECT,
                "expected": [],
            },
        )
    )

    assert result.consistency == "consistent"
    assert result.resolution.public_record == "resolved"
    assert result.resolution.publication_disclosure == "resolved"
    assert result.resolution.hedera_mirror == "resolved"

    assert tuple(
        relationship.status
        for relationship in result.relationships
    ) == (
        "consistent",
        "consistent",
    )

    findings = {
        finding.check_id: finding
        for finding in result.report.findings
    }

    plaintext = findings[
        "triangulation.plaintext_ciphertext_binding"
    ]

    assert plaintext.outcome == "indeterminate"
    assert (
        plaintext.reason_code
        == "EXPLORER_ASSISTED_DECRYPTION"
    )

    bundle_observation = next(
        entry
        for entry in result.report.observations
        if entry.id == "dataset.bundle"
    )
    bundle_facts = {
        entry.key: entry
        for entry in bundle_observation.facts
    }

    assert (
        bundle_facts["source_subject_id"].value
        == "dataset.alpha"
    )


def test_missing_disclosure_remains_incomplete(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence = dataset_evidence()
    evidence = ExplorerPublishedEvidenceV1(
        public_record=evidence.public_record,
        disclosure=ExplorerPublicationDisclosureV1(
            status="unavailable",
            reason_code="PUBLICATION_DECRYPT_UNAVAILABLE",
            receipt_observation=None,
            message_binding_observation=None,
        ),
    )

    async def verify(**kwargs):
        del kwargs
        return source_report(
            "dataset",
            DATASET_SUBJECT,
        )

    async def resolve_dataset(*args):
        del args
        return evidence

    async def resolve_mirror(*args):
        del args
        return mirror_result(
            DATASET_SUBJECT,
            "dataset",
        )

    monkeypatch.setattr(
        public_v1,
        "verify_dataset_v1_with_intent",
        verify,
    )
    monkeypatch.setattr(
        public_v1,
        "resolve_explorer_dataset_publication_v1",
        resolve_dataset,
    )
    monkeypatch.setattr(
        public_v1,
        "resolve_hedera_publication_v1",
        resolve_mirror,
    )

    result = run(
        triangulate_dataset_v1(
            config(),
            bundle=BUNDLE,
            files=[],
            intent={
                "subject": DATASET_SUBJECT,
                "expected": [],
            },
        )
    )

    assert result.consistency == "incomplete"

    finding = next(
        entry
        for entry in result.report.findings
        if entry.check_id
        == "triangulation.plaintext_ciphertext_binding"
    )

    assert (
        finding.reason_code
        == "PUBLICATION_DISCLOSURE_UNAVAILABLE"
    )


def test_public_record_conflict_overrides_comparator(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence = ExplorerPublishedEvidenceV1(
        public_record=ExplorerPublicRecordV1(
            status="conflict",
            reason_code="PUBLIC_DATASET_KEY_MISMATCH",
            observation=None,
            publication=None,
        ),
        disclosure=ExplorerPublicationDisclosureV1(
            status="unavailable",
            reason_code="PUBLICATION_ANCHOR_UNAVAILABLE",
            receipt_observation=None,
            message_binding_observation=None,
        ),
    )

    async def verify(**kwargs):
        del kwargs
        return source_report(
            "dataset",
            DATASET_SUBJECT,
        )

    async def resolve_dataset(*args):
        del args
        return evidence

    monkeypatch.setattr(
        public_v1,
        "verify_dataset_v1_with_intent",
        verify,
    )
    monkeypatch.setattr(
        public_v1,
        "resolve_explorer_dataset_publication_v1",
        resolve_dataset,
    )

    result = run(
        triangulate_dataset_v1(
            config(),
            bundle=BUNDLE,
            files=[],
            intent={
                "subject": DATASET_SUBJECT,
                "expected": [],
            },
        )
    )

    assert result.consistency == "conflict"
    assert result.resolution.hedera_mirror == "not_requested"

    finding = next(
        entry
        for entry in result.report.findings
        if entry.check_id == "triangulation.public_record_scope"
    )

    assert finding.outcome == "fail"
    assert (
        finding.reason_code
        == "PUBLIC_DATASET_KEY_MISMATCH"
    )


def test_mirror_transaction_conflict_is_preserved(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def verify(**kwargs):
        del kwargs
        return source_report(
            "dataset",
            DATASET_SUBJECT,
        )

    async def resolve_dataset(*args):
        del args
        return dataset_evidence()

    async def resolve_mirror(*args):
        del args
        return HederaMessageObservationV1(
            status="conflict",
            reason_code="MIRROR_TRANSACTION_FAILED",
            observation=None,
        )

    monkeypatch.setattr(
        public_v1,
        "verify_dataset_v1_with_intent",
        verify,
    )
    monkeypatch.setattr(
        public_v1,
        "resolve_explorer_dataset_publication_v1",
        resolve_dataset,
    )
    monkeypatch.setattr(
        public_v1,
        "resolve_hedera_publication_v1",
        resolve_mirror,
    )

    result = run(
        triangulate_dataset_v1(
            config(),
            bundle=BUNDLE,
            files=[],
            intent={
                "subject": DATASET_SUBJECT,
                "expected": [],
            },
        )
    )

    assert result.consistency == "conflict"

    finding = next(
        entry
        for entry in result.report.findings
        if entry.check_id == "triangulation.mirror_transaction"
    )

    assert (
        finding.reason_code
        == "MIRROR_TRANSACTION_FAILED"
    )


def test_dataset_requires_network_and_correct_profile() -> None:
    with pytest.raises(
        TypeError,
        match="explicit Hedera network",
    ):
        run(
            triangulate_dataset_v1(
                config(),
                bundle=BUNDLE,
                files=[],
                intent={
                    "subject": {
                        "kind": "dataset",
                        "id": "dataset.alpha",
                    },
                    "expected": [],
                },
            )
        )

    with pytest.raises(
        TypeError,
        match="requires dataset intent",
    ):
        run(
            triangulate_dataset_v1(
                config(),
                bundle=BUNDLE,
                files=[],
                intent={
                    "subject": INGEST_SUBJECT,
                    "expected": [],
                },
            )
        )


def test_ingest_uses_independent_anchor_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = source_report(
        "ingest",
        INGEST_SUBJECT,
    )

    public_record = ExplorerPublicRecordV1(
        status="resolved",
        reason_code=None,
        observation=observation(
            "ingest.public_record",
            INGEST_SUBJECT,
            "public_record",
            (
                fact("fingerprint", DIGEST),
                fact("bundle_digest", BUNDLE_DIGEST),
            ),
        ),
        publication=ExplorerPublicationV1(
            hedera_network="testnet",
            entity_kind="merkle_anchor",
            entity_id="anchor-1",
            transaction_id=None,
            message_id="7@0.0.123",
            topic_id="0.0.123",
            sequence_number=7,
        ),
    )

    disclosure = ExplorerPublicationDisclosureV1(
        status="resolved",
        reason_code=None,
        receipt_observation=observation(
            "ingest.publication_receipt",
            INGEST_SUBJECT,
            "public_record",
            (
                fact(
                    "publication.proof.ingest_object_key",
                    "object.alpha",
                ),
                fact(
                    "publication.proof.ingest_fingerprint",
                    DIGEST,
                ),
                fact(
                    "publication.proof.ingest_bundle_digest",
                    BUNDLE_DIGEST,
                ),
            ),
        ),
        message_binding_observation=observation(
            "ingest.core_binding",
            INGEST_SUBJECT,
            "public_record",
            (
                fact(
                    "publication.message_sha3_512",
                    MESSAGE_DIGEST,
                ),
                fact(
                    "publication.message_bytes",
                    3,
                ),
            ),
        ),
    )

    async def verify(**kwargs):
        assert kwargs["bundle"] is BUNDLE
        assert kwargs["material"] is MATERIAL
        return source

    async def resolve_ingest(
        transport,
        request,
    ):
        assert transport is not None
        assert request.ingest_object_key == "object.alpha"
        assert request.anchor_request_id == ANCHOR_ID
        assert request.network == "testnet"

        return ExplorerPublishedEvidenceV1(
            public_record=public_record,
            disclosure=disclosure,
        )

    async def resolve_mirror(*args):
        del args
        return mirror_result(
            INGEST_SUBJECT,
            "ingest",
        )

    monkeypatch.setattr(
        public_v1,
        "verify_ingest_v1_with_intent",
        verify,
    )
    monkeypatch.setattr(
        public_v1,
        "resolve_explorer_ingest_publication_v1",
        resolve_ingest,
    )
    monkeypatch.setattr(
        public_v1,
        "resolve_hedera_publication_v1",
        resolve_mirror,
    )

    result = run(
        triangulate_ingest_v1(
            config(),
            bundle=BUNDLE,
            material=MATERIAL,
            intent={
                "subject": INGEST_SUBJECT,
                "expected": [],
            },
            anchor_request_id=ANCHOR_ID,
        )
    )

    assert result.consistency == "consistent"
    assert tuple(
        relationship.status
        for relationship in result.relationships
    ) == (
        "consistent",
        "consistent",
    )


BUNDLE = object()
MATERIAL = object()
ANCHOR_ID = "12345678-1234-1234-1234-123456789abc"