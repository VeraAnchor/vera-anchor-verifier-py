import asyncio
from types import SimpleNamespace
from typing import Literal, cast

import pytest

import vera_anchor_verifier.triangulation.authorized_ingest_v1 as module
from vera_anchor_verifier.auth import (
    create_static_bearer_auth_provider_v1,
)
from vera_anchor_verifier.contracts import (
    VerificationFact,
    VerificationFinding,
    VerificationIntent,
    VerificationObservation,
    VerificationReport,
    VerificationSubject,
)
from vera_anchor_verifier.resolvers.authorized_observation_v1 import (
    AuthorizedHcsObservationsV1Config,
    AuthorizedHcsObservationsV1Result,
)
from vera_anchor_verifier.resolvers.core_authorized_v1 import (
    AuthorizedHcsAcquisitionV1,
    AuthorizedHcsCoreHashObservationV1,
    AuthorizedHcsEncryptionV1,
    AuthorizedHcsEvidenceV1,
    AuthorizedHcsEvidenceV1Result,
    AuthorizedHcsMessageBindingV1,
    AuthorizedHcsTopicV1,
    AuthorizedHcsTransactionV1,
    CoreAuthorizedV1Config,
)
from vera_anchor_verifier.resolvers.hedera_mirror_v1 import (
    HederaMessageObservationV1,
)
from vera_anchor_verifier.triangulation.authorized_ingest_v1 import (
    AuthorizedIngestTriangulationV1Input,
    parse_authorized_ingest_receipt_v1,
    triangulate_authorized_ingest_v1,
)

NETWORK = "testnet"
SUBJECT = cast(
    VerificationSubject,
    {
        "kind": "ingest",
        "id": "research.ingest",
        "hedera_network": NETWORK,
    },
)

MESSAGE_HASH = "a" * 128
ROOT = "b" * 128
BUNDLE = "c" * 128
FINGERPRINT = "d" * 128
IDEMPOTENCY = "e" * 128

RAW_RECEIPT: dict[str, object] = {
    "v": "v1",
    "kind": "ingest_receipt",
    "mode": "register_and_anchor",
    "private_user_metadata": "private-user-metadata",
}


def run[T](coro) -> T:
    return asyncio.run(coro)


def source_report(
    with_receipt: bool = False,
) -> VerificationReport:
    intent = cast(
        VerificationIntent,
        {
            "subject": SUBJECT,
            "expected": [],
        },
    )

    observations = [
        VerificationObservation(
            id="ingest.source",
            subject={
                "kind": "ingest",
                "id": SUBJECT["id"],
            },
            source="local_computation",
            facts=(
                VerificationFact(
                    key="source_file_or_item_count",
                    state="available",
                    value=2,
                ),
                VerificationFact(
                    key="source_total_bytes",
                    state="available",
                    value=25,
                ),
                VerificationFact(
                    key="source_merkle_root",
                    state="available",
                    value=ROOT,
                ),
            ),
        ),
        VerificationObservation(
            id="ingest.bundle",
            subject={
                "kind": "ingest",
                "id": SUBJECT["id"],
            },
            source="local_computation",
            facts=(
                VerificationFact(
                    key="bundle_digest",
                    state="available",
                    value=BUNDLE,
                ),
                VerificationFact(
                    key="idempotency_key",
                    state="available",
                    value=IDEMPOTENCY,
                ),
                VerificationFact(
                    key="declared_file_or_item_count",
                    state="available",
                    value=2,
                ),
                VerificationFact(
                    key="declared_total_bytes",
                    state="available",
                    value=25,
                ),
                VerificationFact(
                    key="fingerprint",
                    state="available",
                    value=FINGERPRINT,
                ),
            ),
        ),
    ]

    if with_receipt:
        observations.append(
            VerificationObservation(
                id="ingest.receipt",
                subject=SUBJECT,
                source="provided_evidence",
                facts=(
                    VerificationFact(
                        key="receipt_id_recomputed",
                        state="available",
                        value="f" * 128,
                    ),
                    VerificationFact(
                        key="receipt_declared_network",
                        state="available",
                        value=None,
                    ),
                ),
            )
        )

    return VerificationReport(
        intent=intent,
        observations=tuple(observations),
        findings=(
            VerificationFinding(
                check_id="ingest.source_binding",
                outcome="pass",
                reason_code=None,
                observation_ids=(
                    "ingest.source",
                    "ingest.bundle",
                ),
            ),
            VerificationFinding(
                check_id="ingest.bundle_consistency",
                outcome="pass",
                reason_code=None,
                observation_ids=(
                    "ingest.bundle",
                ),
            ),
            VerificationFinding(
                check_id="ingest.receipt_binding",
                outcome=(
                    "pass"
                    if with_receipt
                    else "indeterminate"
                ),
                reason_code=(
                    None
                    if with_receipt
                    else "RECEIPT_NOT_SUPPLIED"
                ),
                observation_ids=(
                    (
                        "ingest.bundle",
                        "ingest.receipt",
                    )
                    if with_receipt
                    else ()
                ),
            ),
            VerificationFinding(
                check_id="intent.subject",
                outcome="pass",
                reason_code=None,
                observation_ids=(
                    "ingest.source",
                    "ingest.bundle",
                ),
            ),
            VerificationFinding(
                check_id="intent.declared_network",
                outcome="indeterminate",
                reason_code=(
                    "NETWORK_EVIDENCE_UNAVAILABLE"
                ),
                observation_ids=(),
            ),
        ),
    )


def receipt(
    *,
    fingerprint: str = FINGERPRINT,
):
    return SimpleNamespace(
        hedera_network=None,
        object_key=SUBJECT["id"],
        object_kind="file_set",
        program=None,
        version_label=None,
        receipt_id="f" * 128,
        idempotency_key=IDEMPOTENCY,
        fingerprint=fingerprint,
        bundle_digest=BUNDLE,
        merkle_root=ROOT,
        item_count=2,
        total_bytes=25,
        receipt_anchor_id=None,
        receipt_anchor_hash=None,
        receipt_leaf_id=None,
        receipt_leaf_hash=None,
        receipt_payload_hash=None,
        receipt_hcs_transaction_id=None,
        receipt_hcs_message_id=None,
        root_anchor_id=None,
        root_anchor_hash=None,
        root_id=None,
        anchored_root_hash=None,
        root_hcs_transaction_id=None,
        root_hcs_message_id=None,
    )


def hcs_observation(
    source: Literal[
        "authorized_service",
        "hedera_mirror",
    ],
) -> VerificationObservation:
    authorized = (
        source == "authorized_service"
    )

    return VerificationObservation(
        id=(
            "ingest.authorized_core"
            if authorized
            else "ingest.hedera_mirror"
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
                value=7,
            ),
            VerificationFact(
                key="publication.message_sha3_512",
                state="available",
                value=MESSAGE_HASH,
            ),
            VerificationFact(
                key="publication.message_bytes",
                state="available",
                value=256,
            ),
        ),
    )


def resolution(
    payload: object,
    mirror_status: Literal[
        "resolved",
        "unavailable",
    ] = "resolved",
) -> AuthorizedHcsObservationsV1Result:
    authorized = hcs_observation(
        "authorized_service"
    )
    mirror_observation = hcs_observation(
        "hedera_mirror"
    )

    evidence = AuthorizedHcsEvidenceV1(
        acquisition=AuthorizedHcsAcquisitionV1(
            resolver_id="core.authorized-hcs.v1",
            access_context="authorized",
            retrieval_provider="vera_anchor_core",
            decryption_method="service_assisted",
            recoverability="service_dependent",
        ),
        hedera_network="testnet",
        topic=AuthorizedHcsTopicV1(
            name="merkle_anchor",
            topic_id="0.0.12345",
            key_version=None,
        ),
        encryption=AuthorizedHcsEncryptionV1(
            topic_key_version=None,
            user_key_version=None,
        ),
        tx=AuthorizedHcsTransactionV1(
            id="11111111-1111-4111-8111-111111111111",
            message_id="7@0.0.12345",
            transaction_id=(
                "0.0.77@1234567890.123456789"
            ),
            sequence_number=7,
            consensus_timestamp=(
                "1234567890.123456789"
            ),
            status="confirmed",
            mirror_verified=False,
            mirror_verified_at=None,
        ),
        core_hash_observation=(
            AuthorizedHcsCoreHashObservationV1(
                expected=None,
                computed=None,
            )
        ),
        message_binding=(
            AuthorizedHcsMessageBindingV1(
                schema_version=(
                    "vera.hcs-message-binding.v1"
                ),
                algorithm="sha3-512",
                message_sha3_512=MESSAGE_HASH,
                message_bytes=256,
            )
        ),
        payload_included=True,
        payload=payload,
    )

    mirror = (
        HederaMessageObservationV1(
            status="resolved",
            reason_code=None,
            observation=mirror_observation,
        )
        if mirror_status == "resolved"
        else HederaMessageObservationV1(
            status="unavailable",
            reason_code="MIRROR_UNAVAILABLE",
            observation=None,
        )
    )

    return AuthorizedHcsObservationsV1Result(
        core=AuthorizedHcsEvidenceV1Result(
            status="resolved",
            reason_code=None,
            evidence=evidence,
        ),
        authorized_observation=authorized,
        mirror=mirror,
        mirror_resolution=mirror_status,
    )


def config() -> AuthorizedHcsObservationsV1Config:
    return AuthorizedHcsObservationsV1Config(
        core=CoreAuthorizedV1Config(
            base_url="https://core.example.test",
            auth_provider=(
                create_static_bearer_auth_provider_v1(
                    "test-api-key"
                )
            ),
        )
    )


def input() -> AuthorizedIngestTriangulationV1Input:
    return {
        "intent": {
            "subject": SUBJECT,
            "expected": [],
        },
        "bundle": {},
        "material": {
            "kind": "json",
            "value": {},
        },
        "hcs_reference": {
            "message_id": "7@0.0.12345",
        },
    }


def install(
    monkeypatch: pytest.MonkeyPatch,
    *,
    payload: object = RAW_RECEIPT,
    mirror_status: Literal[
        "resolved",
        "unavailable",
    ] = "resolved",
    receipt_ok: bool = True,
    fingerprint: str = FINGERPRINT,
) -> None:
    async def fake_resolve(
        resolver_config,
        resolver_input,
    ):
        del resolver_config, resolver_input

        return resolution(
            payload,
            mirror_status,
        )

    async def fake_verify(**kwargs):
        return source_report(
            with_receipt=(
                "receipt" in kwargs
            )
        )

    def fake_receipt_verifier(value):
        del value

        return SimpleNamespace(
            ok=receipt_ok,
            mismatches=(
                ()
                if receipt_ok
                else (
                    SimpleNamespace(
                        field="receipt_id",
                        expected="a",
                        actual="b",
                    ),
                )
            ),
            computed=receipt(
                fingerprint=fingerprint
            ),
        )

    monkeypatch.setattr(
        module,
        "resolve_authorized_hcs_observations_v1",
        fake_resolve,
    )
    monkeypatch.setattr(
        module,
        "verify_ingest_v1_with_intent",
        fake_verify,
    )
    monkeypatch.setattr(
        module,
        "verify_ingest_v1_receipt",
        fake_receipt_verifier,
    )


def test_binds_local_ingest_to_authorized_receipt_and_hedera(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install(monkeypatch)

    result = run(
        triangulate_authorized_ingest_v1(
            config(),
            input(),
        )
    )

    assert result.consistency == "consistent"
    assert [
        relationship.id
        for relationship
        in result.relationships
    ] == [
        "authorized_hedera",
        "provided_authorized",
    ]

    findings = {
        finding.check_id: finding
        for finding in result.report.findings
    }

    assert (
        findings[
            "triangulation.provided_authorized."
            "merkle_root"
        ].outcome
        == "pass"
    )
    assert (
        findings[
            "triangulation.authorized_ingest."
            "receipt_profile"
        ].outcome
        == "pass"
    )

    authorized_receipt = next(
        observation
        for observation
        in result.report.observations
        if observation.id == "ingest.receipt"
    )

    assert (
        authorized_receipt.source
        == "authorized_service"
    )
    assert (
        authorized_receipt.resolver_id
        == "core.authorized-hcs.v1"
    )

    assert (
        "private-user-metadata"
        not in repr(result.report)
    )


def test_authenticated_receipt_conflict_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install(
        monkeypatch,
        fingerprint="0" * 128,
    )

    result = run(
        triangulate_authorized_ingest_v1(
            config(),
            input(),
        )
    )

    assert result.consistency == "conflict"

    finding = next(
        entry
        for entry in result.report.findings
        if entry.check_id
        == (
            "triangulation.provided_authorized."
            "fingerprint"
        )
    )

    assert finding.outcome == "fail"
    assert finding.reason_code == "FACT_MISMATCH"


def test_self_inconsistent_receipt_is_not_promoted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install(
        monkeypatch,
        receipt_ok=False,
    )

    result = run(
        triangulate_authorized_ingest_v1(
            config(),
            input(),
        )
    )

    assert result.consistency == "conflict"
    assert (
        result.resolution.ingest_receipt
        == "conflict"
    )

    assert not any(
        observation.id == "ingest.receipt"
        and observation.source
        == "authorized_service"
        for observation
        in result.report.observations
    )


def test_mirror_unavailability_remains_incomplete(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install(
        monkeypatch,
        mirror_status="unavailable",
    )

    result = run(
        triangulate_authorized_ingest_v1(
            config(),
            input(),
        )
    )

    assert result.consistency == "incomplete"
    assert (
        result.resolution.hedera_mirror
        == "unavailable"
    )


def test_rejects_caller_receipt_and_requires_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install(monkeypatch)

    caller_receipt = dict(input())
    caller_receipt["receipt"] = RAW_RECEIPT

    with pytest.raises(
        TypeError,
        match="does not accept caller-supplied receipt",
    ):
        run(
            triangulate_authorized_ingest_v1(
                config(),
                cast(
                    AuthorizedIngestTriangulationV1Input,
                    caller_receipt,
                ),
            )
        )

    missing_network = dict(input())
    missing_network["intent"] = {
        "subject": {
            "kind": "ingest",
            "id": SUBJECT["id"],
        },
        "expected": [],
    }

    with pytest.raises(
        TypeError,
        match="explicit Hedera network",
    ):
        run(
            triangulate_authorized_ingest_v1(
                config(),
                cast(
                    AuthorizedIngestTriangulationV1Input,
                    missing_network,
                ),
            )
        )


def test_unsupported_receipt_is_classified_before_verifier(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    called = False

    def verifier(value):
        nonlocal called
        called = True
        raise AssertionError(
            "receipt verifier must not run"
        )

    monkeypatch.setattr(
        module,
        "verify_ingest_v1_receipt",
        verifier,
    )

    result = (
        parse_authorized_ingest_receipt_v1(
            {
                "v": "v2",
                "kind": "ingest_receipt",
                "mode": "register_and_anchor",
            },
            "testnet",
        )
    )

    assert result.status == "unsupported"
    assert (
        result.reason_code
        == "AUTHORIZED_INGEST_RECEIPT_UNSUPPORTED"
    )
    assert called is False