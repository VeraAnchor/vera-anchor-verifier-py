import asyncio
from typing import Literal, cast

import pytest

import vera_anchor_verifier.triangulation.authorized_dataset_v1 as module
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
from vera_anchor_verifier.profiles.dataset.registry_event_v1 import (
    parse_dataset_registry_version_created_v1,
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
from vera_anchor_verifier.triangulation.authorized_dataset_v1 import (
    AuthorizedDatasetTriangulationV1Input,
    triangulate_authorized_dataset_v1,
)

NETWORK = "testnet"
DATASET_KEY = "research.dataset.v1"
FINGERPRINT = "a" * 128
MESSAGE_DIGEST = "b" * 128
VERSION_ID = (
    "11111111-1111-4111-8111-111111111111"
)

SUBJECT = cast(
    VerificationSubject,
    {
        "kind": "dataset",
        "id": DATASET_KEY,
        "hedera_network": NETWORK,
    },
)


def run[T](coro) -> T:
    return asyncio.run(coro)


def registry_payload(
    fingerprint: str = FINGERPRINT,
    event: str = "dataset_version.created",
) -> dict[str, object]:
    return {
        "_type": "core.dataset_registry.event.v1",
        "event": event,
        "entity_id": f"{DATASET_KEY}@3",
        "ts": "2026-11-05T00:00:00.000Z",
        "actor_user_id": (
            "22222222-2222-4222-8222-222222222222"
        ),
        "hedera_network": NETWORK,
        "service_event_hash": "c" * 128,
        "payload": {
            "dataset_version_id": VERSION_ID,
            "dataset_key": DATASET_KEY,
            "version": 3,
            "dataset_fingerprint": fingerprint,
            "manifest_hash": "d" * 128,
            "schema_hash": "e" * 128,
            "bytes_estimate": 128,
            "row_count": 4,
            "col_count": 2,
            "set_active": False,
        },
    }


def source_report() -> VerificationReport:
    intent = cast(
        VerificationIntent,
        {
            "subject": SUBJECT,
            "expected": [],
        },
    )

    return VerificationReport(
        intent=intent,
        observations=(
            VerificationObservation(
                id="dataset.source",
                subject={
                    "kind": "dataset",
                    "id": DATASET_KEY,
                },
                source="local_computation",
                facts=(),
            ),
            VerificationObservation(
                id="dataset.bundle",
                subject={
                    "kind": "dataset",
                    "id": DATASET_KEY,
                },
                source="local_computation",
                facts=(
                    VerificationFact(
                        key="dataset_fingerprint",
                        state="available",
                        value=FINGERPRINT,
                    ),
                ),
            ),
        ),
        findings=(
            VerificationFinding(
                check_id="dataset.source_binding",
                outcome="pass",
                reason_code=None,
                observation_ids=(
                    "dataset.source",
                    "dataset.bundle",
                ),
            ),
            VerificationFinding(
                check_id=(
                    "dataset.bundle_consistency"
                ),
                outcome="pass",
                reason_code=None,
                observation_ids=(
                    "dataset.bundle",
                ),
            ),
            VerificationFinding(
                check_id="intent.subject",
                outcome="pass",
                reason_code=None,
                observation_ids=(
                    "dataset.source",
                    "dataset.bundle",
                ),
            ),
        ),
    )


def message_observation(
    source: Literal[
        "authorized_service",
        "hedera_mirror",
    ],
) -> VerificationObservation:
    authorized = source == "authorized_service"

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
                value=7,
            ),
            VerificationFact(
                key="publication.message_sha3_512",
                state="available",
                value=MESSAGE_DIGEST,
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
) -> AuthorizedHcsObservationsV1Result:
    authorized = message_observation(
        "authorized_service"
    )
    mirror_observation = message_observation(
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
            name="dataset_registry_events",
            topic_id="0.0.12345",
            key_version=1,
        ),
        encryption=AuthorizedHcsEncryptionV1(
            topic_key_version=1,
            user_key_version=1,
        ),
        tx=AuthorizedHcsTransactionV1(
            id="tx-row",
            message_id="7@0.0.12345",
            transaction_id=(
                "0.0.123@1793836800.000000001"
            ),
            sequence_number=7,
            consensus_timestamp=(
                "1793836800.000000001"
            ),
            status="SUCCESS",
            mirror_verified=True,
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
                message_sha3_512=MESSAGE_DIGEST,
                message_bytes=256,
            )
        ),
        payload_included=True,
        payload=payload,
    )

    return AuthorizedHcsObservationsV1Result(
        core=AuthorizedHcsEvidenceV1Result(
            status="resolved",
            reason_code=None,
            evidence=evidence,
        ),
        authorized_observation=authorized,
        mirror=HederaMessageObservationV1(
            status="resolved",
            reason_code=None,
            observation=mirror_observation,
        ),
        mirror_resolution="resolved",
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


def input() -> AuthorizedDatasetTriangulationV1Input:
    return {
        "bundle": {},
        "files": [],
        "intent": {
            "subject": SUBJECT,
            "expected": [],
        },
        "hcs_reference": {
            "message_id": "7@0.0.12345",
        },
    }


def install_resolution(
    monkeypatch: pytest.MonkeyPatch,
    payload: object,
    calls: list[object] | None = None,
) -> None:
    async def fake_verify(**kwargs):
        del kwargs
        return source_report()

    async def fake_resolve(
        resolver_config,
        resolver_input,
    ):
        if calls is not None:
            calls.append(
                (
                    resolver_config,
                    resolver_input,
                )
            )
        return resolution(payload)

    monkeypatch.setattr(
        module,
        "verify_dataset_v1_with_intent",
        fake_verify,
    )
    monkeypatch.setattr(
        module,
        "resolve_authorized_hcs_observations_v1",
        fake_resolve,
    )


def test_parses_current_registry_version_event() -> None:
    parsed = (
        parse_dataset_registry_version_created_v1(
            registry_payload(),
            "testnet",
        )
    )

    assert parsed.status == "resolved"
    assert parsed.event is not None
    assert parsed.event.dataset_key == DATASET_KEY
    assert (
        parsed.event.dataset_fingerprint
        == FINGERPRINT
    )
    assert parsed.event.version == 3

    rendered = repr(parsed.event)
    assert "actor_user_id" not in rendered
    assert "service_event_hash" not in rendered
    assert "bytes_estimate" not in rendered


def test_other_registry_event_is_unsupported() -> None:
    parsed = (
        parse_dataset_registry_version_created_v1(
            registry_payload(
                event="dataset.upserted"
            ),
            "testnet",
        )
    )

    assert parsed.status == "unsupported"
    assert (
        parsed.reason_code
        == "AUTHORIZED_DATASET_EVENT_UNSUPPORTED"
    )


def test_registry_network_mismatch_is_conflict() -> None:
    parsed = (
        parse_dataset_registry_version_created_v1(
            registry_payload(),
            "mainnet",
        )
    )

    assert parsed.status == "conflict"
    assert (
        parsed.reason_code
        == "AUTHORIZED_DATASET_NETWORK_MISMATCH"
    )


def test_binds_local_dataset_to_authorized_registry_and_hedera(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[object] = []

    install_resolution(
        monkeypatch,
        registry_payload(),
        calls,
    )

    result = run(
        triangulate_authorized_dataset_v1(
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
            "dataset_key"
        ].outcome
        == "pass"
    )
    assert (
        findings[
            "triangulation.provided_authorized."
            "dataset_fingerprint"
        ].outcome
        == "pass"
    )
    assert (
        findings[
            "triangulation.authorized_dataset."
            "registry_event_profile"
        ].outcome
        == "pass"
    )

    rendered = repr(result.report)
    assert "actor_user_id" not in rendered
    assert "service_event_hash" not in rendered

    assert len(calls) == 1

    _, resolver_input = calls[0]

    assert (
        resolver_input.request.network
        == "testnet"
    )
    assert (
        resolver_input.request.include_decrypted
        is True
    )
    assert (
        resolver_input.request.message_id
        == "7@0.0.12345"
    )


def test_authenticated_fingerprint_conflict_is_reported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install_resolution(
        monkeypatch,
        registry_payload(
            fingerprint="f" * 128
        ),
    )

    result = run(
        triangulate_authorized_dataset_v1(
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
            "dataset_fingerprint"
        )
    )

    assert finding.outcome == "fail"
    assert finding.reason_code == "FACT_MISMATCH"


def test_malformed_claimed_registry_event_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = registry_payload()
    body = payload["payload"]

    assert isinstance(body, dict)
    body["dataset_fingerprint"] = "not-a-digest"

    install_resolution(
        monkeypatch,
        payload,
    )

    result = run(
        triangulate_authorized_dataset_v1(
            config(),
            input(),
        )
    )

    assert result.consistency == "conflict"
    assert (
        result.resolution.dataset_registry_event
        == "invalid"
    )

    finding = next(
        entry
        for entry in result.report.findings
        if entry.check_id
        == (
            "triangulation.authorized_dataset."
            "registry_event_profile"
        )
    )

    assert finding.outcome == "fail"
    assert (
        finding.reason_code
        == "AUTHORIZED_DATASET_EVENT_PAYLOAD_INVALID"
    )