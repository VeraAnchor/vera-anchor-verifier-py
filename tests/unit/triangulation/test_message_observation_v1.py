from dataclasses import FrozenInstanceError

import pytest

from vera_anchor_verifier import sha3_512_hex
from vera_anchor_verifier.triangulation.message_observation_v1 import (
    MAX_MESSAGE_BYTES,
    CoreMessageBindingV1Input,
    MirrorMessageV1Input,
    observe_authorized_core_message_binding_v1,
    observe_core_message_binding_v1,
    observe_mirror_message_v1,
)

SUBJECT = {
    "kind": "dataset",
    "id": "dataset.alpha",
    "hedera_network": "testnet",
}
ABC_SHA3_512 = sha3_512_hex(b"abc")


def facts(observation):
    return {fact.key: fact for fact in observation.facts}


def test_mirror_observation_hashes_exact_message_bytes() -> None:
    result = observe_mirror_message_v1(
        MirrorMessageV1Input(
            id="mirror.message",
            subject=SUBJECT,
            topic_id="0.0.123",
            sequence_number=7,
            message_bytes=b"abc",
        )
    )
    indexed = facts(result)

    assert result.source == "hedera_mirror"
    assert result.subject == SUBJECT
    assert indexed["hedera.topic_id"].value == "0.0.123"
    assert indexed["hedera.sequence_number"].value == 7
    assert (
        indexed["publication.message_sha3_512"].value
        == ABC_SHA3_512
    )
    assert indexed["publication.message_bytes"].value == 3


def test_mirror_accepts_exact_byte_like_inputs() -> None:
    for value in (
        bytearray(b"abc"),
        memoryview(b"abc"),
    ):
        result = observe_mirror_message_v1(
            MirrorMessageV1Input(
                id="mirror.message",
                subject=SUBJECT,
                topic_id="0.0.123",
                sequence_number=1,
                message_bytes=value,
            )
        )

        assert (
            facts(result)["publication.message_sha3_512"].value
            == ABC_SHA3_512
        )


@pytest.mark.parametrize(
    ("topic_id", "sequence_number"),
    [
        ("0.0.0", 1),
        ("0.0.01", 1),
        ("1.2.3", 1),
        ("0.0.123", 0),
        ("0.0.123", -1),
        ("0.0.123", True),
        ("0.0.123", 1 << 53),
    ],
)
def test_mirror_locator_validation_fails_closed(
    topic_id: str,
    sequence_number: object,
) -> None:
    with pytest.raises(
        TypeError,
        match="Invalid or oversized Mirror message observation",
    ):
        observe_mirror_message_v1(
            MirrorMessageV1Input(
                id="mirror.message",
                subject=SUBJECT,
                topic_id=topic_id,
                sequence_number=sequence_number,  # type: ignore[arg-type]
                message_bytes=b"abc",
            )
        )


def test_mirror_requires_explicit_network_scope() -> None:
    with pytest.raises(TypeError, match="Invalid observation subject"):
        observe_mirror_message_v1(
            MirrorMessageV1Input(
                id="mirror.message",
                subject={
                    "kind": "dataset",
                    "id": "dataset.alpha",
                },
                topic_id="0.0.123",
                sequence_number=1,
                message_bytes=b"abc",
            )
        )


def test_mirror_enforces_message_size_limit() -> None:
    with pytest.raises(
        TypeError,
        match="Invalid or oversized Mirror message observation",
    ):
        observe_mirror_message_v1(
            MirrorMessageV1Input(
                id="mirror.message",
                subject=SUBJECT,
                topic_id="0.0.123",
                sequence_number=1,
                message_bytes=b"x" * (MAX_MESSAGE_BYTES + 1),
            )
        )


def test_valid_core_binding_is_normalized() -> None:
    result = observe_core_message_binding_v1(
        CoreMessageBindingV1Input(
            id="core.binding",
            subject=SUBJECT,
            binding={
                "schema_version": "vera.hcs-message-binding.v1",
                "algorithm": "sha3-512",
                "message_sha3_512": ABC_SHA3_512.upper(),
                "message_bytes": 3,
            },
        )
    )
    indexed = facts(result)

    assert result.source == "public_record"
    assert result.resolver_id is None
    assert (
        indexed["publication.message_sha3_512"].state
        == "available"
    )
    assert (
        indexed["publication.message_sha3_512"].value
        == ABC_SHA3_512
    )
    assert indexed["publication.message_bytes"].value == 3


def test_missing_core_binding_is_unavailable() -> None:
    result = observe_core_message_binding_v1(
        CoreMessageBindingV1Input(
            id="core.binding",
            subject=SUBJECT,
            binding=None,
        )
    )
    indexed = facts(result)

    for key in (
        "publication.message_sha3_512",
        "publication.message_bytes",
    ):
        assert indexed[key].state == "unavailable"
        assert (
            indexed[key].reason_code
            == "CORE_MESSAGE_BINDING_UNAVAILABLE"
        )


@pytest.mark.parametrize(
    "binding",
    [
        {},
        {
            "schema_version": "wrong",
            "algorithm": "sha3-512",
            "message_sha3_512": ABC_SHA3_512,
            "message_bytes": 3,
        },
        {
            "schema_version": "vera.hcs-message-binding.v1",
            "algorithm": "sha256",
            "message_sha3_512": ABC_SHA3_512,
            "message_bytes": 3,
        },
        {
            "schema_version": "vera.hcs-message-binding.v1",
            "algorithm": "sha3-512",
            "message_sha3_512": "0" * 127,
            "message_bytes": 3,
        },
        {
            "schema_version": "vera.hcs-message-binding.v1",
            "algorithm": "sha3-512",
            "message_sha3_512": ABC_SHA3_512,
            "message_bytes": -1,
        },
        {
            "schema_version": "vera.hcs-message-binding.v1",
            "algorithm": "sha3-512",
            "message_sha3_512": ABC_SHA3_512,
            "message_bytes": True,
        },
    ],
)
def test_invalid_core_binding_is_distinct_from_missing(
    binding: object,
) -> None:
    result = observe_core_message_binding_v1(
        CoreMessageBindingV1Input(
            id="core.binding",
            subject=SUBJECT,
            binding=binding,
        )
    )

    for value in result.facts:
        assert value.state == "unavailable"
        assert value.reason_code == "CORE_MESSAGE_BINDING_INVALID"


def test_authorized_binding_has_explicit_provenance() -> None:
    result = observe_authorized_core_message_binding_v1(
        CoreMessageBindingV1Input(
            id="core.authorized",
            subject=SUBJECT,
            binding={
                "schema_version": "vera.hcs-message-binding.v1",
                "algorithm": "sha3-512",
                "message_sha3_512": ABC_SHA3_512,
                "message_bytes": 3,
            },
        )
    )

    assert result.source == "authorized_service"
    assert result.resolver_id == "core.authorized-hcs.v1"


def test_observations_are_immutable() -> None:
    result = observe_mirror_message_v1(
        MirrorMessageV1Input(
            id="mirror.message",
            subject=SUBJECT,
            topic_id="0.0.123",
            sequence_number=1,
            message_bytes=b"abc",
        )
    )

    with pytest.raises(FrozenInstanceError):
        result.id = "changed"  # type: ignore[misc]