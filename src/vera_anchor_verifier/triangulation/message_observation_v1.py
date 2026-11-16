"""Normalize exact-message and Core ciphertext-binding observations."""

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal, TypeGuard, cast

from ..contracts import (
    VerificationFact,
    VerificationObservation,
    VerificationSubject,
)
from ..crypto.sha3 import BytesLike, sha3_512_hex

MAX_MESSAGE_BYTES = 1024 * 1024

_TOPIC_ID_RE = re.compile(r"^0\.0\.[1-9][0-9]*$", re.ASCII)
_OBSERVATION_ID_RE = re.compile(
    r"^[a-z][a-z0-9._:-]{0,127}$",
    re.ASCII,
)
_DIGEST_RE = re.compile(
    r"^[0-9a-f]{128}$",
    re.IGNORECASE | re.ASCII,
)
_CORE_BINDING_SCHEMA = "vera.hcs-message-binding.v1"
_MAX_SAFE_INTEGER = (1 << 53) - 1

type CoreObservationSource = Literal[
    "public_record",
    "authorized_service",
]


@dataclass(frozen=True, slots=True)
class MirrorMessageV1Input:
    id: str
    subject: VerificationSubject
    topic_id: str
    sequence_number: int | float
    message_bytes: BytesLike


@dataclass(frozen=True, slots=True)
class CoreMessageBindingV1Input:
    id: str
    subject: VerificationSubject
    binding: object


def _safe_positive_integer(
    value: object,
) -> TypeGuard[int | float]:
    if isinstance(value, bool):
        return False

    if isinstance(value, int):
        return 1 <= value <= _MAX_SAFE_INTEGER

    return (
        isinstance(value, float)
        and value.is_integer()
        and 1 <= value <= _MAX_SAFE_INTEGER
    )


def _safe_nonnegative_integer(
    value: object,
) -> TypeGuard[int | float]:
    if isinstance(value, bool):
        return False

    if isinstance(value, int):
        return 0 <= value <= _MAX_SAFE_INTEGER

    return (
        isinstance(value, float)
        and value.is_integer()
        and 0 <= value <= _MAX_SAFE_INTEGER
    )


def _subject(
    value: object,
    *,
    require_network: bool,
) -> VerificationSubject:
    if not isinstance(value, Mapping):
        raise TypeError("Invalid observation subject")

    subject_id = value.get("id")

    if not isinstance(subject_id, str) or not subject_id:
        raise TypeError("Invalid observation subject")

    if (
        require_network
        and value.get("hedera_network")
        not in ("mainnet", "testnet")
    ):
        raise TypeError("Invalid observation subject")

    return cast(
        VerificationSubject,
        dict(value),
    )


def observe_mirror_message_v1(
    input: MirrorMessageV1Input,
) -> VerificationObservation:
    """Hash exact supplied HCS message bytes."""
    if (
        _OBSERVATION_ID_RE.fullmatch(input.id) is None
        or _TOPIC_ID_RE.fullmatch(input.topic_id) is None
        or not _safe_positive_integer(
            input.sequence_number
        )
        or not isinstance(
            input.message_bytes,
            (bytes, bytearray, memoryview),
        )
        or len(input.message_bytes) > MAX_MESSAGE_BYTES
    ):
        raise TypeError(
            "Invalid or oversized Mirror message observation"
        )

    subject = _subject(
        input.subject,
        require_network=True,
    )
    message_bytes = bytes(
        input.message_bytes
    )

    return VerificationObservation(
        id=input.id,
        source="hedera_mirror",
        subject=subject,
        facts=(
            VerificationFact(
                key="hedera.topic_id",
                state="available",
                value=input.topic_id,
            ),
            VerificationFact(
                key="hedera.sequence_number",
                state="available",
                value=input.sequence_number,
            ),
            VerificationFact(
                key="publication.message_sha3_512",
                state="available",
                value=sha3_512_hex(
                    message_bytes
                ),
            ),
            VerificationFact(
                key="publication.message_bytes",
                state="available",
                value=len(message_bytes),
            ),
        ),
    )


def _core_message_binding_observation(
    input: CoreMessageBindingV1Input,
    *,
    source: CoreObservationSource,
    resolver_id: str | None = None,
) -> VerificationObservation:
    if (
        _OBSERVATION_ID_RE.fullmatch(input.id)
        is None
    ):
        raise TypeError(
            "Invalid Core message-binding observation"
        )

    subject = _subject(
        input.subject,
        require_network=False,
    )

    binding = (
        input.binding
        if isinstance(input.binding, Mapping)
        else None
    )
    missing = binding is None

    schema = (
        None
        if binding is None
        else binding.get("schema_version")
    )
    algorithm = (
        None
        if binding is None
        else binding.get("algorithm")
    )
    digest = (
        None
        if binding is None
        else binding.get("message_sha3_512")
    )
    length = (
        None
        if binding is None
        else binding.get("message_bytes")
    )

    digest_value = (
        digest.lower()
        if isinstance(digest, str)
        else None
    )
    length_value = (
        length
        if _safe_nonnegative_integer(length)
        else None
    )

    valid = (
        schema == _CORE_BINDING_SCHEMA
        and algorithm == "sha3-512"
        and digest_value is not None
        and _DIGEST_RE.fullmatch(
            digest_value
        )
        is not None
        and length_value is not None
    )

    reason = (
        "CORE_MESSAGE_BINDING_UNAVAILABLE"
        if missing
        else "CORE_MESSAGE_BINDING_INVALID"
    )

    if valid:
        facts = (
            VerificationFact(
                key="publication.message_sha3_512",
                state="available",
                value=digest_value,
            ),
            VerificationFact(
                key="publication.message_bytes",
                state="available",
                value=length_value,
            ),
        )
    else:
        facts = (
            VerificationFact(
                key="publication.message_sha3_512",
                state="unavailable",
                reason_code=reason,
            ),
            VerificationFact(
                key="publication.message_bytes",
                state="unavailable",
                reason_code=reason,
            ),
        )

    return VerificationObservation(
        id=input.id,
        source=source,
        subject=subject,
        resolver_id=resolver_id,
        facts=facts,
    )


def observe_core_message_binding_v1(
    input: CoreMessageBindingV1Input,
) -> VerificationObservation:
    """Normalize a public Core ciphertext-binding claim."""
    return _core_message_binding_observation(
        input,
        source="public_record",
    )


def observe_authorized_core_message_binding_v1(
    input: CoreMessageBindingV1Input,
) -> VerificationObservation:
    """Normalize an authenticated Core ciphertext-binding claim."""
    return _core_message_binding_observation(
        input,
        source="authorized_service",
        resolver_id="core.authorized-hcs.v1",
    )