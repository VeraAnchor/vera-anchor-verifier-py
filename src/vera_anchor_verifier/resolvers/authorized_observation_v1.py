"""Authorized Core and independent Hedera observation acquisition."""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal

from ..contracts import (
    HederaNetwork,
    VerificationFact,
    VerificationObservation,
    VerificationSubject,
)
from ..triangulation.message_observation_v1 import (
    CoreMessageBindingV1Input,
    observe_authorized_core_message_binding_v1,
)
from .core_authorized_v1 import (
    AuthorizedHcsEvidenceV1,
    AuthorizedHcsEvidenceV1Request,
    AuthorizedHcsEvidenceV1Result,
    CoreAuthorizedV1Config,
    resolve_authorized_hcs_evidence_v1,
)
from .hedera_mirror_v1 import (
    HederaMessageLocatorV1,
    HederaMessageObservationV1,
    HederaMirrorV1Config,
    resolve_hedera_message_v1,
)

_ECMASCRIPT_TRIM = (
    "\u0009\u000b\u000c\u0020\u00a0\u1680"
    "\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a"
    "\u2028\u2029\u202f\u205f\u3000\ufeff\u000a\u000d"
)

type AuthorizedMirrorResolutionV1 = Literal[
    "resolved",
    "unavailable",
    "invalid",
    "conflict",
    "not_requested",
    "not_resolved",
    "locator_unavailable",
]


@dataclass(frozen=True, slots=True)
class AuthorizedHcsObservationsV1Config:
    core: CoreAuthorizedV1Config
    mirror: HederaMirrorV1Config | Literal[False] | None = None


@dataclass(frozen=True, slots=True)
class AuthorizedHcsObservationsV1Input:
    subject: VerificationSubject
    request: AuthorizedHcsEvidenceV1Request


@dataclass(frozen=True, slots=True)
class AuthorizedHcsObservationsV1Result:
    core: AuthorizedHcsEvidenceV1Result
    authorized_observation: VerificationObservation | None
    mirror: HederaMessageObservationV1 | None
    mirror_resolution: AuthorizedMirrorResolutionV1


@dataclass(frozen=True, slots=True)
class _PreparedAuthorizedHcsObservationV1:
    observation: VerificationObservation
    mirror_locator: HederaMessageLocatorV1 | None


def _js_length(value: str) -> int:
    return len(value.encode("utf-16-le", "surrogatepass")) // 2


def _trim(value: str) -> str:
    return value.strip(_ECMASCRIPT_TRIM)


def _available(key: str, value: str | int) -> VerificationFact:
    return VerificationFact(key=key, state="available", value=value)


def _unavailable(key: str, reason: str) -> VerificationFact:
    return VerificationFact(key=key, state="unavailable", reason_code=reason)


def _optional_fact(
    key: str,
    value: str | int | None,
    reason: str,
) -> VerificationFact:
    if value is None:
        return _unavailable(key, reason)
    return _available(key, value)


def _checked_subject(
    subject: VerificationSubject,
    network: HederaNetwork,
) -> VerificationSubject:
    if not isinstance(subject, Mapping):
        raise TypeError(
            "Authorized HCS observation requires an exact network-bound subject"
        )

    subject_id = subject.get("id")
    if (
        not isinstance(subject_id, str)
        or not subject_id
        or _js_length(subject_id) > 512
        or _trim(subject_id) != subject_id
        or subject.get("hedera_network") != network
    ):
        raise TypeError(
            "Authorized HCS observation requires an exact network-bound subject"
        )

    return subject


def _prepare_authorized_hcs_observation_v1(
    evidence: AuthorizedHcsEvidenceV1,
    subject: VerificationSubject,
) -> _PreparedAuthorizedHcsObservationV1:
    if evidence.hedera_network not in ("mainnet", "testnet"):
        raise TypeError("Invalid authorized HCS evidence")

    scoped_subject = _checked_subject(subject, evidence.hedera_network)
    binding = observe_authorized_core_message_binding_v1(
        CoreMessageBindingV1Input(
            id=f"{scoped_subject['kind']}.authorized_core",
            subject=scoped_subject,
            binding={
                "schema_version": evidence.message_binding.schema_version,
                "algorithm": evidence.message_binding.algorithm,
                "message_sha3_512": evidence.message_binding.message_sha3_512,
                "message_bytes": evidence.message_binding.message_bytes,
            },
        )
    )

    facts = (
        *binding.facts,
        _optional_fact(
            "publication.topic_id",
            evidence.topic.topic_id,
            "CORE_AUTHORIZED_TOPIC_UNAVAILABLE",
        ),
        _optional_fact(
            "publication.sequence_number",
            evidence.tx.sequence_number,
            "CORE_AUTHORIZED_SEQUENCE_UNAVAILABLE",
        ),
        _optional_fact(
            "core.hash.expected",
            evidence.core_hash_observation.expected,
            "CORE_HASH_EXPECTED_UNAVAILABLE",
        ),
        _optional_fact(
            "core.hash.computed",
            evidence.core_hash_observation.computed,
            "CORE_HASH_COMPUTED_UNAVAILABLE",
        ),
        _available("acquisition.access_context", evidence.acquisition.access_context),
        _available(
            "acquisition.decryption_method",
            evidence.acquisition.decryption_method,
        ),
        _available(
            "acquisition.recoverability",
            evidence.acquisition.recoverability,
        ),
    )
    observation = VerificationObservation(
        id=binding.id,
        subject=binding.subject,
        source=binding.source,
        resolver_id=binding.resolver_id,
        facts=facts,
    )

    mirror_locator: HederaMessageLocatorV1 | None
    if evidence.topic.topic_id is not None and evidence.tx.sequence_number is not None:
        mirror_locator = HederaMessageLocatorV1(
            hedera_network=evidence.hedera_network,
            topic_id=evidence.topic.topic_id,
            sequence_number=evidence.tx.sequence_number,
            transaction_id=evidence.tx.transaction_id,
        )
    else:
        mirror_locator = None

    return _PreparedAuthorizedHcsObservationV1(
        observation=observation,
        mirror_locator=mirror_locator,
    )


async def resolve_authorized_hcs_observations_v1(
    config: AuthorizedHcsObservationsV1Config,
    input: AuthorizedHcsObservationsV1Input,
) -> AuthorizedHcsObservationsV1Result:
    """
    Acquire authorized Core and optional independent Mirror observations.

    This function does not declare the sources consistent or policy-acceptable.
    """
    _checked_subject(input.subject, input.request.network)
    core = await resolve_authorized_hcs_evidence_v1(config.core, input.request)

    if core.status != "resolved" or core.evidence is None:
        return AuthorizedHcsObservationsV1Result(
            core=core,
            authorized_observation=None,
            mirror=None,
            mirror_resolution=(
                "not_requested" if config.mirror is False else "not_resolved"
            ),
        )

    prepared = _prepare_authorized_hcs_observation_v1(
        core.evidence,
        input.subject,
    )

    if config.mirror is False:
        return AuthorizedHcsObservationsV1Result(
            core=core,
            authorized_observation=prepared.observation,
            mirror=None,
            mirror_resolution="not_requested",
        )

    if prepared.mirror_locator is None:
        return AuthorizedHcsObservationsV1Result(
            core=core,
            authorized_observation=prepared.observation,
            mirror=None,
            mirror_resolution="locator_unavailable",
        )

    mirror_config = HederaMirrorV1Config() if config.mirror is None else config.mirror
    mirror = await resolve_hedera_message_v1(
        mirror_config,
        prepared.mirror_locator,
        input.subject,
    )

    return AuthorizedHcsObservationsV1Result(
        core=core,
        authorized_observation=prepared.observation,
        mirror=mirror,
        mirror_resolution=mirror.status,
    )