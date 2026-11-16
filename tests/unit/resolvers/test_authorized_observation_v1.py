import asyncio
import base64
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

import pytest

from vera_anchor_verifier import sha3_512_hex
from vera_anchor_verifier.auth import (
    create_static_bearer_auth_provider_v1,
)
from vera_anchor_verifier.contracts import (
    VerificationSubject,
)
from vera_anchor_verifier.resolvers import (
    AuthorizedHcsEvidenceV1Request,
    AuthorizedHcsObservationsV1Config,
    AuthorizedHcsObservationsV1Input,
    CoreAuthorizedV1Config,
    HederaMirrorV1Config,
    resolve_authorized_hcs_observations_v1,
)
from vera_anchor_verifier.resolvers.core_authorized_v1 import (
    CoreAuthorizedFetchResponseV1,
)
from vera_anchor_verifier.resolvers.hedera_mirror_v1 import (
    HederaMirrorFetchResponseV1,
)

CORE = "https://core.example.test"
MIRROR = "https://mirror.example.test/api/v1"
TOPIC = "0.0.12345"
SEQUENCE = 5
MESSAGE = b"authorized-encrypted-message"
DIGEST = sha3_512_hex(MESSAGE)

SUBJECT: VerificationSubject = {
    "kind": "dataset",
    "id": "research.dataset",
    "hedera_network": "testnet",
}


def run[T](coro) -> T:
    return asyncio.run(coro)


def core_body() -> dict[str, object]:
    return {
        "ok": True,
        "hedera_network": "testnet",
        "mode": "decrypt_only",
        "verified": None,
        "topic": {
            "name": "dataset_private",
            "topic_id": TOPIC,
            "key_version": 3,
        },
        "encryption": {
            "topic_key_version": 3,
            "user_key_version": 2,
        },
        "tx": {
            "id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "message_id": f"{SEQUENCE}@{TOPIC}",
            "transaction_id": None,
            "sequence_number": SEQUENCE,
            "consensus_timestamp": "1234567890.123456789",
            "status": "confirmed",
            "mirror_verified": False,
            "mirror_verified_at": None,
        },
        "hash": {
            "expected": "a" * 128,
            "computed": "a" * 128,
            "match": None,
        },
        "message_binding": {
            "schema_version": "vera.hcs-message-binding.v1",
            "algorithm": "sha3-512",
            "message_sha3_512": DIGEST,
            "message_bytes": len(MESSAGE),
        },
        "payload": {
            "secret": "not-a-report-fact",
        },
    }


@dataclass
class FakeCoreFetch:
    calls: list[dict[str, Any]] = field(
        default_factory=list
    )

    async def __call__(
        self,
        url: str,
        headers: Mapping[str, str],
        body: bytes,
        timeout_ms: int,
        max_response_bytes: int,
    ) -> CoreAuthorizedFetchResponseV1:
        self.calls.append(
            {
                "url": url,
                "headers": dict(headers),
                "body": body,
                "timeout_ms": timeout_ms,
                "max_response_bytes": max_response_bytes,
            }
        )

        encoded = json.dumps(
            core_body(),
            separators=(",", ":"),
        ).encode()

        return CoreAuthorizedFetchResponseV1(
            status=200,
            headers={
                "Content-Type": "application/json",
                "Content-Length": str(len(encoded)),
            },
            body=encoded,
        )


@dataclass
class FakeMirrorFetch:
    calls: list[str] = field(
        default_factory=list
    )

    async def __call__(
        self,
        url: str,
        headers: Mapping[str, str],
        timeout_ms: int,
        max_response_bytes: int,
    ) -> HederaMirrorFetchResponseV1:
        del headers, timeout_ms, max_response_bytes

        self.calls.append(url)

        encoded = json.dumps(
            {
                "topic_id": TOPIC,
                "sequence_number": SEQUENCE,
                "consensus_timestamp": (
                    "1234567890.123456789"
                ),
                "message": base64.b64encode(
                    MESSAGE
                ).decode("ascii"),
            },
            separators=(",", ":"),
        ).encode()

        return HederaMirrorFetchResponseV1(
            status=200,
            headers={
                "Content-Type": "application/json",
                "Content-Length": str(len(encoded)),
            },
            body=encoded,
        )


def core_config(
    fetch: FakeCoreFetch,
) -> CoreAuthorizedV1Config:
    return CoreAuthorizedV1Config(
        base_url=CORE,
        auth_provider=(
            create_static_bearer_auth_provider_v1(
                "test-api-key"
            )
        ),
        fetch_impl=fetch,
    )


def request() -> AuthorizedHcsEvidenceV1Request:
    return AuthorizedHcsEvidenceV1Request(
        network="testnet",
        message_id=f"{SEQUENCE}@{TOPIC}",
        include_decrypted=True,
    )


def facts(
    observation,
) -> dict[str, object]:
    assert observation is not None

    return {
        fact.key: fact
        for fact in observation.facts
    }


def test_marks_core_as_authorized_service_without_plaintext_facts() -> None:
    core_fetch = FakeCoreFetch()

    result = run(
        resolve_authorized_hcs_observations_v1(
            AuthorizedHcsObservationsV1Config(
                core=core_config(core_fetch),
                mirror=False,
            ),
            AuthorizedHcsObservationsV1Input(
                subject=SUBJECT,
                request=request(),
            ),
        )
    )

    assert result.core.status == "resolved"
    assert result.authorized_observation is not None

    observation = result.authorized_observation

    assert observation.source == "authorized_service"
    assert (
        observation.resolver_id
        == "core.authorized-hcs.v1"
    )

    indexed = facts(observation)

    assert (
        indexed[
            "publication.message_sha3_512"
        ].value
        == DIGEST
    )
    assert (
        indexed[
            "publication.sequence_number"
        ].value
        == SEQUENCE
    )
    assert (
        indexed[
            "acquisition.access_context"
        ].value
        == "authorized"
    )

    serialized = json.dumps(
        [
            {
                "key": fact.key,
                "state": fact.state,
                "value": fact.value,
                "reason_code": fact.reason_code,
            }
            for fact in observation.facts
        ],
        default=str,
    )

    assert "not-a-report-fact" not in serialized
    assert result.mirror is None
    assert result.mirror_resolution == "not_requested"


def test_subject_network_substitution_fails_before_core_request() -> None:
    core_fetch = FakeCoreFetch()

    mismatched: VerificationSubject = {
        "kind": "dataset",
        "id": "research.dataset",
        "hedera_network": "mainnet",
    }

    with pytest.raises(
        TypeError,
        match="exact network-bound subject",
    ):
        run(
            resolve_authorized_hcs_observations_v1(
                AuthorizedHcsObservationsV1Config(
                    core=core_config(core_fetch),
                ),
                AuthorizedHcsObservationsV1Input(
                    subject=mismatched,
                    request=request(),
                ),
            )
        )

    assert core_fetch.calls == []


def test_core_and_mirror_are_separate_observations() -> None:
    core_fetch = FakeCoreFetch()
    mirror_fetch = FakeMirrorFetch()

    result = run(
        resolve_authorized_hcs_observations_v1(
            AuthorizedHcsObservationsV1Config(
                core=core_config(core_fetch),
                mirror=HederaMirrorV1Config(
                    base_urls={
                        "testnet": MIRROR,
                    },
                    fetch_impl=mirror_fetch,
                ),
            ),
            AuthorizedHcsObservationsV1Input(
                subject=SUBJECT,
                request=request(),
            ),
        )
    )

    assert result.core.status == "resolved"

    assert result.authorized_observation is not None
    assert (
        result.authorized_observation.source
        == "authorized_service"
    )

    assert result.mirror_resolution == "resolved"
    assert result.mirror is not None
    assert result.mirror.status == "resolved"
    assert result.mirror.observation is not None
    assert (
        result.mirror.observation.source
        == "hedera_mirror"
    )

    mirror_facts = facts(
        result.mirror.observation
    )

    assert (
        mirror_facts[
            "publication.message_sha3_512"
        ].value
        == DIGEST
    )

    assert len(core_fetch.calls) == 1
    assert len(mirror_fetch.calls) == 1


def test_mirror_can_be_explicitly_disabled() -> None:
    core_fetch = FakeCoreFetch()

    result = run(
        resolve_authorized_hcs_observations_v1(
            AuthorizedHcsObservationsV1Config(
                core=core_config(core_fetch),
                mirror=False,
            ),
            AuthorizedHcsObservationsV1Input(
                subject=SUBJECT,
                request=request(),
            ),
        )
    )

    assert result.core.status == "resolved"
    assert result.authorized_observation is not None
    assert result.mirror is None
    assert result.mirror_resolution == "not_requested"
    assert len(core_fetch.calls) == 1


def test_failed_core_resolution_does_not_fall_through_to_mirror() -> None:
    class UnauthorizedCoreFetch(FakeCoreFetch):
        async def __call__(
            self,
            url: str,
            headers: Mapping[str, str],
            body: bytes,
            timeout_ms: int,
            max_response_bytes: int,
        ) -> CoreAuthorizedFetchResponseV1:
            self.calls.append(
                {
                    "url": url,
                    "headers": dict(headers),
                    "body": body,
                    "timeout_ms": timeout_ms,
                    "max_response_bytes": max_response_bytes,
                }
            )

            return CoreAuthorizedFetchResponseV1(
                status=403,
                headers={},
                body=b"",
            )

    core_fetch = UnauthorizedCoreFetch()
    mirror_fetch = FakeMirrorFetch()

    result = run(
        resolve_authorized_hcs_observations_v1(
            AuthorizedHcsObservationsV1Config(
                core=core_config(core_fetch),
                mirror=HederaMirrorV1Config(
                    base_urls={
                        "testnet": MIRROR,
                    },
                    fetch_impl=mirror_fetch,
                ),
            ),
            AuthorizedHcsObservationsV1Input(
                subject=SUBJECT,
                request=request(),
            ),
        )
    )

    assert result.core.status == "forbidden"
    assert result.authorized_observation is None
    assert result.mirror is None
    assert result.mirror_resolution == "not_resolved"
    assert len(core_fetch.calls) == 1
    assert mirror_fetch.calls == []