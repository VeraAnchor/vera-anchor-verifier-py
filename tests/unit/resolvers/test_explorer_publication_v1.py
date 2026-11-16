import asyncio
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

import pytest

from vera_anchor_verifier.resolvers import (
    ExplorerDatasetV1Request,
    ExplorerPublicTransportV1,
    resolve_explorer_dataset_publication_v1,
)
from vera_anchor_verifier.resolvers.explorer_transport_v1 import (
    ExplorerFetchResponseV1,
)

DIGEST = "a" * 128
OTHER_DIGEST = "b" * 128
SCHEMA = "va:explorer_publication_receipt:v1"


def run[T](coro) -> T:
    return asyncio.run(coro)


@dataclass
class FakeExplorerFetch:
    dataset_body: object
    disclosure_body: object | None = None
    disclosure_status: int = 200
    calls: list[dict[str, Any]] = field(default_factory=list)

    async def __call__(
        self,
        url: str,
        method: str,
        headers: Mapping[str, str],
        body: bytes | None,
        timeout_ms: int,
        max_response_bytes: int,
    ) -> ExplorerFetchResponseV1:
        del timeout_ms, max_response_bytes

        parsed = urlsplit(url)

        self.calls.append(
            {
                "path": parsed.path,
                "query": parsed.query,
                "method": method,
                "headers": dict(headers),
                "body": body,
            }
        )

        if method == "GET":
            payload = self.dataset_body
            status = 200
        else:
            payload = self.disclosure_body
            status = self.disclosure_status

        return ExplorerFetchResponseV1(
            status=status,
            headers={},
            body=json.dumps(
                payload,
                separators=(",", ":"),
            ).encode(),
        )


def config(
    fetch: FakeExplorerFetch,
) -> ExplorerPublicTransportV1:
    return ExplorerPublicTransportV1(
        base_url="https://explorer.example",
        fetch_impl=fetch,
    )


def dataset_record() -> dict[str, object]:
    return {
        "hedera_network": "testnet",
        "dataset_key": "dataset.alpha",
        "dataset_fingerprint": DIGEST,
        "dataset_version_id": "version-1",
        "publication_version_topic_id": "0.0.123",
        "publication_version_sequence_number": 7,
    }


def receipt(
    *,
    proof: object | None = None,
) -> dict[str, object]:
    value: dict[str, object] = {
        "schema": SCHEMA,
        "event_type": "published",
        "entity_kind": "dataset_version",
        "entity_id": "version-1",
        "visibility": "public",
        "event_version": 1,
    }

    if proof is not None:
        value["proof"] = proof

    return value


def disclosure_response(
    *,
    payload: object | None = None,
    verified: object = True,
    hash_match: object = True,
    message_binding: object | None = None,
) -> dict[str, object]:
    return {
        "hedera_network": "testnet",
        "tx": {
            "message_id": "7@0.0.123",
        },
        "topic": {
            "topic_id": "0.0.123",
        },
        "hash": {
            "match": hash_match,
        },
        "verified": verified,
        "payload": (
            receipt(
                proof={
                    "dataset_key": "dataset.alpha",
                    "fingerprint": DIGEST,
                }
            )
            if payload is None
            else payload
        ),
        "message_binding": (
            {
                "schema_version": "vera.hcs-message-binding.v1",
                "algorithm": "sha3-512",
                "message_sha3_512": OTHER_DIGEST,
                "message_bytes": 123,
            }
            if message_binding is None
            else message_binding
        ),
    }


def facts(observation) -> dict[str, Any]:
    assert observation is not None
    return {
        fact.key: fact
        for fact in observation.facts
    }


def resolve(
    fetch: FakeExplorerFetch,
):
    return run(
        resolve_explorer_dataset_publication_v1(
            config(fetch),
            ExplorerDatasetV1Request(
                dataset_key="dataset.alpha",
                network="testnet",
            ),
        )
    )


def test_resolves_public_record_and_scoped_disclosure() -> None:
    fetch = FakeExplorerFetch(
        dataset_body=dataset_record(),
        disclosure_body=disclosure_response(),
    )

    result = resolve(fetch)

    assert result.public_record.status == "resolved"
    assert result.disclosure.status == "resolved"
    assert result.disclosure.reason_code is None

    receipt_observation = result.disclosure.receipt_observation
    binding_observation = (
        result.disclosure.message_binding_observation
    )

    assert receipt_observation is not None
    assert (
        receipt_observation.resolver_id
        == "explorer.public-disclosure.v1"
    )

    indexed = facts(receipt_observation)

    assert (
        indexed["publication.proof.dataset_key"].value
        == "dataset.alpha"
    )
    assert (
        indexed["publication.proof.fingerprint"].value
        == DIGEST
    )

    binding = facts(binding_observation)

    assert (
        binding["publication.message_sha3_512"].value
        == OTHER_DIGEST
    )
    assert binding["publication.message_bytes"].value == 123


def test_disclosure_request_uses_only_resolved_locator() -> None:
    fetch = FakeExplorerFetch(
        dataset_body=dataset_record(),
        disclosure_body=disclosure_response(),
    )

    resolve(fetch)

    assert len(fetch.calls) == 2

    call = fetch.calls[1]

    assert call["method"] == "POST"
    assert call["path"] == "/v1/hcs/verify-decrypt"
    assert call["query"] == ""

    assert call["body"] is not None

    body = json.loads(call["body"])

    assert body == {
        "hedera_network": "testnet",
        "mode": "decrypt_and_verify",
        "include_decrypted": True,
        "message_id": "7@0.0.123",
    }


def test_unresolved_public_record_prevents_disclosure_request() -> None:
    fetch = FakeExplorerFetch(
        dataset_body={
            "hedera_network": "testnet",
            "dataset_key": "dataset.other",
        },
    )

    result = resolve(fetch)

    assert result.public_record.status == "conflict"
    assert (
        result.disclosure.status,
        result.disclosure.reason_code,
    ) == (
        "unavailable",
        "PUBLICATION_ANCHOR_UNAVAILABLE",
    )
    assert len(fetch.calls) == 1


def test_response_network_mismatch_is_conflict() -> None:
    response = disclosure_response()
    response["hedera_network"] = "mainnet"

    result = resolve(
        FakeExplorerFetch(
            dataset_body=dataset_record(),
            disclosure_body=response,
        )
    )

    assert (
        result.disclosure.status,
        result.disclosure.reason_code,
    ) == (
        "conflict",
        "PUBLICATION_NETWORK_MISMATCH",
    )


def test_message_reference_mismatch_is_conflict() -> None:
    response = disclosure_response()
    response["tx"] = {
        "message_id": "8@0.0.123",
    }

    result = resolve(
        FakeExplorerFetch(
            dataset_body=dataset_record(),
            disclosure_body=response,
        )
    )

    assert (
        result.disclosure.status,
        result.disclosure.reason_code,
    ) == (
        "conflict",
        "PUBLICATION_MESSAGE_MISMATCH",
    )


def test_missing_message_reference_is_unavailable() -> None:
    response = disclosure_response()
    response["tx"] = {}

    result = resolve(
        FakeExplorerFetch(
            dataset_body=dataset_record(),
            disclosure_body=response,
        )
    )

    assert (
        result.disclosure.status,
        result.disclosure.reason_code,
    ) == (
        "unavailable",
        "PUBLICATION_MESSAGE_REFERENCE_UNAVAILABLE",
    )


def test_topic_mismatch_is_conflict() -> None:
    response = disclosure_response()
    response["topic"] = {
        "topic_id": "0.0.456",
    }

    result = resolve(
        FakeExplorerFetch(
            dataset_body=dataset_record(),
            disclosure_body=response,
        )
    )

    assert (
        result.disclosure.status,
        result.disclosure.reason_code,
    ) == (
        "conflict",
        "PUBLICATION_TOPIC_MISMATCH",
    )


@pytest.mark.parametrize(
    ("verified", "hash_match", "reason"),
    [
        (
            False,
            True,
            "PUBLICATION_PROVIDER_VERIFICATION_FAILED",
        ),
        (
            True,
            False,
            "PUBLICATION_PROVIDER_VERIFICATION_FAILED",
        ),
        (
            None,
            True,
            "PUBLICATION_PROVIDER_VERIFICATION_UNAVAILABLE",
        ),
        (
            True,
            None,
            "PUBLICATION_PROVIDER_VERIFICATION_UNAVAILABLE",
        ),
    ],
)
def test_provider_verification_is_not_upgraded_to_proof(
    verified: object,
    hash_match: object,
    reason: str,
) -> None:
    result = resolve(
        FakeExplorerFetch(
            dataset_body=dataset_record(),
            disclosure_body=disclosure_response(
                verified=verified,
                hash_match=hash_match,
            ),
        )
    )

    assert result.disclosure.status == "unavailable"
    assert result.disclosure.reason_code == reason


def test_unsupported_receipt_schema_is_distinct() -> None:
    payload = receipt()
    payload["schema"] = "future.schema.v2"

    result = resolve(
        FakeExplorerFetch(
            dataset_body=dataset_record(),
            disclosure_body=disclosure_response(
                payload=payload,
            ),
        )
    )

    assert (
        result.disclosure.status,
        result.disclosure.reason_code,
    ) == (
        "unsupported",
        "PUBLICATION_RECEIPT_UNSUPPORTED_SCHEMA",
    )


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {
            "schema": SCHEMA,
            "event_type": "published",
            "entity_kind": "dataset_version",
            "entity_id": "wrong-version",
            "visibility": "public",
            "event_version": 1,
        },
        {
            "schema": SCHEMA,
            "event_type": "published",
            "entity_kind": "dataset_version",
            "entity_id": "version-1",
            "visibility": "private",
            "event_version": 1,
        },
        {
            "schema": SCHEMA,
            "event_type": "published",
            "entity_kind": "dataset_version",
            "entity_id": "version-1",
            "visibility": "public",
            "event_version": 1,
            "proof": None,
        },
    ],
)
def test_invalid_receipt_envelope_fails_closed(
    payload: object,
) -> None:
    result = resolve(
        FakeExplorerFetch(
            dataset_body=dataset_record(),
            disclosure_body=disclosure_response(
                payload=payload,
            ),
        )
    )

    assert (
        result.disclosure.status,
        result.disclosure.reason_code,
    ) == (
        "invalid",
        "PUBLICATION_RECEIPT_INVALID",
    )


def test_invalid_proof_digest_fails_closed() -> None:
    result = resolve(
        FakeExplorerFetch(
            dataset_body=dataset_record(),
            disclosure_body=disclosure_response(
                payload=receipt(
                    proof={
                        "dataset_key": "dataset.alpha",
                        "fingerprint": "not-a-digest",
                    }
                ),
            ),
        )
    )

    assert (
        result.disclosure.status,
        result.disclosure.reason_code,
    ) == (
        "invalid",
        "PUBLICATION_RECEIPT_INVALID",
    )


def test_optional_numeric_commitments_require_safe_numbers() -> None:
    result = resolve(
        FakeExplorerFetch(
            dataset_body=dataset_record(),
            disclosure_body=disclosure_response(
                payload=receipt(
                    proof={
                        "dataset_key": "dataset.alpha",
                        "ingest_total_bytes": "123",
                    }
                ),
            ),
        )
    )

    assert (
        result.disclosure.status,
        result.disclosure.reason_code,
    ) == (
        "invalid",
        "PUBLICATION_RECEIPT_INVALID",
    )


def test_large_receipt_payload_is_rejected() -> None:
    oversized = json.dumps(
        {
            "schema": SCHEMA,
            "event_type": "published",
            "entity_kind": "dataset_version",
            "entity_id": "version-1",
            "visibility": "public",
            "event_version": 1,
            "proof": {
                "dataset_key": "x" * (128 * 1024),
            },
        },
        separators=(",", ":"),
    )

    result = resolve(
        FakeExplorerFetch(
            dataset_body=dataset_record(),
            disclosure_body=disclosure_response(
                payload=oversized,
            ),
        )
    )

    assert (
        result.disclosure.status,
        result.disclosure.reason_code,
    ) == (
        "invalid",
        "PUBLICATION_RECEIPT_INVALID",
    )


def test_missing_message_binding_does_not_fake_binding_evidence() -> None:
    response = disclosure_response()
    response.pop("message_binding")

    result = resolve(
        FakeExplorerFetch(
            dataset_body=dataset_record(),
            disclosure_body=response,
        )
    )

    assert result.disclosure.status == "resolved"

    binding = facts(
        result.disclosure.message_binding_observation
    )

    for key in (
        "publication.message_sha3_512",
        "publication.message_bytes",
    ):
        assert binding[key].state == "unavailable"
        assert (
            binding[key].reason_code
            == "CORE_MESSAGE_BINDING_UNAVAILABLE"
        )


@pytest.mark.parametrize(
    ("status", "reason"),
    [
        (404, "EXPLORER_NOT_FOUND"),
        (500, "EXPLORER_HTTP_UNAVAILABLE"),
    ],
)
def test_disclosure_transport_failure_remains_unavailable(
    status: int,
    reason: str,
) -> None:
    result = resolve(
        FakeExplorerFetch(
            dataset_body=dataset_record(),
            disclosure_body={},
            disclosure_status=status,
        )
    )

    assert result.disclosure.status == "unavailable"
    assert result.disclosure.reason_code == reason