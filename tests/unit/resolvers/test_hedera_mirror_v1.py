import asyncio
import base64
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

import pytest

from vera_anchor_verifier import sha3_512_hex
from vera_anchor_verifier.resolvers import (
    HederaMessageLocatorV1,
    HederaMirrorV1Config,
    resolve_hedera_message_v1,
)
from vera_anchor_verifier.resolvers.hedera_mirror_v1 import (
    HederaMirrorFetchResponseV1,
)

SUBJECT = {
    "kind": "dataset",
    "id": "dataset.alpha",
    "hedera_network": "testnet",
}


def run[T](coro) -> T:
    return asyncio.run(coro)


def encoded(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def json_response(
    value: object,
    *,
    status: int = 200,
) -> HederaMirrorFetchResponseV1:
    return HederaMirrorFetchResponseV1(
        status=status,
        headers={},
        body=json.dumps(
            value,
            separators=(",", ":"),
        ).encode(),
    )


@dataclass
class FakeMirrorFetch:
    responses: dict[str, HederaMirrorFetchResponseV1]
    calls: list[str] = field(default_factory=list)

    async def __call__(
        self,
        url: str,
        headers: Mapping[str, str],
        timeout_ms: int,
        max_response_bytes: int,
    ) -> HederaMirrorFetchResponseV1:
        del headers, timeout_ms, max_response_bytes

        parsed = urlsplit(url)
        marker = "/api/v1/"
        assert marker in parsed.path

        key = parsed.path.split(marker, 1)[1]

        if parsed.query:
            key = f"{key}?{parsed.query}"

        self.calls.append(key)

        return self.responses.get(
            key,
            json_response({}, status=404),
        )


def config(
    fetch: FakeMirrorFetch,
) -> HederaMirrorV1Config:
    return HederaMirrorV1Config(
        base_urls={
            "testnet": "https://mirror.example/api/v1",
        },
        fetch_impl=fetch,
    )


def facts(result) -> dict[str, Any]:
    assert result.observation is not None
    return {
        fact.key: fact
        for fact in result.observation.facts
    }


def message_row(
    value: bytes,
    *,
    sequence: int = 7,
    timestamp: str = "123.000000001",
    chunk: dict[str, object] | None = None,
) -> dict[str, object]:
    row: dict[str, object] = {
        "topic_id": "0.0.123",
        "sequence_number": sequence,
        "consensus_timestamp": timestamp,
        "message": encoded(value),
    }

    if chunk is not None:
        row["chunk_info"] = chunk

    return row


def test_resolves_and_hashes_exact_unchunked_message() -> None:
    fetch = FakeMirrorFetch(
        {
            "topics/0.0.123/messages/7": json_response(
                message_row(b"abc")
            ),
        }
    )

    result = run(
        resolve_hedera_message_v1(
            config(fetch),
            HederaMessageLocatorV1(
                hedera_network="testnet",
                topic_id="0.0.123",
                sequence_number=7,
            ),
            SUBJECT,
        )
    )

    assert result.status == "resolved"
    assert result.reason_code is None
    assert result.observation is not None
    assert result.observation.source == "hedera_mirror"
    assert (
        result.observation.resolver_id
        == "hedera.mirror-rest.v1"
    )

    indexed = facts(result)

    assert (
        indexed["publication.message_sha3_512"].value
        == sha3_512_hex(b"abc")
    )
    assert indexed["publication.message_bytes"].value == 3
    assert (
        indexed["hedera.consensus_timestamp_exact"].value
        == "123.000000001"
    )


def test_invalid_locator_fails_before_transport() -> None:
    fetch = FakeMirrorFetch({})

    result = run(
        resolve_hedera_message_v1(
            config(fetch),
            HederaMessageLocatorV1(
                hedera_network="testnet",
                topic_id="0.0.123",
                sequence_number=0,
            ),
            SUBJECT,
        )
    )

    assert (
        result.status,
        result.reason_code,
    ) == (
        "unavailable",
        "MIRROR_MESSAGE_LOCATOR_UNAVAILABLE",
    )
    assert fetch.calls == []


def test_subject_network_mismatch_fails_before_transport() -> None:
    fetch = FakeMirrorFetch({})

    result = run(
        resolve_hedera_message_v1(
            config(fetch),
            HederaMessageLocatorV1(
                hedera_network="mainnet",
                topic_id="0.0.123",
                sequence_number=7,
            ),
            SUBJECT,
        )
    )

    assert result.status == "unavailable"
    assert (
        result.reason_code
        == "MIRROR_MESSAGE_LOCATOR_UNAVAILABLE"
    )
    assert fetch.calls == []


def test_message_not_found_and_rate_limit_remain_distinct() -> None:
    missing = FakeMirrorFetch(
        {
            "topics/0.0.123/messages/7": json_response(
                {},
                status=404,
            ),
        }
    )

    result = run(
        resolve_hedera_message_v1(
            config(missing),
            HederaMessageLocatorV1(
                hedera_network="testnet",
                topic_id="0.0.123",
                sequence_number=7,
            ),
            SUBJECT,
        )
    )

    assert (
        result.status,
        result.reason_code,
    ) == (
        "unavailable",
        "MIRROR_MESSAGE_NOT_FOUND",
    )

    limited = FakeMirrorFetch(
        {
            "topics/0.0.123/messages/7": json_response(
                {},
                status=429,
            ),
        }
    )

    result = run(
        resolve_hedera_message_v1(
            config(limited),
            HederaMessageLocatorV1(
                hedera_network="testnet",
                topic_id="0.0.123",
                sequence_number=7,
            ),
            SUBJECT,
        )
    )

    assert (
        result.status,
        result.reason_code,
    ) == (
        "unavailable",
        "MIRROR_RATE_LIMITED",
    )


def test_malformed_message_payload_is_unavailable() -> None:
    row = message_row(b"abc")
    row["message"] = "not base64!"

    fetch = FakeMirrorFetch(
        {
            "topics/0.0.123/messages/7": json_response(row),
        }
    )

    result = run(
        resolve_hedera_message_v1(
            config(fetch),
            HederaMessageLocatorV1(
                hedera_network="testnet",
                topic_id="0.0.123",
                sequence_number=7,
            ),
            SUBJECT,
        )
    )

    assert (
        result.status,
        result.reason_code,
    ) == (
        "unavailable",
        "MIRROR_RESPONSE_INVALID",
    )


def test_three_chunk_message_is_reassembled_in_chunk_order() -> None:
    group = "0.0.5@100.1"

    chunk_1 = message_row(
        b"A",
        sequence=10,
        timestamp="200.000000001",
        chunk={
            "number": 1,
            "total": 3,
            "initial_transaction_id": group,
        },
    )
    chunk_2 = message_row(
        b"B",
        sequence=11,
        timestamp="200.000000002",
        chunk={
            "number": 2,
            "total": 3,
            "initial_transaction_id": group,
        },
    )
    chunk_3 = message_row(
        b"C",
        sequence=12,
        timestamp="200.000000003",
        chunk={
            "number": 3,
            "total": 3,
            "initial_transaction_id": group,
        },
    )

    before = (
        "topics/0.0.123/messages?"
        "order=desc&limit=100&"
        "timestamp=lte%3A200.000000002"
    )
    after = (
        "topics/0.0.123/messages?"
        "order=asc&limit=100&"
        "timestamp=gte%3A200.000000002"
    )

    fetch = FakeMirrorFetch(
        {
            "topics/0.0.123/messages/11": json_response(
                chunk_2
            ),
            before: json_response(
                {
                    "messages": [
                        chunk_2,
                        chunk_1,
                    ],
                }
            ),
            after: json_response(
                {
                    "messages": [
                        chunk_2,
                        chunk_3,
                    ],
                }
            ),
        }
    )

    result = run(
        resolve_hedera_message_v1(
            config(fetch),
            HederaMessageLocatorV1(
                hedera_network="testnet",
                topic_id="0.0.123",
                sequence_number=11,
            ),
            SUBJECT,
        )
    )

    assert result.status == "resolved"

    indexed = facts(result)

    assert indexed["publication.message_bytes"].value == 3
    assert (
        indexed["publication.message_sha3_512"].value
        == sha3_512_hex(b"ABC")
    )


def test_missing_chunk_is_reassembly_unavailable() -> None:
    group = "0.0.5@100.1"

    chunk_2 = message_row(
        b"B",
        sequence=11,
        timestamp="200.000000002",
        chunk={
            "number": 2,
            "total": 3,
            "initial_transaction_id": group,
        },
    )

    before = (
        "topics/0.0.123/messages?"
        "order=desc&limit=100&"
        "timestamp=lte%3A200.000000002"
    )
    after = (
        "topics/0.0.123/messages?"
        "order=asc&limit=100&"
        "timestamp=gte%3A200.000000002"
    )

    fetch = FakeMirrorFetch(
        {
            "topics/0.0.123/messages/11": json_response(
                chunk_2
            ),
            before: json_response(
                {"messages": [chunk_2]}
            ),
            after: json_response(
                {"messages": [chunk_2]}
            ),
        }
    )

    result = run(
        resolve_hedera_message_v1(
            config(fetch),
            HederaMessageLocatorV1(
                hedera_network="testnet",
                topic_id="0.0.123",
                sequence_number=11,
            ),
            SUBJECT,
        )
    )

    assert (
        result.status,
        result.reason_code,
    ) == (
        "unavailable",
        "MIRROR_MESSAGE_REASSEMBLY_UNAVAILABLE",
    )


def test_conflicting_duplicate_chunk_is_rejected() -> None:
    group = "0.0.5@100.1"

    first = message_row(
        b"B",
        sequence=11,
        timestamp="200.000000002",
        chunk={
            "number": 2,
            "total": 3,
            "initial_transaction_id": group,
        },
    )
    conflicting = message_row(
        b"X",
        sequence=11,
        timestamp="200.000000002",
        chunk={
            "number": 2,
            "total": 3,
            "initial_transaction_id": group,
        },
    )

    before = (
        "topics/0.0.123/messages?"
        "order=desc&limit=100&"
        "timestamp=lte%3A200.000000002"
    )
    after = (
        "topics/0.0.123/messages?"
        "order=asc&limit=100&"
        "timestamp=gte%3A200.000000002"
    )

    fetch = FakeMirrorFetch(
        {
            "topics/0.0.123/messages/11": json_response(
                first
            ),
            before: json_response(
                {"messages": [conflicting]}
            ),
            after: json_response(
                {"messages": []}
            ),
        }
    )

    result = run(
        resolve_hedera_message_v1(
            config(fetch),
            HederaMessageLocatorV1(
                hedera_network="testnet",
                topic_id="0.0.123",
                sequence_number=11,
            ),
            SUBJECT,
        )
    )

    assert (
        result.status,
        result.reason_code,
    ) == (
        "unavailable",
        "MIRROR_RESPONSE_INVALID",
    )


def test_successful_transaction_is_cross_checked() -> None:
    transaction = "0.0.9@123.4"

    fetch = FakeMirrorFetch(
        {
            "topics/0.0.123/messages/7": json_response(
                message_row(b"abc")
            ),
            (
                "transactions/"
                "0.0.9-123-000000004"
            ): json_response(
                {
                    "transactions": [
                        {
                            "transaction_id": (
                                "0.0.9@123.000000004"
                            ),
                            "result": "SUCCESS",
                            "consensus_timestamp": (
                                "124.000000005"
                            ),
                        }
                    ]
                }
            ),
        }
    )

    result = run(
        resolve_hedera_message_v1(
            config(fetch),
            HederaMessageLocatorV1(
                hedera_network="testnet",
                topic_id="0.0.123",
                sequence_number=7,
                transaction_id=transaction,
            ),
            SUBJECT,
        )
    )

    assert result.status == "resolved"

    indexed = facts(result)

    assert (
        indexed["hedera.transaction_id"].value
        == "0.0.9@123.000000004"
    )
    assert (
        indexed[
            "hedera.transaction_consensus_timestamp_exact"
        ].value
        == "124.000000005"
    )


def test_failed_transaction_is_explicit_conflict() -> None:
    fetch = FakeMirrorFetch(
        {
            "topics/0.0.123/messages/7": json_response(
                message_row(b"abc")
            ),
            (
                "transactions/"
                "0.0.9-123-000000004"
            ): json_response(
                {
                    "transactions": [
                        {
                            "transaction_id": (
                                "0.0.9@123.000000004"
                            ),
                            "result": "INVALID_SIGNATURE",
                        }
                    ]
                }
            ),
        }
    )

    result = run(
        resolve_hedera_message_v1(
            config(fetch),
            HederaMessageLocatorV1(
                hedera_network="testnet",
                topic_id="0.0.123",
                sequence_number=7,
                transaction_id="0.0.9@123.4",
            ),
            SUBJECT,
        )
    )

    assert (
        result.status,
        result.reason_code,
    ) == (
        "conflict",
        "MIRROR_TRANSACTION_FAILED",
    )


def test_invalid_transaction_reference_is_invalid() -> None:
    fetch = FakeMirrorFetch(
        {
            "topics/0.0.123/messages/7": json_response(
                message_row(b"abc")
            ),
        }
    )

    result = run(
        resolve_hedera_message_v1(
            config(fetch),
            HederaMessageLocatorV1(
                hedera_network="testnet",
                topic_id="0.0.123",
                sequence_number=7,
                transaction_id="not-a-transaction",
            ),
            SUBJECT,
        )
    )

    assert (
        result.status,
        result.reason_code,
    ) == (
        "invalid",
        "MIRROR_REFERENCE_INVALID",
    )


@pytest.mark.parametrize(
    "base_url",
    [
        "http://mirror.example/api/v1",
        "https://user:pass@mirror.example/api/v1",
        "https://mirror.example/not-api",
        "https://mirror.example/api/v1?query=1",
    ],
)
def test_untrusted_mirror_base_urls_fail_closed(
    base_url: str,
) -> None:
    fetch = FakeMirrorFetch(
        {
            "topics/0.0.123/messages/7": json_response(
                message_row(b"abc")
            ),
        }
    )

    result = run(
        resolve_hedera_message_v1(
            HederaMirrorV1Config(
                base_urls={
                    "testnet": base_url,
                },
                fetch_impl=fetch,
            ),
            HederaMessageLocatorV1(
                hedera_network="testnet",
                topic_id="0.0.123",
                sequence_number=7,
            ),
            SUBJECT,
        )
    )

    assert (
        result.status,
        result.reason_code,
    ) == (
        "invalid",
        "MIRROR_REFERENCE_INVALID",
    )