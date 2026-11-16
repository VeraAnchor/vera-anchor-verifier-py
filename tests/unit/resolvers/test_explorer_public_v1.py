import asyncio
import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

import pytest

from vera_anchor_verifier.resolvers import (
    ExplorerDatasetV1Request,
    ExplorerIngestV1Request,
    ExplorerMerkleRootV1Request,
    ExplorerPublicTransportV1,
    resolve_explorer_dataset_v1,
    resolve_explorer_ingest_v1,
    resolve_explorer_merkle_root_v1,
)
from vera_anchor_verifier.resolvers.explorer_transport_v1 import (
    ExplorerFetchResponseV1,
)

DIGEST = "a" * 128
OTHER_DIGEST = "b" * 128
ANCHOR_ID = "12345678-1234-1234-1234-123456789abc"
ROOT_ID = "abcdef12-3456-7890-abcd-ef1234567890"


def run[T](coro) -> T:
    return asyncio.run(coro)


@dataclass
class JsonFetch:
    body: object
    status: int = 200
    headers: Mapping[str, str] | None = None

    async def __call__(
        self,
        url: str,
        method: str,
        headers: Mapping[str, str],
        body: bytes | None,
        timeout_ms: int,
        max_response_bytes: int,
    ) -> ExplorerFetchResponseV1:
        del url, method, headers, body, timeout_ms, max_response_bytes

        return ExplorerFetchResponseV1(
            status=self.status,
            headers=self.headers or {},
            body=json.dumps(
                self.body,
                separators=(",", ":"),
            ).encode(),
        )


def config(
    body: object,
    *,
    status: int = 200,
) -> ExplorerPublicTransportV1:
    return ExplorerPublicTransportV1(
        base_url="https://explorer.example",
        fetch_impl=JsonFetch(
            body,
            status=status,
        ),
    )


def facts(result) -> dict[str, Any]:
    assert result.observation is not None
    return {
        fact.key: fact
        for fact in result.observation.facts
    }


def test_dataset_record_is_normalized_without_bundle_inference() -> None:
    result = run(
        resolve_explorer_dataset_v1(
            config(
                {
                    "hedera_network": "testnet",
                    "dataset_key": "dataset.alpha",
                    "dataset_fingerprint": DIGEST.upper(),
                    "manifest_hash": OTHER_DIGEST,
                    "dataset_version_id": "version-1",
                    "dataset_id": "dataset-id",
                    "publication_version_topic_id": "0.0.123",
                    "publication_version_sequence_number": "7",
                }
            ),
            ExplorerDatasetV1Request(
                dataset_key="dataset.alpha",
                network="testnet",
            ),
        )
    )

    assert result.status == "resolved"
    assert result.publication is not None
    assert result.publication.entity_kind == "dataset_version"
    assert result.publication.message_id == "7@0.0.123"

    indexed = facts(result)

    assert indexed["dataset_fingerprint"].value == DIGEST
    assert indexed["dataset.manifest_hash"].value == OTHER_DIGEST
    assert "bundle_digest" not in indexed

    assert result.observation is not None
    assert result.observation.source == "public_record"
    assert (
        result.observation.resolver_id
        == "explorer.public-http.v1"
    )


def test_dataset_falls_back_to_dataset_publication() -> None:
    result = run(
        resolve_explorer_dataset_v1(
            config(
                {
                    "hedera_network": "mainnet",
                    "dataset_key": "dataset.alpha",
                    "dataset_id": "dataset-id",
                    "publication_dataset_message_id": "9@0.0.456",
                }
            ),
            ExplorerDatasetV1Request(
                dataset_key="dataset.alpha",
                network="mainnet",
            ),
        )
    )

    assert result.status == "resolved"
    assert result.publication is not None
    assert result.publication.entity_kind == "dataset"
    assert result.publication.topic_id == "0.0.456"
    assert result.publication.sequence_number == 9


def test_dataset_identity_unavailable_and_conflict_are_distinct() -> None:
    missing = run(
        resolve_explorer_dataset_v1(
            config(
                {
                    "hedera_network": "testnet",
                }
            ),
            ExplorerDatasetV1Request(
                dataset_key="dataset.alpha",
                network="testnet",
            ),
        )
    )

    assert (
        missing.status,
        missing.reason_code,
    ) == (
        "unavailable",
        "PUBLIC_DATASET_KEY_UNAVAILABLE",
    )

    conflict = run(
        resolve_explorer_dataset_v1(
            config(
                {
                    "hedera_network": "testnet",
                    "dataset_key": "dataset.other",
                }
            ),
            ExplorerDatasetV1Request(
                dataset_key="dataset.alpha",
                network="testnet",
            ),
        )
    )

    assert (
        conflict.status,
        conflict.reason_code,
    ) == (
        "conflict",
        "PUBLIC_DATASET_KEY_MISMATCH",
    )


def test_dataset_network_mismatch_is_invalid() -> None:
    result = run(
        resolve_explorer_dataset_v1(
            config(
                {
                    "hedera_network": "mainnet",
                    "dataset_key": "dataset.alpha",
                }
            ),
            ExplorerDatasetV1Request(
                dataset_key="dataset.alpha",
                network="testnet",
            ),
        )
    )

    assert (
        result.status,
        result.reason_code,
    ) == (
        "invalid",
        "PUBLIC_DATASET_RESPONSE_INVALID",
    )


def test_ingest_record_binds_anchor_and_object_identity() -> None:
    result = run(
        resolve_explorer_ingest_v1(
            config(
                {
                    "hedera_network": "testnet",
                    "anchor_request_id": ANCHOR_ID,
                    "ingest_object_key": "object.alpha",
                    "ingest_fingerprint": DIGEST,
                    "ingest_bundle_digest": OTHER_DIGEST,
                    "ingest_merkle_root": DIGEST,
                    "ingest_total_bytes": "123",
                    "root_id": ROOT_ID,
                    "root_hash": OTHER_DIGEST,
                    "publication_anchor_topic_id": "0.0.789",
                    "publication_anchor_sequence_number": 11,
                }
            ),
            ExplorerIngestV1Request(
                anchor_request_id=ANCHOR_ID,
                ingest_object_key="object.alpha",
                network="testnet",
            ),
        )
    )

    assert result.status == "resolved"
    assert result.publication is not None
    assert result.publication.entity_kind == "merkle_anchor"

    indexed = facts(result)

    assert indexed["fingerprint"].value == DIGEST
    assert indexed["bundle_digest"].value == OTHER_DIGEST
    assert indexed["ingest.total_bytes"].value == 123
    assert indexed["merkle.root_id"].value == ROOT_ID


@pytest.mark.parametrize(
    ("row", "reason"),
    [
        (
            {
                "hedera_network": "testnet",
                "ingest_object_key": "object.alpha",
            },
            "PUBLIC_ANCHOR_ID_UNAVAILABLE",
        ),
        (
            {
                "hedera_network": "testnet",
                "anchor_request_id": ANCHOR_ID,
            },
            "PUBLIC_INGEST_OBJECT_UNAVAILABLE",
        ),
    ],
)
def test_ingest_missing_identity_fields_are_unavailable(
    row: dict[str, object],
    reason: str,
) -> None:
    result = run(
        resolve_explorer_ingest_v1(
            config(row),
            ExplorerIngestV1Request(
                anchor_request_id=ANCHOR_ID,
                ingest_object_key="object.alpha",
                network="testnet",
            ),
        )
    )

    assert (
        result.status,
        result.reason_code,
    ) == (
        "unavailable",
        reason,
    )


def test_ingest_identity_conflicts_fail_explicitly() -> None:
    anchor_conflict = run(
        resolve_explorer_ingest_v1(
            config(
                {
                    "hedera_network": "testnet",
                    "anchor_request_id": ROOT_ID,
                    "ingest_object_key": "object.alpha",
                }
            ),
            ExplorerIngestV1Request(
                anchor_request_id=ANCHOR_ID,
                ingest_object_key="object.alpha",
                network="testnet",
            ),
        )
    )

    assert anchor_conflict.status == "conflict"
    assert (
        anchor_conflict.reason_code
        == "PUBLIC_ANCHOR_ID_MISMATCH"
    )

    object_conflict = run(
        resolve_explorer_ingest_v1(
            config(
                {
                    "hedera_network": "testnet",
                    "anchor_request_id": ANCHOR_ID,
                    "ingest_object_key": "object.other",
                }
            ),
            ExplorerIngestV1Request(
                anchor_request_id=ANCHOR_ID,
                ingest_object_key="object.alpha",
                network="testnet",
            ),
        )
    )

    assert object_conflict.status == "conflict"
    assert (
        object_conflict.reason_code
        == "PUBLIC_INGEST_OBJECT_MISMATCH"
    )


def test_merkle_root_record_is_normalized() -> None:
    result = run(
        resolve_explorer_merkle_root_v1(
            config(
                {
                    "hedera_network": "mainnet",
                    "id": ROOT_ID,
                    "root_hash": DIGEST,
                    "leaf_count": "42",
                    "hash_alg": "sha3-512",
                    "tree_alg": "binary-sorted-v2",
                    "publication_root_message_id": "0.0.321@15",
                }
            ),
            ExplorerMerkleRootV1Request(
                root_id=ROOT_ID,
                network="mainnet",
            ),
        )
    )

    assert result.status == "resolved"
    assert result.publication is not None
    assert result.publication.message_id == "15@0.0.321"

    indexed = facts(result)

    assert indexed["merkle.root_hash"].value == DIGEST
    assert indexed["merkle.leaf_count"].value == 42
    assert indexed["merkle.hash_alg"].value == "sha3-512"
    assert indexed["merkle.tree_alg"].value == "binary-sorted-v2"


def test_missing_publication_is_resolved_with_unavailable_facts() -> None:
    result = run(
        resolve_explorer_merkle_root_v1(
            config(
                {
                    "hedera_network": "testnet",
                    "id": ROOT_ID,
                    "root_hash": DIGEST,
                }
            ),
            ExplorerMerkleRootV1Request(
                root_id=ROOT_ID,
                network="testnet",
            ),
        )
    )

    assert result.status == "resolved"
    assert result.publication is None

    indexed = facts(result)

    for key in (
        "publication.entity_kind",
        "publication.entity_id",
        "publication.topic_id",
        "publication.sequence_number",
    ):
        assert indexed[key].state == "unavailable"
        assert (
            indexed[key].reason_code
            == "PUBLICATION_ANCHOR_UNAVAILABLE"
        )


@pytest.mark.parametrize(
    "row",
    [
        {
            "hedera_network": "testnet",
            "id": ROOT_ID,
            "root_hash": "not-a-hash",
        },
        {
            "hedera_network": "testnet",
            "id": ROOT_ID,
            "leaf_count": -1,
        },
        {
            "hedera_network": "testnet",
            "id": ROOT_ID,
            "publication_root_topic_id": "0.0.123",
        },
        {
            "hedera_network": "testnet",
            "id": ROOT_ID,
            "publication_root_message_id": "7@0.0.123",
            "publication_root_topic_id": "0.0.456",
            "publication_root_sequence_number": 7,
        },
    ],
)
def test_malformed_merkle_records_are_invalid(
    row: dict[str, object],
) -> None:
    result = run(
        resolve_explorer_merkle_root_v1(
            config(row),
            ExplorerMerkleRootV1Request(
                root_id=ROOT_ID,
                network="testnet",
            ),
        )
    )

    assert (
        result.status,
        result.reason_code,
    ) == (
        "invalid",
        "PUBLIC_MERKLE_RESPONSE_INVALID",
    )


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (404, "not_found"),
        (500, "unavailable"),
    ],
)
def test_transport_outcomes_are_preserved(
    status: int,
    expected: str,
) -> None:
    result = run(
        resolve_explorer_dataset_v1(
            config({}, status=status),
            ExplorerDatasetV1Request(
                dataset_key="dataset.alpha",
                network="testnet",
            ),
        )
    )

    assert result.status == expected
    assert result.observation is None
    assert result.publication is None


@pytest.mark.parametrize(
    "lookup_request",
    [
        ExplorerDatasetV1Request(
            dataset_key="../escape",
            network="testnet",
        ),
        ExplorerIngestV1Request(
            anchor_request_id="not-a-uuid",
            ingest_object_key="object.alpha",
            network="testnet",
        ),
        ExplorerMerkleRootV1Request(
            root_id="not-a-uuid",
            network="mainnet",
        ),
    ],
)
def test_invalid_lookup_inputs_fail_before_transport(
    lookup_request: object,
) -> None:
    with pytest.raises(
        TypeError,
        match="Invalid Explorer public lookup input",
    ):
        if isinstance(
            lookup_request,
            ExplorerDatasetV1Request,
        ):
            run(
                resolve_explorer_dataset_v1(
                    config({}),
                    lookup_request,
                )
            )
        elif isinstance(
            lookup_request,
            ExplorerIngestV1Request,
        ):
            run(
                resolve_explorer_ingest_v1(
                    config({}),
                    lookup_request,
                )
            )
        else:
            assert isinstance(
                lookup_request,
                ExplorerMerkleRootV1Request,
            )
            run(
                resolve_explorer_merkle_root_v1(
                    config({}),
                    lookup_request,
                )
            )