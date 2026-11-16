import asyncio
import base64
import hashlib
import json
from collections.abc import Mapping

import pytest

from vera_anchor_verifier.resolvers.hcs1_mirror_v1 import Hcs1MirrorV1Config
from vera_anchor_verifier.resolvers.hcs13_mirror_v1 import (
    Hcs13MirrorV1Request,
    resolve_hcs13_schema_v1,
)
from vera_anchor_verifier.resolvers.hedera_mirror_v1 import (
    HederaMirrorFetchResponseV1,
)
from vera_anchor_verifier.standards.hcs.hcs1_v1 import Hcs1V1ContentOptions
from vera_anchor_verifier.standards.hcs.hcs13_v1 import (
    finalize_hcs13_schema_v1,
)

BASE = "https://testnet.mirrornode.hedera.com/api/v1"
NETWORK = "testnet"
REGISTRY = "0.0.5001"
SCHEMA_TOPIC = "0.0.5002"
SEQUENCE = 7

SCHEMA = finalize_hcs13_schema_v1(
    {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {
            "count": {
                "type": "integer",
                "minimum": 0,
            },
        },
        "required": ["count"],
    }
)


def run(coro):
    return asyncio.run(coro)


def b64(value: bytes | str) -> str:
    raw = value.encode("utf-8") if isinstance(value, str) else value
    return base64.b64encode(raw).decode("ascii")


def decode_options() -> Hcs1V1ContentOptions:
    def decompress(compressed: bytes, limit: int) -> bytes:
        assert len(compressed) <= limit
        return compressed

    return Hcs1V1ContentOptions(decompress_zstd=decompress)


def response(
    value: object,
    *,
    status: int = 200,
) -> HederaMirrorFetchResponseV1:
    return HederaMirrorFetchResponseV1(
        status=status,
        headers={},
        body=json.dumps(value, separators=(",", ":")).encode("utf-8"),
    )


def fixture(
    *,
    target: str | None = None,
    schema_bytes: bytes | None = None,
    registry_memo: str | None = None,
    file_memo: str | None = None,
    missing: str | None = None,
    invalid_sequence: int | None = None,
):
    urls: list[str] = []
    raw_schema = (
        schema_bytes
        if schema_bytes is not None
        else SCHEMA.canonical_payload.encode("utf-8")
    )

    chunk = json.dumps(
        {
            "o": 0,
            "c": f"data:application/json;base64,{b64(raw_schema)}",
        },
        separators=(",", ":"),
    ).encode("utf-8")

    async def fetch(
        url: str,
        headers: Mapping[str, str],
        timeout_ms: int,
        max_response_bytes: int,
    ) -> HederaMirrorFetchResponseV1:
        del headers
        del timeout_ms
        del max_response_bytes

        urls.append(url)

        if url == missing:
            return HederaMirrorFetchResponseV1(
                status=404,
                headers={},
                body=b"",
            )

        if url == f"{BASE}/topics/{REGISTRY}":
            return response(
                {
                    "topic_id": REGISTRY,
                    "memo": (
                        registry_memo
                        if registry_memo is not None
                        else "hcs-2:0:86400"
                    ),
                }
            )

        if url == f"{BASE}/topics/{REGISTRY}/messages/{SEQUENCE}":
            register = json.dumps(
                {
                    "p": "hcs-2",
                    "op": "register",
                    "t_id": target if target is not None else SCHEMA_TOPIC,
                },
                separators=(",", ":"),
            )

            return response(
                {
                    "topic_id": REGISTRY,
                    "sequence_number": (
                        invalid_sequence
                        if invalid_sequence is not None
                        else SEQUENCE
                    ),
                    "consensus_timestamp": "1792039124.000000123",
                    "message": b64(register),
                }
            )

        if url == f"{BASE}/topics/{SCHEMA_TOPIC}":
            return response(
                {
                    "topic_id": SCHEMA_TOPIC,
                    "memo": (
                        file_memo
                        if file_memo is not None
                        else (
                            f"{hashlib.sha256(raw_schema).hexdigest()}"
                            ":zstd:base64"
                        )
                    ),
                    "submit_key": {"key": "present"},
                    "admin_key": None,
                }
            )

        if url == (
            f"{BASE}/topics/{SCHEMA_TOPIC}"
            "/messages?limit=100&order=asc"
        ):
            return response(
                {
                    "messages": [
                        {
                            "topic_id": SCHEMA_TOPIC,
                            "sequence_number": 1,
                            "message": b64(chunk),
                        }
                    ],
                    "links": {"next": None},
                }
            )

        raise AssertionError(f"Unexpected Mirror request: {url}")

    return fetch, urls


def request(**overrides: object) -> Hcs13MirrorV1Request:
    values: dict[str, object] = {
        "hedera_network": NETWORK,
        "reference": f"hcs://13/{REGISTRY}#{SEQUENCE}",
    }
    values.update(overrides)
    return Hcs13MirrorV1Request(**values)  # type: ignore[arg-type]


def test_resolves_exact_historical_schema() -> None:
    fetch, urls = fixture()

    result = run(
        resolve_hcs13_schema_v1(
            Hcs1MirrorV1Config(fetch_impl=fetch),
            request(
                expected_schema_sha256=SCHEMA.sha256,
                expected_hcs1_reference=f"hcs://1/{SCHEMA_TOPIC}",
            ),
            decode_options(),
        )
    )

    assert result.status == "resolved"
    assert result.reason_code is None
    assert result.schema_hcs1_reference == f"hcs://1/{SCHEMA_TOPIC}"
    assert result.content_sha256 == SCHEMA.sha256
    assert result.schema_sha256 == SCHEMA.sha256
    assert result.assurance == "mirror_corroborated"
    assert result.registry_memo_temporal_scope == "current_observation"
    assert (
        result.registry_consensus_timestamp_exact
        == "1792039124.000000123"
    )
    assert result.schema is not None
    assert result.schema["type"] == "object"

    assert urls == [
        f"{BASE}/topics/{REGISTRY}",
        f"{BASE}/topics/{REGISTRY}/messages/{SEQUENCE}",
        f"{BASE}/topics/{SCHEMA_TOPIC}",
        (
            f"{BASE}/topics/{SCHEMA_TOPIC}"
            "/messages?limit=100&order=asc"
        ),
    ]


def test_rejects_topic_substitution_before_hcs1_read() -> None:
    fetch, urls = fixture(target="0.0.999")

    result = run(
        resolve_hcs13_schema_v1(
            Hcs1MirrorV1Config(fetch_impl=fetch),
            request(
                expected_hcs1_reference=f"hcs://1/{SCHEMA_TOPIC}",
            ),
            decode_options(),
        )
    )

    assert result.status == "conflict"
    assert result.reason_code == "HCS2_TARGET_MISMATCH"
    assert len(urls) == 2


def test_expected_schema_checksum_mismatch_is_conflict() -> None:
    fetch, _urls = fixture()

    result = run(
        resolve_hcs13_schema_v1(
            Hcs1MirrorV1Config(fetch_impl=fetch),
            request(expected_schema_sha256="f" * 64),
            decode_options(),
        )
    )

    assert result.status == "conflict"
    assert result.reason_code == "HCS1_EXPECTED_CHECKSUM_MISMATCH"


def test_observed_hcs1_checksum_disagreement_is_invalid() -> None:
    fetch, _urls = fixture(
        file_memo=f"{'a' * 64}:zstd:base64"
    )

    result = run(
        resolve_hcs13_schema_v1(
            Hcs1MirrorV1Config(fetch_impl=fetch),
            request(),
            decode_options(),
        )
    )

    assert result.status == "invalid"
    assert result.reason_code == "HCS1_CHECKSUM_MISMATCH"


def test_noncanonical_publication_is_unsupported() -> None:
    raw = json.dumps(
        {
            "required": ["count"],
            "type": "object",
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "properties": {
                "count": {
                    "minimum": 0,
                    "type": "integer",
                },
            },
        }
    ).encode("utf-8")

    assert raw != SCHEMA.canonical_payload.encode("utf-8")

    fetch, _urls = fixture(schema_bytes=raw)

    result = run(
        resolve_hcs13_schema_v1(
            Hcs1MirrorV1Config(fetch_impl=fetch),
            request(),
            decode_options(),
        )
    )

    assert result.status == "unsupported"
    assert result.reason_code == "HCS13_SCHEMA_CONTENT_NOT_CANONICAL"


def test_distinguishes_missing_exact_registry_entry() -> None:
    missing = f"{BASE}/topics/{REGISTRY}/messages/{SEQUENCE}"
    fetch, urls = fixture(missing=missing)

    result = run(
        resolve_hcs13_schema_v1(
            Hcs1MirrorV1Config(fetch_impl=fetch),
            request(),
            decode_options(),
        )
    )

    assert result.status == "unavailable"
    assert result.reason_code == "HCS2_REGISTER_NOT_FOUND"
    assert len(urls) == 2


def test_rejects_historical_sequence_scope_mismatch() -> None:
    fetch, urls = fixture(invalid_sequence=8)

    result = run(
        resolve_hcs13_schema_v1(
            Hcs1MirrorV1Config(fetch_impl=fetch),
            request(),
            decode_options(),
        )
    )

    assert result.status == "invalid"
    assert result.reason_code == "HCS2_MESSAGE_SCOPE_INVALID"
    assert len(urls) == 2


def test_validates_request_before_network_reads() -> None:
    fetch, urls = fixture()

    with pytest.raises(
        TypeError,
        match="HCS13_NETWORK_INVALID",
    ):
        run(
            resolve_hcs13_schema_v1(
                Hcs1MirrorV1Config(fetch_impl=fetch),
                Hcs13MirrorV1Request(
                    hedera_network="previewnet",  # type: ignore[arg-type]
                    reference=f"hcs://13/{REGISTRY}#{SEQUENCE}",
                ),
                decode_options(),
            )
        )

    with pytest.raises(
        TypeError,
        match="HCS13_EXPECTED_CHECKSUM_INVALID",
    ):
        run(
            resolve_hcs13_schema_v1(
                Hcs1MirrorV1Config(fetch_impl=fetch),
                request(expected_schema_sha256="bad"),
                decode_options(),
            )
        )

    with pytest.raises(
        TypeError,
        match="HCS1_REFERENCE_INVALID",
    ):
        run(
            resolve_hcs13_schema_v1(
                Hcs1MirrorV1Config(fetch_impl=fetch),
                request(
                    expected_hcs1_reference="https://evil.example",
                ),
                decode_options(),
            )
        )

    assert urls == []