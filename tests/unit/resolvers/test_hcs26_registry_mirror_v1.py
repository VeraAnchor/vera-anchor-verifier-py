import asyncio
import base64
import json
from collections.abc import Mapping

import pytest

from vera_anchor_verifier.resolvers.hcs26_registry_mirror_v1 import (
    Hcs26RegistryRequestV1,
    read_hcs26_registry_message_v1,
)
from vera_anchor_verifier.resolvers.hedera_mirror_v1 import (
    HederaMirrorFetchResponseV1,
    HederaMirrorV1Config,
)

BASE = "https://testnet.mirrornode.hedera.com/api/v1"
TOPIC = "0.0.6001"
SEQUENCE = 42
TIMESTAMP = "1792039124.000000001"

MESSAGE = json.dumps(
    {
        "p": "hcs-26",
        "op": "register",
        "t_id": "0.0.6002",
        "account_id": "0.0.6999",
        "metadata": "hcs://1/0.0.6900",
    },
    separators=(",", ":"),
).encode("utf-8")


def run(coro):
    return asyncio.run(coro)


def b64(value: bytes | str) -> str:
    raw = (
        value.encode("utf-8")
        if isinstance(value, str)
        else value
    )
    return base64.b64encode(raw).decode("ascii")


def response(
    value: object,
    *,
    status: int = 200,
    headers: Mapping[str, str] | None = None,
) -> HederaMirrorFetchResponseV1:
    return HederaMirrorFetchResponseV1(
        status=status,
        headers=headers or {},
        body=json.dumps(
            value,
            separators=(",", ":"),
        ).encode("utf-8"),
    )


def request(
    *,
    registry_type: str = "discovery",
    **overrides: object,
) -> Hcs26RegistryRequestV1:
    values: dict[str, object] = {
        "hedera_network": "testnet",
        "topic_id": TOPIC,
        "sequence_number": SEQUENCE,
        "registry_type": registry_type,
    }
    values.update(overrides)
    return Hcs26RegistryRequestV1(
        **values  # type: ignore[arg-type]
    )


def test_resolves_exact_historical_registry_message() -> None:
    calls: list[str] = []

    async def fetch(
        url: str,
        headers: Mapping[str, str],
        timeout_ms: int,
        max_response_bytes: int,
    ) -> HederaMirrorFetchResponseV1:
        calls.append(url)

        assert headers == {
            "Accept": "application/json",
        }
        assert timeout_ms == 8_000
        assert (
            max_response_bytes
            == 256 * 1024
        )

        if url == f"{BASE}/topics/{TOPIC}":
            return response(
                {
                    "topic_id": TOPIC,
                    "memo": (
                        "hcs-26:0:86400:0"
                    ),
                }
            )

        if url == (
            f"{BASE}/topics/{TOPIC}"
            f"/messages/{SEQUENCE}"
        ):
            return response(
                {
                    "topic_id": TOPIC,
                    "sequence_number": (
                        SEQUENCE
                    ),
                    "consensus_timestamp": (
                        TIMESTAMP
                    ),
                    "message": b64(
                        MESSAGE
                    ),
                }
            )

        raise AssertionError(
            f"Unexpected URL: {url}"
        )

    result = run(
        read_hcs26_registry_message_v1(
            HederaMirrorV1Config(
                fetch_impl=fetch
            ),
            request(),
        )
    )

    assert result.status == "resolved"
    assert result.reason_code is None
    assert result.evidence is not None
    assert (
        result.evidence.topic_id
        == TOPIC
    )
    assert (
        result.evidence.sequence_number
        == SEQUENCE
    )
    assert (
        result.evidence.consensus_timestamp
        == TIMESTAMP
    )
    assert (
        result.evidence.memo.type
        == "discovery"
    )
    assert (
        result.evidence.message
        == MESSAGE
    )

    assert calls == [
        f"{BASE}/topics/{TOPIC}",
        (
            f"{BASE}/topics/{TOPIC}"
            f"/messages/{SEQUENCE}"
        ),
    ]


def test_accepts_canonical_base64_topic_memo() -> None:
    memo = b64(
        "hcs-26:1:0:1"
    )

    async def fetch(
        url: str,
        headers: Mapping[str, str],
        timeout_ms: int,
        max_response_bytes: int,
    ) -> HederaMirrorFetchResponseV1:
        del headers
        del timeout_ms
        del max_response_bytes

        if url == f"{BASE}/topics/{TOPIC}":
            return response(
                {
                    "topic_id": TOPIC,
                    "memo": memo,
                }
            )

        return response(
            {
                "topic_id": TOPIC,
                "sequence_number": (
                    float(SEQUENCE)
                ),
                "consensus_timestamp": (
                    TIMESTAMP
                ),
                "message": b64(
                    MESSAGE
                ),
            }
        )

    result = run(
        read_hcs26_registry_message_v1(
            HederaMirrorV1Config(
                fetch_impl=fetch
            ),
            request(
                registry_type="version"
            ),
        )
    )

    assert result.status == "resolved"
    assert result.evidence is not None
    assert (
        result.evidence.memo.type
        == "version"
    )
    assert (
        result.evidence.memo.indexed
        is False
    )


def test_rejects_registry_type_before_message_read() -> None:
    calls: list[str] = []

    async def fetch(
        url: str,
        headers: Mapping[str, str],
        timeout_ms: int,
        max_response_bytes: int,
    ) -> HederaMirrorFetchResponseV1:
        del headers
        del timeout_ms
        del max_response_bytes

        calls.append(url)

        return response(
            {
                "topic_id": TOPIC,
                "memo": (
                    "hcs-26:0:86400:0"
                ),
            }
        )

    result = run(
        read_hcs26_registry_message_v1(
            HederaMirrorV1Config(
                fetch_impl=fetch
            ),
            request(
                registry_type="version"
            ),
        )
    )

    assert result.status == "invalid"
    assert result.reason_code == (
        "HCS26_REGISTRY_TYPE_MISMATCH"
    )
    assert calls == [
        f"{BASE}/topics/{TOPIC}",
    ]


def test_rejects_registry_and_message_scope_substitution() -> None:
    async def wrong_topic(
        url: str,
        headers: Mapping[str, str],
        timeout_ms: int,
        max_response_bytes: int,
    ) -> HederaMirrorFetchResponseV1:
        del url
        del headers
        del timeout_ms
        del max_response_bytes

        return response(
            {
                "topic_id": "0.0.999",
                "memo": (
                    "hcs-26:0:86400:0"
                ),
            }
        )

    topic_result = run(
        read_hcs26_registry_message_v1(
            HederaMirrorV1Config(
                fetch_impl=wrong_topic
            ),
            request(),
        )
    )

    assert topic_result.status == "invalid"
    assert topic_result.reason_code == (
        "HCS26_REGISTRY_SCOPE_MISMATCH"
    )

    async def wrong_message(
        url: str,
        headers: Mapping[str, str],
        timeout_ms: int,
        max_response_bytes: int,
    ) -> HederaMirrorFetchResponseV1:
        del headers
        del timeout_ms
        del max_response_bytes

        if url == f"{BASE}/topics/{TOPIC}":
            return response(
                {
                    "topic_id": TOPIC,
                    "memo": (
                        "hcs-26:0:86400:0"
                    ),
                }
            )

        return response(
            {
                "topic_id": TOPIC,
                "sequence_number": (
                    SEQUENCE + 1
                ),
                "consensus_timestamp": (
                    TIMESTAMP
                ),
                "message": b64(
                    MESSAGE
                ),
            }
        )

    message_result = run(
        read_hcs26_registry_message_v1(
            HederaMirrorV1Config(
                fetch_impl=wrong_message
            ),
            request(),
        )
    )

    assert (
        message_result.status
        == "invalid"
    )
    assert message_result.reason_code == (
        "HCS26_REGISTRY_MESSAGE_SCOPE_MISMATCH"
    )


def test_rejects_chunked_message_and_invalid_timestamp() -> None:
    async def chunked(
        url: str,
        headers: Mapping[str, str],
        timeout_ms: int,
        max_response_bytes: int,
    ) -> HederaMirrorFetchResponseV1:
        del headers
        del timeout_ms
        del max_response_bytes

        if url == f"{BASE}/topics/{TOPIC}":
            return response(
                {
                    "topic_id": TOPIC,
                    "memo": (
                        "hcs-26:0:86400:0"
                    ),
                }
            )

        return response(
            {
                "topic_id": TOPIC,
                "sequence_number": SEQUENCE,
                "consensus_timestamp": (
                    TIMESTAMP
                ),
                "chunk_info": {},
                "message": b64(
                    MESSAGE
                ),
            }
        )

    result = run(
        read_hcs26_registry_message_v1(
            HederaMirrorV1Config(
                fetch_impl=chunked
            ),
            request(),
        )
    )

    assert result.status == "invalid"
    assert result.reason_code == (
        "HCS26_REGISTRY_MESSAGE_SCOPE_MISMATCH"
    )

    async def bad_timestamp(
        url: str,
        headers: Mapping[str, str],
        timeout_ms: int,
        max_response_bytes: int,
    ) -> HederaMirrorFetchResponseV1:
        del headers
        del timeout_ms
        del max_response_bytes

        if url == f"{BASE}/topics/{TOPIC}":
            return response(
                {
                    "topic_id": TOPIC,
                    "memo": (
                        "hcs-26:0:86400:0"
                    ),
                }
            )

        return response(
            {
                "topic_id": TOPIC,
                "sequence_number": SEQUENCE,
                "consensus_timestamp": (
                    "latest"
                ),
                "message": b64(
                    MESSAGE
                ),
            }
        )

    result = run(
        read_hcs26_registry_message_v1(
            HederaMirrorV1Config(
                fetch_impl=bad_timestamp
            ),
            request(),
        )
    )

    assert result.status == "invalid"
    assert result.reason_code == (
        "HCS26_REGISTRY_TIMESTAMP_INVALID"
    )


def test_rejects_invalid_memo_and_message_base64() -> None:
    async def bad_memo(
        url: str,
        headers: Mapping[str, str],
        timeout_ms: int,
        max_response_bytes: int,
    ) -> HederaMirrorFetchResponseV1:
        del url
        del headers
        del timeout_ms
        del max_response_bytes

        return response(
            {
                "topic_id": TOPIC,
                "memo": "***",
            }
        )

    result = run(
        read_hcs26_registry_message_v1(
            HederaMirrorV1Config(
                fetch_impl=bad_memo
            ),
            request(),
        )
    )

    assert result.status == "invalid"
    assert result.reason_code == (
        "HCS26_TOPIC_MEMO_INVALID"
    )

    async def bad_message(
        url: str,
        headers: Mapping[str, str],
        timeout_ms: int,
        max_response_bytes: int,
    ) -> HederaMirrorFetchResponseV1:
        del headers
        del timeout_ms
        del max_response_bytes

        if url == f"{BASE}/topics/{TOPIC}":
            return response(
                {
                    "topic_id": TOPIC,
                    "memo": (
                        "hcs-26:0:86400:0"
                    ),
                }
            )

        return response(
            {
                "topic_id": TOPIC,
                "sequence_number": SEQUENCE,
                "consensus_timestamp": (
                    TIMESTAMP
                ),
                "message": "***",
            }
        )

    result = run(
        read_hcs26_registry_message_v1(
            HederaMirrorV1Config(
                fetch_impl=bad_message
            ),
            request(),
        )
    )

    assert result.status == "invalid"
    assert result.reason_code == (
        "HCS26_MIRROR_MESSAGE_INVALID"
    )


def test_distinguishes_missing_registry_and_entry() -> None:
    async def missing_registry(
        url: str,
        headers: Mapping[str, str],
        timeout_ms: int,
        max_response_bytes: int,
    ) -> HederaMirrorFetchResponseV1:
        del url
        del headers
        del timeout_ms
        del max_response_bytes

        return HederaMirrorFetchResponseV1(
            status=404,
            headers={},
            body=b"",
        )

    result = run(
        read_hcs26_registry_message_v1(
            HederaMirrorV1Config(
                fetch_impl=missing_registry
            ),
            request(),
        )
    )

    assert result.status == "unavailable"
    assert result.reason_code == (
        "HCS26_REGISTRY_NOT_FOUND"
    )

    async def missing_entry(
        url: str,
        headers: Mapping[str, str],
        timeout_ms: int,
        max_response_bytes: int,
    ) -> HederaMirrorFetchResponseV1:
        del headers
        del timeout_ms
        del max_response_bytes

        if url == f"{BASE}/topics/{TOPIC}":
            return response(
                {
                    "topic_id": TOPIC,
                    "memo": (
                        "hcs-26:0:86400:0"
                    ),
                }
            )

        return HederaMirrorFetchResponseV1(
            status=404,
            headers={},
            body=b"",
        )

    result = run(
        read_hcs26_registry_message_v1(
            HederaMirrorV1Config(
                fetch_impl=missing_entry
            ),
            request(),
        )
    )

    assert result.status == "unavailable"
    assert result.reason_code == (
        "HCS26_REGISTRY_ENTRY_NOT_FOUND"
    )


def test_maps_rate_limit_and_oversized_response() -> None:
    async def limited(
        url: str,
        headers: Mapping[str, str],
        timeout_ms: int,
        max_response_bytes: int,
    ) -> HederaMirrorFetchResponseV1:
        del url
        del headers
        del timeout_ms
        del max_response_bytes

        return HederaMirrorFetchResponseV1(
            status=429,
            headers={},
            body=b"",
        )

    result = run(
        read_hcs26_registry_message_v1(
            HederaMirrorV1Config(
                fetch_impl=limited
            ),
            request(),
        )
    )

    assert result.status == "unavailable"
    assert result.reason_code == (
        "HCS26_MIRROR_RATE_LIMITED"
    )

    async def oversized(
        url: str,
        headers: Mapping[str, str],
        timeout_ms: int,
        max_response_bytes: int,
    ) -> HederaMirrorFetchResponseV1:
        del url
        del headers
        del timeout_ms

        return HederaMirrorFetchResponseV1(
            status=200,
            headers={
                "content-length": str(
                    max_response_bytes + 1
                )
            },
            body=b"{}",
        )

    result = run(
        read_hcs26_registry_message_v1(
            HederaMirrorV1Config(
                fetch_impl=oversized
            ),
            request(),
        )
    )

    assert result.status == "unavailable"
    assert result.reason_code == (
        "HCS26_MIRROR_RESPONSE_TOO_LARGE"
    )


def test_validates_locator_base_and_bounds_before_fetch() -> None:
    calls: list[str] = []

    async def fetch(
        url: str,
        headers: Mapping[str, str],
        timeout_ms: int,
        max_response_bytes: int,
    ) -> HederaMirrorFetchResponseV1:
        del headers
        del timeout_ms
        del max_response_bytes

        calls.append(url)
        raise AssertionError(
            "Fetch must not run"
        )

    with pytest.raises(
        TypeError,
        match="HCS26_REGISTRY_LOCATOR_INVALID",
    ):
        run(
            read_hcs26_registry_message_v1(
                HederaMirrorV1Config(
                    fetch_impl=fetch
                ),
                request(
                    topic_id=(
                        "https://evil.example"
                    )
                ),
            )
        )

    with pytest.raises(
        TypeError,
        match="HCS26_MIRROR_BASE_URL_INVALID",
    ):
        run(
            read_hcs26_registry_message_v1(
                HederaMirrorV1Config(
                    fetch_impl=fetch,
                    base_urls={
                        "testnet": (
                            "http://evil.example/api/v1"
                        ),
                    },
                ),
                request(),
            )
        )

    with pytest.raises(
        TypeError,
        match="HCS26_MIRROR_BOUNDS_INVALID",
    ):
        run(
            read_hcs26_registry_message_v1(
                HederaMirrorV1Config(
                    fetch_impl=fetch,
                    timeout_ms=100,
                ),
                request(),
            )
        )

    assert calls == []