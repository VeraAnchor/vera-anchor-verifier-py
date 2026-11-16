import asyncio
import base64
import hashlib
import json
from collections.abc import Mapping

import pytest

from vera_anchor_verifier.resolvers.hcs1_mirror_v1 import (
    Hcs1MirrorV1Config,
    Hcs1MirrorV1Request,
    resolve_hcs1_file_v1,
)
from vera_anchor_verifier.resolvers.hedera_mirror_v1 import (
    HederaMirrorFetchResponseV1,
)
from vera_anchor_verifier.standards.hcs.hcs1_v1 import (
    Hcs1V1ContentOptions,
)

TOPIC = "0.0.10765268"
REFERENCE = f"hcs://1/{TOPIC}"
MIRROR = (
    "https://testnet.mirrornode.hedera.com/api/v1"
)

CONTENT = (
    b'{"name":"SAGE","version":"1.0.0"}'
)
COMPRESSED = b"hcs1-zstd-fixture"
SHA256 = hashlib.sha256(
    CONTENT
).hexdigest()
MEMO = (
    f"{SHA256}:zstd:base64"
)


def run(coro):
    return asyncio.run(
        coro
    )


def chunk(
    order: int,
    content: str,
) -> bytes:
    return json.dumps(
        {
            "o": order,
            "c": content,
        },
        separators=(",", ":"),
    ).encode("utf-8")


ENCODED = base64.b64encode(
    COMPRESSED
).decode("ascii")

FIRST = chunk(
    0,
    (
        "data:application/json;"
        f"base64,{ENCODED[:8]}"
    ),
)
SECOND = chunk(
    1,
    ENCODED[8:],
)


def topic_json(
    *,
    admin_key: object = None,
) -> dict[str, object]:
    return {
        "topic_id": TOPIC,
        "memo": MEMO,
        "submit_key": {
            "key": "present",
        },
        "admin_key": admin_key,
    }


def messages_json(
    *,
    next_link: object = None,
) -> dict[str, object]:
    return {
        "messages": [
            {
                "topic_id": TOPIC,
                "sequence_number": 1,
                "message": (
                    base64.b64encode(
                        FIRST
                    ).decode("ascii")
                ),
            },
            {
                "topic_id": TOPIC,
                "sequence_number": 2,
                "message": (
                    base64.b64encode(
                        SECOND
                    ).decode("ascii")
                ),
            },
        ],
        "links": {
            "next": next_link,
        },
    }


def response(
    value: object,
    *,
    status: int = 200,
) -> HederaMirrorFetchResponseV1:
    return HederaMirrorFetchResponseV1(
        status=status,
        headers={
            "content-type": (
                "application/json"
            ),
        },
        body=(
            json.dumps(
                value,
                separators=(",", ":"),
            ).encode("utf-8")
        ),
    )


def decode_options(
) -> Hcs1V1ContentOptions:
    def decompress(
        compressed: bytes,
        limit: int,
    ) -> bytes:
        assert compressed == COMPRESSED
        assert limit >= len(CONTENT)
        return CONTENT

    return Hcs1V1ContentOptions(
        decompress_zstd=decompress
    )


def test_resolves_fixed_topic_and_verifies_content() -> None:
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
        assert 1 <= timeout_ms <= 8_000
        assert (
            max_response_bytes
            == 2 * 1024 * 1024
        )

        if url == (
            f"{MIRROR}/topics/{TOPIC}"
        ):
            return response(
                topic_json()
            )

        if url == (
            f"{MIRROR}/topics/{TOPIC}"
            "/messages?limit=100&order=asc"
        ):
            return response(
                messages_json()
            )

        raise AssertionError(
            f"Unexpected URL: {url}"
        )

    result = run(
        resolve_hcs1_file_v1(
            Hcs1MirrorV1Config(
                fetch_impl=fetch
            ),
            Hcs1MirrorV1Request(
                reference=REFERENCE,
                network="testnet",
                expected_sha256=SHA256,
            ),
            decode_options(),
        )
    )

    assert result.status == "resolved"
    assert result.reason_code is None
    assert result.hedera_network == (
        "testnet"
    )
    assert result.resolver_id == (
        "hedera.mirror-rest.hcs1.v1"
    )
    assert result.verification is not None
    assert (
        result.verification.sha256
        == SHA256
    )
    assert (
        result.verification.bytes
        == CONTENT
    )
    assert len(calls) == 2


def test_rejects_cross_origin_pagination_without_fetching_it() -> None:
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

        if "/messages?" in url:
            return response(
                messages_json(
                    next_link=(
                        "https://evil.example/"
                        "private"
                    )
                )
            )

        return response(
            topic_json()
        )

    result = run(
        resolve_hcs1_file_v1(
            Hcs1MirrorV1Config(
                fetch_impl=fetch
            ),
            Hcs1MirrorV1Request(
                reference=REFERENCE,
                network="testnet",
            ),
            decode_options(),
        )
    )

    assert result.status == "invalid"
    assert result.reason_code == (
        "HCS1_MIRROR_PAGINATION_INVALID"
    )
    assert len(calls) == 2
    assert not any(
        "evil.example" in url
        for url in calls
    )


def test_requires_explicit_links_next_shape() -> None:
    async def fetch(
        url: str,
        headers: Mapping[str, str],
        timeout_ms: int,
        max_response_bytes: int,
    ) -> HederaMirrorFetchResponseV1:
        del headers
        del timeout_ms
        del max_response_bytes

        if "/messages?" in url:
            value = messages_json()
            value.pop("links")
            return response(value)

        return response(
            topic_json()
        )

    result = run(
        resolve_hcs1_file_v1(
            Hcs1MirrorV1Config(
                fetch_impl=fetch
            ),
            Hcs1MirrorV1Request(
                reference=REFERENCE,
                network="testnet",
            ),
            decode_options(),
        )
    )

    assert result.status == "invalid"
    assert result.reason_code == (
        "HCS1_MIRROR_PAGINATION_INVALID"
    )


def test_distinguishes_not_found_and_mutable_topic() -> None:
    async def absent(
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

    missing = run(
        resolve_hcs1_file_v1(
            Hcs1MirrorV1Config(
                fetch_impl=absent
            ),
            Hcs1MirrorV1Request(
                reference=REFERENCE,
                network="testnet",
            ),
            decode_options(),
        )
    )

    assert missing.status == (
        "unavailable"
    )
    assert missing.reason_code == (
        "HCS1_TOPIC_NOT_FOUND"
    )

    async def mutable(
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
            topic_json(
                admin_key={
                    "key": "present",
                }
            )
        )

    invalid = run(
        resolve_hcs1_file_v1(
            Hcs1MirrorV1Config(
                fetch_impl=mutable
            ),
            Hcs1MirrorV1Request(
                reference=REFERENCE,
                network="testnet",
            ),
            decode_options(),
        )
    )

    assert invalid.status == "invalid"
    assert invalid.reason_code == (
        "HCS1_TOPIC_METADATA_INVALID"
    )


def test_detects_non_monotonic_message_sequence() -> None:
    async def fetch(
        url: str,
        headers: Mapping[str, str],
        timeout_ms: int,
        max_response_bytes: int,
    ) -> HederaMirrorFetchResponseV1:
        del headers
        del timeout_ms
        del max_response_bytes

        if "/messages?" not in url:
            return response(
                topic_json()
            )

        value = messages_json()
        raw_messages = value[
            "messages"
        ]
        assert isinstance(
            raw_messages,
            list,
        )

        second = raw_messages[1]
        assert isinstance(
            second,
            dict,
        )
        second["sequence_number"] = 1

        return response(value)

    result = run(
        resolve_hcs1_file_v1(
            Hcs1MirrorV1Config(
                fetch_impl=fetch
            ),
            Hcs1MirrorV1Request(
                reference=REFERENCE,
                network="testnet",
            ),
            decode_options(),
        )
    )

    assert result.status == "invalid"
    assert result.reason_code == (
        "HCS1_MIRROR_MESSAGE_INVALID"
    )


def test_expected_checksum_mismatch_is_conflict() -> None:
    async def fetch(
        url: str,
        headers: Mapping[str, str],
        timeout_ms: int,
        max_response_bytes: int,
    ) -> HederaMirrorFetchResponseV1:
        del headers
        del timeout_ms
        del max_response_bytes

        if "/messages?" in url:
            return response(
                messages_json()
            )

        return response(
            topic_json()
        )

    result = run(
        resolve_hcs1_file_v1(
            Hcs1MirrorV1Config(
                fetch_impl=fetch
            ),
            Hcs1MirrorV1Request(
                reference=REFERENCE,
                network="testnet",
                expected_sha256=(
                    "a" * 64
                ),
            ),
            decode_options(),
        )
    )

    assert result.status == "conflict"
    assert result.reason_code == (
        "HCS1_EXPECTED_CHECKSUM_MISMATCH"
    )
    assert result.verification is not None


def test_rejects_untrusted_base_and_invalid_limits() -> None:
    with pytest.raises(
        TypeError,
        match=(
            "fixed HTTPS /api/v1 endpoint"
        ),
    ):
        run(
            resolve_hcs1_file_v1(
                Hcs1MirrorV1Config(
                    base_urls={
                        "testnet": (
                            "http://evil.example/"
                            "api/v1"
                        ),
                    },
                ),
                Hcs1MirrorV1Request(
                    reference=REFERENCE,
                    network="testnet",
                ),
                decode_options(),
            )
        )

    with pytest.raises(
        TypeError,
        match=(
            "Invalid HCS-1 Mirror "
            "read limits"
        ),
    ):
        run(
            resolve_hcs1_file_v1(
                Hcs1MirrorV1Config(
                    timeout_ms=100,
                ),
                Hcs1MirrorV1Request(
                    reference=REFERENCE,
                    network="testnet",
                ),
                decode_options(),
            )
        )


def test_rejects_pagination_query_expansion() -> None:
    async def fetch(
        url: str,
        headers: Mapping[str, str],
        timeout_ms: int,
        max_response_bytes: int,
    ) -> HederaMirrorFetchResponseV1:
        del headers
        del timeout_ms
        del max_response_bytes

        if "/messages?" in url:
            return response(
                messages_json(
                    next_link=(
                        f"{MIRROR}/topics/"
                        f"{TOPIC}/messages"
                        "?limit=100&order=asc"
                        "&url=https://evil.example"
                    )
                )
            )

        return response(
            topic_json()
        )

    result = run(
        resolve_hcs1_file_v1(
            Hcs1MirrorV1Config(
                fetch_impl=fetch
            ),
            Hcs1MirrorV1Request(
                reference=REFERENCE,
                network="testnet",
            ),
            decode_options(),
        )
    )

    assert result.status == "invalid"
    assert result.reason_code == (
        "HCS1_MIRROR_PAGINATION_INVALID"
    )