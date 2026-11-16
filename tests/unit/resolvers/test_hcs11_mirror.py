import asyncio
import base64
import hashlib
import json
from collections.abc import Mapping

import pytest

from vera_anchor_verifier.resolvers.hcs1_mirror_v1 import Hcs1MirrorV1Config
from vera_anchor_verifier.resolvers.hcs11_mirror_v1 import (
    Hcs11MirrorV1Request,
    resolve_hcs11_profile_v1,
)
from vera_anchor_verifier.resolvers.hedera_mirror_v1 import (
    HederaMirrorFetchResponseV1,
)
from vera_anchor_verifier.standards.hcs.hcs1_v1 import Hcs1V1ContentOptions
from vera_anchor_verifier.standards.hcs.hcs11_v1 import Hcs11V1Error

BASE = "https://testnet.mirrornode.hedera.com/api/v1"
MAINNET_BASE = "https://mainnet-public.mirrornode.hedera.com/api/v1"

ACCOUNT = "0.0.10738880"
REGISTRY = "0.0.10765269"
PROFILE_TOPIC = "0.0.10765268"
SEQUENCE = 1

DID = "did:web:agents.example.org"

UAID = (
    "uaid:did:agents.example.org;"
    "uid=lab;"
    "registry=self;"
    "proto=hcs-26;"
    f"nativeId=hedera:testnet:{ACCOUNT}"
)

PROFILE = (
    '{"aiAgent":{"capabilities":[0,7],'
    '"model":"lab-model","type":1},'
    '"display_name":"Lab Agent",'
    '"type":1,'
    f'"uaid":"{UAID}",'
    '"version":"1.1"}'
)

CHECKSUM = hashlib.sha256(PROFILE.encode("utf-8")).hexdigest()

DIRECT_MEMO = f"hcs-11:hcs://1/{PROFILE_TOPIC}"
REGISTRY_MEMO = f"hcs-11:hcs://2/{REGISTRY}"


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


def request(**overrides: object) -> Hcs11MirrorV1Request:
    values: dict[str, object] = {
        "hedera_network": "testnet",
        "account_id": ACCOUNT,
    }
    values.update(overrides)
    return Hcs11MirrorV1Request(**values)  # type: ignore[arg-type]


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
    mode: str = "registry",
    *,
    account_memo: str | None = None,
    account_id: str | None = None,
    target: str | None = None,
    canonical_profile: str | None = None,
    registry_sequence: int | None = None,
    registry_memo: str | None = None,
    file_memo: str | None = None,
):
    urls: list[str] = []

    raw_profile = canonical_profile if canonical_profile is not None else PROFILE
    file_bytes = raw_profile.encode("utf-8")

    chunk = json.dumps(
        {
            "o": 0,
            "c": f"data:application/json;base64,{b64(file_bytes)}",
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

        if url == f"{BASE}/accounts/{ACCOUNT}":
            observed_memo = (
                account_memo
                if account_memo is not None
                else REGISTRY_MEMO
                if mode == "registry"
                else DIRECT_MEMO
            )
            return response(
                {
                    "account": account_id if account_id is not None else ACCOUNT,
                    "memo_base64": b64(observed_memo),
                    "deleted": False,
                }
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
                    "t_id": target if target is not None else PROFILE_TOPIC,
                },
                separators=(",", ":"),
            )
            return response(
                {
                    "topic_id": REGISTRY,
                    "sequence_number": (
                        registry_sequence
                        if registry_sequence is not None
                        else SEQUENCE
                    ),
                    "consensus_timestamp": "1792039124.000000003",
                    "message": b64(register),
                }
            )

        if url == f"{BASE}/topics/{PROFILE_TOPIC}":
            return response(
                {
                    "topic_id": PROFILE_TOPIC,
                    "memo": (
                        file_memo
                        if file_memo is not None
                        else (
                            f"{hashlib.sha256(file_bytes).hexdigest()}"
                            ":zstd:base64"
                        )
                    ),
                    "submit_key": {"key": "present"},
                    "admin_key": None,
                }
            )

        if url == (
            f"{BASE}/topics/{PROFILE_TOPIC}"
            "/messages?limit=100&order=asc"
        ):
            return response(
                {
                    "messages": [
                        {
                            "topic_id": PROFILE_TOPIC,
                            "sequence_number": 1,
                            "message": b64(chunk),
                        },
                    ],
                    "links": {"next": None},
                }
            )

        raise AssertionError(f"Unexpected Mirror request: {url}")

    return fetch, urls


def test_resolves_historical_hcs2_then_hcs1_profile() -> None:
    fetch, urls = fixture()

    result = run(
        resolve_hcs11_profile_v1(
            Hcs1MirrorV1Config(fetch_impl=fetch),
            request(
                hcs2_sequence_number=SEQUENCE,
                expected_profile_reference=f"hcs://2/{REGISTRY}",
                expected_hcs1_reference=f"hcs://1/{PROFILE_TOPIC}",
                expected_hcs1_sha256=CHECKSUM,
                expected_profile_sha256=CHECKSUM,
                expected_uaid=UAID,
                expected_base_did=DID,
            ),
            decode_options(),
        )
    )

    assert result.status == "resolved"
    assert result.reason_code is None
    assert result.account_memo_temporal_scope == "current_observation"
    assert result.profile_reference == f"hcs://1/{PROFILE_TOPIC}"
    assert result.content_sha256 == CHECKSUM
    assert result.canonical_profile_sha256 == CHECKSUM
    assert result.did_binding == "match"

    assert result.account_memo is not None
    assert result.account_memo.protocol == "hcs-2"
    assert result.account_memo.topic_id == REGISTRY

    assert result.registry_entry is not None
    assert result.registry_entry.topic_id == REGISTRY
    assert result.registry_entry.sequence_number == SEQUENCE
    assert (
        result.registry_entry.consensus_timestamp
        == "1792039124.000000003"
    )

    assert result.profile is not None
    assert result.profile.uaid == UAID

    assert urls == [
        f"{BASE}/accounts/{ACCOUNT}",
        f"{BASE}/topics/{REGISTRY}",
        f"{BASE}/topics/{REGISTRY}/messages/{SEQUENCE}",
        f"{BASE}/topics/{PROFILE_TOPIC}",
        (
            f"{BASE}/topics/{PROFILE_TOPIC}"
            "/messages?limit=100&order=asc"
        ),
    ]


def test_direct_hcs1_route_skips_hcs2() -> None:
    fetch, urls = fixture("direct")

    result = run(
        resolve_hcs11_profile_v1(
            Hcs1MirrorV1Config(fetch_impl=fetch),
            request(expected_hcs1_sha256=CHECKSUM),
            decode_options(),
        )
    )

    assert result.status == "resolved"
    assert result.registry_entry is None
    assert result.account_memo is not None
    assert result.account_memo.protocol == "hcs-1"
    assert result.did_binding == "not_checked"
    assert len(urls) == 3


def test_requires_explicit_hcs2_sequence_without_registry_fetch() -> None:
    fetch, urls = fixture()

    result = run(
        resolve_hcs11_profile_v1(
            Hcs1MirrorV1Config(fetch_impl=fetch),
            request(),
            decode_options(),
        )
    )

    assert result.status == "unavailable"
    assert result.reason_code == "HCS11_HCS2_SEQUENCE_REQUIRED"
    assert urls == [f"{BASE}/accounts/{ACCOUNT}"]


def test_rejects_hcs2_sequence_for_direct_reference() -> None:
    fetch, urls = fixture("direct")

    result = run(
        resolve_hcs11_profile_v1(
            Hcs1MirrorV1Config(fetch_impl=fetch),
            request(hcs2_sequence_number=SEQUENCE),
            decode_options(),
        )
    )

    assert result.status == "invalid"
    assert result.reason_code == "HCS11_HCS2_SEQUENCE_NOT_APPLICABLE"
    assert len(urls) == 1


def test_rejects_expected_account_reference_before_further_reads() -> None:
    fetch, urls = fixture()

    result = run(
        resolve_hcs11_profile_v1(
            Hcs1MirrorV1Config(fetch_impl=fetch),
            request(
                hcs2_sequence_number=SEQUENCE,
                expected_profile_reference=f"hcs://1/{PROFILE_TOPIC}",
            ),
            decode_options(),
        )
    )

    assert result.status == "conflict"
    assert result.reason_code == "HCS11_ACCOUNT_REFERENCE_MISMATCH"
    assert len(urls) == 1


def test_rejects_account_scope_mismatch() -> None:
    fetch, urls = fixture(
        "direct",
        account_id="0.0.999",
    )

    result = run(
        resolve_hcs11_profile_v1(
            Hcs1MirrorV1Config(fetch_impl=fetch),
            request(),
            decode_options(),
        )
    )

    assert result.status == "invalid"
    assert result.reason_code == "HCS11_ACCOUNT_SCOPE_MISMATCH"
    assert len(urls) == 1


def test_rejects_historical_target_substitution() -> None:
    fetch, urls = fixture(
        "registry",
        target="0.0.999",
    )

    result = run(
        resolve_hcs11_profile_v1(
            Hcs1MirrorV1Config(fetch_impl=fetch),
            request(
                hcs2_sequence_number=SEQUENCE,
                expected_hcs1_reference=f"hcs://1/{PROFILE_TOPIC}",
            ),
            decode_options(),
        )
    )

    assert result.status == "conflict"
    assert result.reason_code == "HCS2_TARGET_MISMATCH"
    assert len(urls) == 3


def test_hcs1_topic_memo_checksum_disagreement_is_invalid() -> None:
    fetch, _urls = fixture(
        "direct",
        file_memo=f"{'a' * 64}:zstd:base64",
    )

    result = run(
        resolve_hcs11_profile_v1(
            Hcs1MirrorV1Config(fetch_impl=fetch),
            request(),
            decode_options(),
        )
    )

    assert result.status == "invalid"
    assert result.reason_code == "HCS1_CHECKSUM_MISMATCH"
    assert result.profile is None


def test_expected_hcs1_checksum_disagreement_is_conflict() -> None:
    fetch, _urls = fixture("direct")

    result = run(
        resolve_hcs11_profile_v1(
            Hcs1MirrorV1Config(fetch_impl=fetch),
            request(expected_hcs1_sha256="a" * 64),
            decode_options(),
        )
    )

    assert result.status == "conflict"
    assert result.reason_code == "HCS1_EXPECTED_CHECKSUM_MISMATCH"


def test_noncanonical_profile_content_is_unsupported() -> None:
    noncanonical = json.dumps(
        {
            "version": "1.1",
            "type": 1,
            "display_name": "Lab Agent",
            "uaid": UAID,
            "aiAgent": {
                "model": "lab-model",
                "type": 1,
                "capabilities": [0, 7],
            },
        },
        separators=(",", ":"),
    )

    fetch, _urls = fixture(
        "direct",
        canonical_profile=noncanonical,
    )

    result = run(
        resolve_hcs11_profile_v1(
            Hcs1MirrorV1Config(fetch_impl=fetch),
            request(),
            decode_options(),
        )
    )

    assert result.status == "unsupported"
    assert result.reason_code == "HCS11_PROFILE_CONTENT_NOT_CANONICAL"
    assert result.canonical_profile_sha256 == CHECKSUM
    assert result.content_sha256 != CHECKSUM


def test_expected_uaid_mismatch_is_conflict() -> None:
    fetch, _urls = fixture("direct")

    mismatched = UAID.replace(
        "uid=lab",
        "uid=other",
    )

    result = run(
        resolve_hcs11_profile_v1(
            Hcs1MirrorV1Config(fetch_impl=fetch),
            request(expected_uaid=mismatched),
            decode_options(),
        )
    )

    assert result.status == "conflict"
    assert result.reason_code == "HCS11_UAID_MISMATCH"


def test_missing_rate_limited_and_invalid_account_responses() -> None:
    async def missing(
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

    unavailable = run(
        resolve_hcs11_profile_v1(
            Hcs1MirrorV1Config(fetch_impl=missing),
            request(),
            decode_options(),
        )
    )

    assert unavailable.status == "unavailable"
    assert unavailable.reason_code == "HCS11_ACCOUNT_NOT_FOUND"

    async def rate_limited(
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

    limited = run(
        resolve_hcs11_profile_v1(
            Hcs1MirrorV1Config(fetch_impl=rate_limited),
            request(),
            decode_options(),
        )
    )

    assert limited.status == "unavailable"
    assert limited.reason_code == "HCS11_ACCOUNT_RATE_LIMITED"

    async def invalid(
        url: str,
        headers: Mapping[str, str],
        timeout_ms: int,
        max_response_bytes: int,
    ) -> HederaMirrorFetchResponseV1:
        del url
        del headers
        del timeout_ms
        del max_response_bytes
        return response([])

    bad = run(
        resolve_hcs11_profile_v1(
            Hcs1MirrorV1Config(fetch_impl=invalid),
            request(),
            decode_options(),
        )
    )

    assert bad.status == "invalid"
    assert bad.reason_code == "HCS11_ACCOUNT_RESPONSE_INVALID"


def test_validates_request_and_base_before_network_calls() -> None:
    fetch, urls = fixture("direct")

    with pytest.raises(
        TypeError,
        match="HCS11_ACCOUNT_LOCATOR_INVALID",
    ):
        run(
            resolve_hcs11_profile_v1(
                Hcs1MirrorV1Config(fetch_impl=fetch),
                request(
                    account_id="https://example.org/private",
                ),
                decode_options(),
            )
        )

    with pytest.raises(
        TypeError,
        match="HCS11_EXPECTED_SHA256_INVALID",
    ):
        run(
            resolve_hcs11_profile_v1(
                Hcs1MirrorV1Config(fetch_impl=fetch),
                request(
                    expected_hcs1_sha256="bad",
                ),
                decode_options(),
            )
        )

    with pytest.raises(
        Hcs11V1Error,
        match="HCS11_PROFILE_REF_INVALID",
    ):
        run(
            resolve_hcs11_profile_v1(
                Hcs1MirrorV1Config(fetch_impl=fetch),
                request(
                    expected_profile_reference="https://evil.example",
                ),
                decode_options(),
            )
        )

    with pytest.raises(
        TypeError,
        match="HCS11_MIRROR_BASE_URL_INVALID",
    ):
        run(
            resolve_hcs11_profile_v1(
                Hcs1MirrorV1Config(
                    fetch_impl=fetch,
                    base_urls={
                        "testnet": (
                            "http://evil.example/api/v1"
                        ),
                    },
                ),
                request(),
                decode_options(),
            )
        )

    assert urls == []


def test_preserves_native_uaid_network_scope() -> None:
    test_fetch, _urls = fixture("direct")

    async def mainnet_fetch(
        url: str,
        headers: Mapping[str, str],
        timeout_ms: int,
        max_response_bytes: int,
    ) -> HederaMirrorFetchResponseV1:
        translated = url.replace(
            MAINNET_BASE,
            BASE,
        )

        return await test_fetch(
            translated,
            headers,
            timeout_ms,
            max_response_bytes,
        )

    result = run(
        resolve_hcs11_profile_v1(
            Hcs1MirrorV1Config(
                fetch_impl=mainnet_fetch
            ),
            Hcs11MirrorV1Request(
                hedera_network="mainnet",
                account_id=ACCOUNT,
            ),
            decode_options(),
        )
    )

    assert result.status == "conflict"
    assert result.reason_code == "HCS11_UAID_NETWORK_MISMATCH"