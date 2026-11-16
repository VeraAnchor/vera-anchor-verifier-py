import asyncio
import base64
import json
from collections.abc import Mapping

import pytest

from vera_anchor_verifier.resolvers.hcs2_mirror_v1 import (
    Hcs2MirrorV1Request,
    resolve_hcs2_register_v1,
)
from vera_anchor_verifier.resolvers.hedera_mirror_v1 import (
    HederaMirrorFetchResponseV1,
    HederaMirrorV1Config,
)

REGISTRY = "0.0.10791100"
TARGET = "0.0.10765268"
NETWORK = "testnet"
SEQUENCE = 42
MEMO = "hcs-2:0:86400"

MIRROR = (
    "https://testnet.mirrornode.hedera.com/api/v1"
)


def run(coro):
    return asyncio.run(coro)


def raw(
    overrides: dict[
        str,
        object,
    ]
    | None = None,
) -> bytes:
    value: dict[
        str,
        object,
    ] = {
        "p": "hcs-2",
        "op": "register",
        "t_id": TARGET,
    }

    if overrides:
        value.update(
            overrides
        )

    return json.dumps(
        value,
        separators=(",", ":"),
    ).encode("utf-8")


def request(
    *,
    expected_t_id: (
        str | None
    ) = TARGET,
) -> Hcs2MirrorV1Request:
    return Hcs2MirrorV1Request(
        hedera_network=NETWORK,
        registry_topic_id=REGISTRY,
        sequence_number=SEQUENCE,
        expected_t_id=expected_t_id,
    )


def topic_row(
    *,
    memo: str = MEMO,
) -> dict[str, object]:
    return {
        "topic_id": REGISTRY,
        "memo": memo,
    }


def message_row(
) -> dict[str, object]:
    return {
        "topic_id": REGISTRY,
        "sequence_number": (
            SEQUENCE
        ),
        "consensus_timestamp": (
            "1792039124.000000003"
        ),
        "message": (
            base64.b64encode(
                raw()
            ).decode("ascii")
        ),
    }


def response(
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
        ).encode("utf-8"),
    )


def mirror_fetch(
    *,
    topic: object | None = None,
    message: object | None = None,
):
    topic_value = (
        topic_row()
        if topic is None
        else topic
    )
    message_value = (
        message_row()
        if message is None
        else message
    )

    async def fetch(
        url: str,
        headers: Mapping[str, str],
        timeout_ms: int,
        max_response_bytes: int,
    ) -> HederaMirrorFetchResponseV1:
        assert headers == {
            "Accept": "application/json",
        }
        assert (
            250
            <= timeout_ms
            <= 15_000
        )
        assert (
            max_response_bytes
            == 256 * 1024
        )

        if url == (
            f"{MIRROR}/topics/"
            f"{REGISTRY}"
        ):
            return response(
                topic_value
            )

        if url == (
            f"{MIRROR}/topics/"
            f"{REGISTRY}/messages/"
            f"{SEQUENCE}"
        ):
            return response(
                message_value
            )

        raise AssertionError(
            f"Unexpected URL: {url}"
        )

    return fetch


def test_resolves_exact_historical_register() -> None:
    result = run(
        resolve_hcs2_register_v1(
            HederaMirrorV1Config(
                fetch_impl=(
                    mirror_fetch()
                )
            ),
            request(),
        )
    )

    assert result.status == "resolved"
    assert result.reason_code is None
    assert (
        result.hedera_network
        == NETWORK
    )
    assert (
        result.registry_topic_id
        == REGISTRY
    )
    assert (
        result.sequence_number
        == SEQUENCE
    )
    assert (
        result.consensus_timestamp
        == "1792039124.000000003"
    )
    assert result.verification is not None
    assert (
        result.verification.target_match
        == "match"
    )
    assert (
        result.verification.register
        is not None
    )
    assert (
        result.verification.register.t_id
        == TARGET
    )


def test_accepts_base64_encoded_topic_memo() -> None:
    encoded = base64.b64encode(
        MEMO.encode("utf-8")
    ).decode("ascii")

    result = run(
        resolve_hcs2_register_v1(
            HederaMirrorV1Config(
                fetch_impl=mirror_fetch(
                    topic=topic_row(
                        memo=encoded
                    )
                )
            ),
            request(),
        )
    )

    assert result.verification is not None
    assert result.verification.memo is not None
    assert (
        result.verification.memo.indexed
        is True
    )
    assert (
        result.verification.memo.ttl
        == 86400
    )


def test_distinguishes_target_conflict_from_invalid_register() -> None:
    conflict = run(
        resolve_hcs2_register_v1(
            HederaMirrorV1Config(
                fetch_impl=(
                    mirror_fetch()
                )
            ),
            request(
                expected_t_id=(
                    "0.0.999"
                )
            ),
        )
    )

    assert (
        conflict.status
        == "conflict"
    )
    assert conflict.reason_code == (
        "HCS2_TARGET_MISMATCH"
    )

    malformed_row = (
        message_row()
    )
    malformed_row["message"] = (
        base64.b64encode(
            raw(
                {
                    "op": "delete",
                }
            )
        ).decode("ascii")
    )

    malformed = run(
        resolve_hcs2_register_v1(
            HederaMirrorV1Config(
                fetch_impl=mirror_fetch(
                    message=(
                        malformed_row
                    )
                )
            ),
            request(),
        )
    )

    assert malformed.status == "invalid"
    assert malformed.reason_code == (
        "HCS2_OPERATION_INVALID"
    )


@pytest.mark.parametrize(
    "row",
    [
        {
            **message_row(),
            "topic_id": "0.0.999",
        },
        {
            **message_row(),
            "sequence_number": (
                SEQUENCE + 1
            ),
        },
        {
            **message_row(),
            "chunk_info": {
                "total": 2,
                "number": 1,
            },
        },
    ],
)
def test_rejects_message_scope_mismatch(
    row: dict[str, object],
) -> None:
    result = run(
        resolve_hcs2_register_v1(
            HederaMirrorV1Config(
                fetch_impl=mirror_fetch(
                    message=row
                )
            ),
            request(),
        )
    )

    assert result.status == "invalid"
    assert result.reason_code == (
        "HCS2_MESSAGE_SCOPE_INVALID"
    )


def test_distinguishes_missing_and_rate_limited() -> None:
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

        return (
            HederaMirrorFetchResponseV1(
                status=404,
                headers={},
                body=b"",
            )
        )

    absent = run(
        resolve_hcs2_register_v1(
            HederaMirrorV1Config(
                fetch_impl=missing
            ),
            request(),
        )
    )

    assert (
        absent.status
        == "unavailable"
    )
    assert absent.reason_code == (
        "HCS2_REGISTRY_NOT_FOUND"
    )

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

        return (
            HederaMirrorFetchResponseV1(
                status=429,
                headers={},
                body=b"",
            )
        )

    limited = run(
        resolve_hcs2_register_v1(
            HederaMirrorV1Config(
                fetch_impl=(
                    rate_limited
                )
            ),
            request(),
        )
    )

    assert (
        limited.status
        == "unavailable"
    )
    assert limited.reason_code == (
        "HCS2_MIRROR_RATE_LIMITED"
    )


def test_rejects_invalid_locator_and_untrusted_base() -> None:
    calls = 0

    async def fetch(
        url: str,
        headers: Mapping[str, str],
        timeout_ms: int,
        max_response_bytes: int,
    ) -> HederaMirrorFetchResponseV1:
        nonlocal calls
        calls += 1

        del url
        del headers
        del timeout_ms
        del max_response_bytes

        raise AssertionError(
            "fetch must not execute"
        )

    with pytest.raises(
        TypeError,
        match=(
            "HCS2_REGISTRY_LOCATOR_INVALID"
        ),
    ):
        run(
            resolve_hcs2_register_v1(
                HederaMirrorV1Config(
                    fetch_impl=fetch
                ),
                Hcs2MirrorV1Request(
                    hedera_network=(
                        NETWORK
                    ),
                    registry_topic_id=(
                        "0.0.5/../../private"
                    ),
                    sequence_number=(
                        SEQUENCE
                    ),
                    expected_t_id=TARGET,
                ),
            )
        )

    with pytest.raises(
        TypeError,
        match=(
            "HCS2_MIRROR_BASE_URL_INVALID"
        ),
    ):
        run(
            resolve_hcs2_register_v1(
                HederaMirrorV1Config(
                    fetch_impl=fetch,
                    base_urls={
                        "testnet": (
                            "http://example.com/"
                            "api/v1"
                        ),
                    },
                ),
                request(),
            )
        )

    assert calls == 0


def test_does_not_invent_target_or_current_state() -> None:
    result = run(
        resolve_hcs2_register_v1(
            HederaMirrorV1Config(
                fetch_impl=(
                    mirror_fetch()
                )
            ),
            request(
                expected_t_id=None
            ),
        )
    )

    assert result.status == "resolved"
    assert result.verification is not None
    assert (
        result.verification.target_match
        == "not_checked"
    )
    assert not hasattr(
        result,
        "current_registry_state",
    )
    assert not hasattr(
        result,
        "consensus_authenticated",
    )