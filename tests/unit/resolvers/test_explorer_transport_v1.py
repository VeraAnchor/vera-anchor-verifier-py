import asyncio
from dataclasses import dataclass, field
from typing import Any

import pytest

from vera_anchor_verifier.resolvers.explorer_transport_v1 import (
    MAX_EXPLORER_RESPONSE_BYTES,
    ExplorerFetchResponseV1,
    ExplorerPublicTransportV1,
    read_explorer_public_v1,
)


def run[T](coro) -> T:
    return asyncio.run(coro)


@dataclass
class FakeFetch:
    response: ExplorerFetchResponseV1 | None = None
    error: Exception | None = None
    calls: list[dict[str, Any]] = field(default_factory=list)

    async def __call__(
        self,
        url: str,
        method: str,
        headers: dict[str, str],
        body: bytes | None,
        timeout_ms: int,
        max_response_bytes: int,
    ) -> ExplorerFetchResponseV1:
        self.calls.append(
            {
                "url": url,
                "method": method,
                "headers": dict(headers),
                "body": body,
                "timeout_ms": timeout_ms,
                "max_response_bytes": max_response_bytes,
            }
        )

        if self.error is not None:
            raise self.error

        assert self.response is not None
        return self.response


def response(
    body: bytes = b'{"ok":true}',
    *,
    status: int = 200,
    headers: dict[str, str] | None = None,
) -> ExplorerFetchResponseV1:
    return ExplorerFetchResponseV1(
        status=status,
        headers=headers or {},
        body=body,
    )


def config(fetch: FakeFetch) -> ExplorerPublicTransportV1:
    return ExplorerPublicTransportV1(
        base_url="https://explorer.example",
        fetch_impl=fetch,
    )


def test_get_is_network_scoped_and_credential_free() -> None:
    fetch = FakeFetch(response())
    result = run(
        read_explorer_public_v1(
            config(fetch),
            "/v1/datasets/dataset.alpha",
            "testnet",
        )
    )

    assert result.status == "ok"
    assert result.body == {"ok": True}

    call = fetch.calls[0]
    assert call["url"] == (
        "https://explorer.example/v1/datasets/"
        "dataset.alpha?network=testnet"
    )
    assert call["method"] == "GET"
    assert call["headers"] == {
        "Accept": "application/json",
    }
    assert call["body"] is None


def test_result_id_is_normalized_and_network_scoped() -> None:
    fetch = FakeFetch(response())
    result_id = "ABCDEF12-3456-7890-ABCD-EF1234567890"

    run(
        read_explorer_public_v1(
            config(fetch),
            "/v1/results/public",
            "mainnet",
            query={"resultId": result_id},
        )
    )

    assert fetch.calls[0]["url"] == (
        "https://explorer.example/v1/results/public"
        "?resultId=abcdef12-3456-7890-abcd-ef1234567890"
        "&network=mainnet"
    )


def test_post_uses_json_and_does_not_append_network() -> None:
    fetch = FakeFetch(response())

    run(
        read_explorer_public_v1(
            config(fetch),
            "/v1/hcs/verify",
            "testnet",
            post_body={"network": "testnet", "value": 1},
        )
    )

    call = fetch.calls[0]

    assert call["url"] == (
        "https://explorer.example/v1/hcs/verify"
    )
    assert call["method"] == "POST"
    assert call["headers"] == {
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    assert call["body"] == b'{"network":"testnet","value":1}'


@pytest.mark.parametrize(
    "base_url",
    [
        "http://explorer.example",
        "https://user:pass@explorer.example",
        "https://explorer.example/path",
        "https://explorer.example/?query=1",
        "https://explorer.example/#fragment",
    ],
)
def test_base_url_restrictions_fail_closed(base_url: str) -> None:
    fetch = FakeFetch(response())

    with pytest.raises(TypeError):
        run(
            read_explorer_public_v1(
                ExplorerPublicTransportV1(
                    base_url=base_url,
                    fetch_impl=fetch,
                ),
                "/v1/datasets/dataset.alpha",
                "testnet",
            )
        )


@pytest.mark.parametrize(
    "base_url",
    [
        "http://localhost:8000",
        "http://127.0.0.1:8000/v1",
        "http://[::1]:8000/v1/",
    ],
)
def test_http_is_permitted_only_for_loopback(
    base_url: str,
) -> None:
    fetch = FakeFetch(response())

    result = run(
        read_explorer_public_v1(
            ExplorerPublicTransportV1(
                base_url=base_url,
                fetch_impl=fetch,
            ),
            "/v1/datasets/dataset.alpha",
            "testnet",
        )
    )

    assert result.status == "ok"


@pytest.mark.parametrize(
    "path",
    [
        "/datasets/x",
        "/v1/../secret",
        "/v1/",
        "https://evil.example/v1/x",
    ],
)
def test_only_fixed_v1_paths_are_allowed(path: str) -> None:
    fetch = FakeFetch(response())

    with pytest.raises(
        TypeError,
        match="Invalid fixed Explorer API path",
    ):
        run(
            read_explorer_public_v1(
                config(fetch),
                path,
                "testnet",
            )
        )


@pytest.mark.parametrize(
    ("timeout", "budget"),
    [
        (99, 1024),
        (60_001, 1024),
        (1000, 1023),
        (1000, MAX_EXPLORER_RESPONSE_BYTES + 1),
        (True, 1024),
    ],
)
def test_request_bounds_fail_closed(
    timeout: object,
    budget: object,
) -> None:
    fetch = FakeFetch(response())

    with pytest.raises(TypeError):
        run(
            read_explorer_public_v1(
                ExplorerPublicTransportV1(
                    base_url="https://explorer.example",
                    fetch_impl=fetch,
                    timeout_ms=timeout,  # type: ignore[arg-type]
                    max_response_bytes=budget,  # type: ignore[arg-type]
                ),
                "/v1/datasets/x",
                "testnet",
            )
        )


def test_query_and_post_body_are_mutually_exclusive() -> None:
    fetch = FakeFetch(response())

    with pytest.raises(
        TypeError,
        match="cannot accompany POST body",
    ):
        run(
            read_explorer_public_v1(
                config(fetch),
                "/v1/results/public",
                "testnet",
                post_body={"value": 1},
                query={
                    "resultId": (
                        "abcdef12-3456-7890-abcd-ef1234567890"
                    )
                },
            )
        )


@pytest.mark.parametrize(
    ("status", "expected", "reason"),
    [
        (404, "not_found", "EXPLORER_NOT_FOUND"),
        (401, "unavailable", "EXPLORER_HTTP_UNAVAILABLE"),
        (429, "unavailable", "EXPLORER_HTTP_UNAVAILABLE"),
        (500, "unavailable", "EXPLORER_HTTP_UNAVAILABLE"),
    ],
)
def test_http_statuses_are_normalized(
    status: int,
    expected: str,
    reason: str,
) -> None:
    fetch = FakeFetch(response(status=status))

    result = run(
        read_explorer_public_v1(
            config(fetch),
            "/v1/datasets/x",
            "testnet",
        )
    )

    assert (result.status, result.reason_code) == (
        expected,
        reason,
    )
    assert result.body is None


def test_transport_failure_is_unavailable() -> None:
    fetch = FakeFetch(error=OSError("network down"))

    result = run(
        read_explorer_public_v1(
            config(fetch),
            "/v1/datasets/x",
            "testnet",
        )
    )

    assert (
        result.status,
        result.reason_code,
    ) == (
        "unavailable",
        "EXPLORER_REQUEST_UNAVAILABLE",
    )


def test_declared_network_mismatch_is_invalid() -> None:
    fetch = FakeFetch(
        response(
            headers={"X-Hedera-Network": "mainnet"},
        )
    )

    result = run(
        read_explorer_public_v1(
            config(fetch),
            "/v1/datasets/x",
            "testnet",
        )
    )

    assert (
        result.status,
        result.reason_code,
    ) == (
        "invalid",
        "EXPLORER_NETWORK_MISMATCH",
    )


def test_declared_and_actual_response_size_are_bounded() -> None:
    declared = FakeFetch(
        response(
            headers={
                "Content-Length": str(
                    MAX_EXPLORER_RESPONSE_BYTES + 1
                )
            },
        )
    )

    result = run(
        read_explorer_public_v1(
            config(declared),
            "/v1/datasets/x",
            "testnet",
        )
    )

    assert result.reason_code == "EXPLORER_RESPONSE_TOO_LARGE"

    actual = FakeFetch(
        response(
            b"x" * (MAX_EXPLORER_RESPONSE_BYTES + 1)
        )
    )

    result = run(
        read_explorer_public_v1(
            config(actual),
            "/v1/datasets/x",
            "testnet",
        )
    )

    assert result.reason_code == "EXPLORER_RESPONSE_TOO_LARGE"


@pytest.mark.parametrize(
    "body",
    [
        b"",
        b"\xff",
        b"not-json",
        b"null",
        b"[]",
        b'{"value":NaN}',
    ],
)
def test_response_must_be_strict_utf8_json_object(
    body: bytes,
) -> None:
    fetch = FakeFetch(response(body))

    result = run(
        read_explorer_public_v1(
            config(fetch),
            "/v1/datasets/x",
            "testnet",
        )
    )

    assert (
        result.status,
        result.reason_code,
    ) == (
        "invalid",
        "EXPLORER_RESPONSE_INVALID",
    )


def test_missing_response_body_is_distinct() -> None:
    fetch = FakeFetch(
        ExplorerFetchResponseV1(
            status=200,
            headers={},
            body=None,
        )
    )

    result = run(
        read_explorer_public_v1(
            config(fetch),
            "/v1/datasets/x",
            "testnet",
        )
    )

    assert (
        result.status,
        result.reason_code,
    ) == (
        "invalid",
        "EXPLORER_EMPTY_RESPONSE",
    )