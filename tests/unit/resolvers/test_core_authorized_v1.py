import asyncio
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

import pytest

from vera_anchor_verifier.auth import (
    AuthProviderContractErrorV1,
    CoreAuthorizationRequestV1,
    create_static_bearer_auth_provider_v1,
)
from vera_anchor_verifier.resolvers import (
    AuthorizedHcsEvidenceV1Request,
    CoreAuthorizedV1Config,
    resolve_authorized_hcs_evidence_v1,
)
from vera_anchor_verifier.resolvers.core_authorized_v1 import (
    CoreAuthorizedFetchResponseV1,
)

CORE = "https://core.example.test"
NETWORK = "testnet"
MESSAGE_ID = "5@0.0.12345"
TX_ID = "0.0.77@1234567890.123456789"
HASH = "a" * 128


def run[T](coro) -> T:
    return asyncio.run(coro)


def success(
    **overrides: object,
) -> dict[str, object]:
    value: dict[str, object] = {
        "ok": True,
        "hedera_network": NETWORK,
        "mode": "decrypt_only",
        "verified": None,
        "topic": {
            "name": "dataset_publication",
            "topic_id": "0.0.12345",
            "key_version": 3,
        },
        "encryption": {
            "topic_key_version": 3,
            "user_key_version": 2,
        },
        "tx": {
            "id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "message_id": MESSAGE_ID,
            "transaction_id": TX_ID,
            "sequence_number": 5,
            "consensus_timestamp": "1234567890.123456789",
            "status": "confirmed",
            "mirror_verified": True,
            "mirror_verified_at": "2026-11-04T12:00:00.000Z",
        },
        "hash": {
            "expected": HASH,
            "computed": HASH,
            "match": None,
        },
        "message_binding": {
            "schema_version": "vera.hcs-message-binding.v1",
            "algorithm": "sha3-512",
            "message_sha3_512": HASH,
            "message_bytes": 512,
        },
        "payload": {
            "schema": "example:v1",
            "value": 7,
        },
    }
    value.update(overrides)
    return value


def cast_tx(value: object) -> dict[str, object]:
    assert isinstance(value, dict)
    return value


def response(
    value: object,
    *,
    status: int = 200,
    headers: Mapping[str, str] | None = None,
) -> CoreAuthorizedFetchResponseV1:
    body = json.dumps(
        value,
        separators=(",", ":"),
    ).encode()

    return CoreAuthorizedFetchResponseV1(
        status=status,
        headers=(
            headers
            or {
                "Content-Type": "application/json",
                "Content-Length": str(len(body)),
            }
        ),
        body=body,
    )


@dataclass
class FakeFetch:
    result: CoreAuthorizedFetchResponseV1 | None = None
    error: Exception | None = None
    calls: list[dict[str, Any]] = field(default_factory=list)

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

        if self.error is not None:
            raise self.error

        assert self.result is not None
        return self.result


def config(
    fetch: FakeFetch,
    *,
    provider=None,
) -> CoreAuthorizedV1Config:
    return CoreAuthorizedV1Config(
        base_url=CORE,
        auth_provider=(
            provider
            or create_static_bearer_auth_provider_v1(
                "test-api-key"
            )
        ),
        fetch_impl=fetch,
    )


def test_retrieves_service_assisted_evidence_through_fixed_post() -> None:
    fetch = FakeFetch(
        result=response(success())
    )

    result = run(
        resolve_authorized_hcs_evidence_v1(
            config(fetch),
            AuthorizedHcsEvidenceV1Request(
                network="testnet",
                message_id=MESSAGE_ID,
                include_decrypted=True,
            ),
        )
    )

    assert result.status == "resolved"
    assert result.reason_code is None
    assert result.evidence is not None

    evidence = result.evidence

    assert evidence.acquisition.resolver_id == "core.authorized-hcs.v1"
    assert evidence.acquisition.access_context == "authorized"
    assert evidence.acquisition.retrieval_provider == "vera_anchor_core"
    assert evidence.acquisition.decryption_method == "service_assisted"
    assert evidence.acquisition.recoverability == "service_dependent"
    assert evidence.payload == {
        "schema": "example:v1",
        "value": 7,
    }
    assert evidence.message_binding.message_sha3_512 == HASH
    assert not hasattr(evidence, "verified")
    assert not hasattr(
        evidence.core_hash_observation,
        "match",
    )

    assert len(fetch.calls) == 1

    call = fetch.calls[0]

    assert call["url"] == (
        "https://core.example.test/v1/hcs/verify-decrypt"
    )
    assert call["headers"] == {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": "Bearer test-api-key",
    }
    assert json.loads(call["body"]) == {
        "hedera_network": "testnet",
        "message_id": MESSAGE_ID,
        "mode": "decrypt_only",
        "include_decrypted": True,
    }


def test_plaintext_requires_explicit_opt_in() -> None:
    fetch = FakeFetch(
        result=response(success())
    )

    result = run(
        resolve_authorized_hcs_evidence_v1(
            config(fetch),
            AuthorizedHcsEvidenceV1Request(
                network="testnet",
                message_id=MESSAGE_ID,
            ),
        )
    )

    assert (
        result.status,
        result.reason_code,
    ) == (
        "invalid",
        "CORE_AUTHORIZED_DISCLOSURE_MISMATCH",
    )


@pytest.mark.parametrize(
    "body",
    [
        success(
            hedera_network="mainnet",
        ),
        success(
            tx={
                **cast_tx(success()["tx"]),
                "message_id": "6@0.0.12345",
            },
        ),
        success(
            mode="decrypt_and_verify",
            verified=True,
            hash={
                "expected": HASH,
                "computed": HASH,
                "match": True,
            },
        ),
    ],
)
def test_network_locator_and_verdict_drift_fail_closed(
    body: dict[str, object],
) -> None:
    result = run(
        resolve_authorized_hcs_evidence_v1(
            config(
                FakeFetch(
                    result=response(body)
                )
            ),
            AuthorizedHcsEvidenceV1Request(
                network="testnet",
                message_id=MESSAGE_ID,
                include_decrypted=True,
            ),
        )
    )

    assert result.status == "invalid"
    assert result.evidence is None


@pytest.mark.parametrize(
    ("status", "expected", "reason"),
    [
        (401, "unauthorized", "CORE_AUTH_REQUIRED"),
        (403, "forbidden", "CORE_AUTH_FORBIDDEN"),
        (
            404,
            "not_found",
            "CORE_AUTHORIZED_EVIDENCE_NOT_FOUND",
        ),
        (429, "rate_limited", "CORE_RATE_LIMITED"),
        (
            400,
            "invalid",
            "CORE_AUTHORIZED_REQUEST_REJECTED",
        ),
        (
            503,
            "unavailable",
            "CORE_AUTHORIZED_HTTP_UNAVAILABLE",
        ),
    ],
)
def test_http_failures_are_mapped_without_retry(
    status: int,
    expected: str,
    reason: str,
) -> None:
    fetch = FakeFetch(
        result=response(
            {"error": "x"},
            status=status,
        )
    )

    result = run(
        resolve_authorized_hcs_evidence_v1(
            config(fetch),
            AuthorizedHcsEvidenceV1Request(
                network="testnet",
                transaction_id=TX_ID,
            ),
        )
    )

    assert (
        result.status,
        result.reason_code,
    ) == (
        expected,
        reason,
    )
    assert result.evidence is None
    assert len(fetch.calls) == 1


def test_provider_execution_failure_is_unavailable_before_transport() -> None:
    class Provider:
        async def authorize(
            self,
            request: CoreAuthorizationRequestV1,
        ):
            del request
            raise RuntimeError(
                "identity provider unavailable"
            )

    fetch = FakeFetch(
        result=response(success())
    )

    result = run(
        resolve_authorized_hcs_evidence_v1(
            config(
                fetch,
                provider=Provider(),
            ),
            AuthorizedHcsEvidenceV1Request(
                network="testnet",
                message_id=MESSAGE_ID,
            ),
        )
    )

    assert (
        result.status,
        result.reason_code,
    ) == (
        "unavailable",
        "AUTH_PROVIDER_UNAVAILABLE",
    )
    assert fetch.calls == []


def test_malformed_provider_output_remains_contract_error() -> None:
    class Provider:
        def authorize(
            self,
            request: CoreAuthorizationRequestV1,
        ):
            del request

            return {
                "authorization": (
                    "Bearer good\r\nX-Evil: yes"
                )
            }

    with pytest.raises(
        AuthProviderContractErrorV1,
        match="invalid authorization",
    ):
        run(
            resolve_authorized_hcs_evidence_v1(
                CoreAuthorizedV1Config(
                    base_url=CORE,
                    auth_provider=Provider(),
                ),
                AuthorizedHcsEvidenceV1Request(
                    network="testnet",
                    message_id=MESSAGE_ID,
                ),
            )
        )


def test_identifier_bound_matches_256_byte_contract() -> None:
    with pytest.raises(
        TypeError,
        match="Invalid message_id",
    ):
        run(
            resolve_authorized_hcs_evidence_v1(
                CoreAuthorizedV1Config(
                    base_url=CORE,
                    auth_provider=(
                        create_static_bearer_auth_provider_v1(
                            "test-api-key"
                        )
                    ),
                ),
                AuthorizedHcsEvidenceV1Request(
                    network="testnet",
                    message_id="x" * 257,
                ),
            )
        )


@pytest.mark.parametrize(
    "base_url",
    [
        "http://core.example.test",
        "https://core.example.test/v1",
        "https://user:pass@core.example.test",
        "https://core.example.test?x=1",
        "https://core.example.test#fragment",
    ],
)
def test_unsafe_core_origins_fail_before_transport(
    base_url: str,
) -> None:
    fetch = FakeFetch(
        result=response(success())
    )

    with pytest.raises(
        TypeError,
        match="fixed HTTPS origin",
    ):
        run(
            resolve_authorized_hcs_evidence_v1(
                CoreAuthorizedV1Config(
                    base_url=base_url,
                    auth_provider=(
                        create_static_bearer_auth_provider_v1(
                            "test-api-key"
                        )
                    ),
                    fetch_impl=fetch,
                ),
                AuthorizedHcsEvidenceV1Request(
                    network="testnet",
                    message_id=MESSAGE_ID,
                ),
            )
        )

    assert fetch.calls == []


def test_http_loopback_origin_is_permitted() -> None:
    body = success()
    body.pop("payload")

    fetch = FakeFetch(
        result=response(body)
    )

    result = run(
        resolve_authorized_hcs_evidence_v1(
            CoreAuthorizedV1Config(
                base_url="http://127.0.0.1:5000",
                auth_provider=(
                    create_static_bearer_auth_provider_v1(
                        "test-api-key"
                    )
                ),
                fetch_impl=fetch,
            ),
            AuthorizedHcsEvidenceV1Request(
                network="testnet",
                message_id=MESSAGE_ID,
            ),
        )
    )

    assert result.status == "resolved"


def test_exactly_one_locator_is_required() -> None:
    safe = create_static_bearer_auth_provider_v1(
        "test-api-key"
    )

    with pytest.raises(
        TypeError,
        match="Exactly one",
    ):
        run(
            resolve_authorized_hcs_evidence_v1(
                CoreAuthorizedV1Config(
                    base_url=CORE,
                    auth_provider=safe,
                ),
                AuthorizedHcsEvidenceV1Request(
                    network="testnet",
                ),
            )
        )

    with pytest.raises(
        TypeError,
        match="Exactly one",
    ):
        run(
            resolve_authorized_hcs_evidence_v1(
                CoreAuthorizedV1Config(
                    base_url=CORE,
                    auth_provider=safe,
                ),
                AuthorizedHcsEvidenceV1Request(
                    network="testnet",
                    message_id=MESSAGE_ID,
                    transaction_id=TX_ID,
                ),
            )
        )


def test_oversized_response_is_rejected_before_json_parse() -> None:
    fetch = FakeFetch(
        result=CoreAuthorizedFetchResponseV1(
            status=200,
            headers={
                "Content-Type": "application/json",
                "Content-Length": "3000000",
            },
            body=b"{}",
        )
    )

    result = run(
        resolve_authorized_hcs_evidence_v1(
            config(fetch),
            AuthorizedHcsEvidenceV1Request(
                network="testnet",
                message_id=MESSAGE_ID,
            ),
        )
    )

    assert (
        result.status,
        result.reason_code,
    ) == (
        "invalid",
        "CORE_AUTHORIZED_RESPONSE_TOO_LARGE",
    )


def test_actual_response_body_is_bounded() -> None:
    fetch = FakeFetch(
        result=CoreAuthorizedFetchResponseV1(
            status=200,
            headers={
                "Content-Type": "application/json",
            },
            body=b"x" * (1024 * 1024 + 1),
        )
    )

    result = run(
        resolve_authorized_hcs_evidence_v1(
            config(fetch),
            AuthorizedHcsEvidenceV1Request(
                network="testnet",
                message_id=MESSAGE_ID,
            ),
        )
    )

    assert (
        result.status,
        result.reason_code,
    ) == (
        "invalid",
        "CORE_AUTHORIZED_RESPONSE_TOO_LARGE",
    )


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"Content-Type": "text/plain"},
    ],
)
def test_json_content_type_is_required(
    headers: dict[str, str],
) -> None:
    fetch = FakeFetch(
        result=CoreAuthorizedFetchResponseV1(
            status=200,
            headers=headers,
            body=b"{}",
        )
    )

    result = run(
        resolve_authorized_hcs_evidence_v1(
            config(fetch),
            AuthorizedHcsEvidenceV1Request(
                network="testnet",
                message_id=MESSAGE_ID,
            ),
        )
    )

    assert (
        result.status,
        result.reason_code,
    ) == (
        "invalid",
        "CORE_AUTHORIZED_RESPONSE_INVALID",
    )


def test_timeout_and_transport_failures_remain_distinct() -> None:
    timed_out = run(
        resolve_authorized_hcs_evidence_v1(
            config(
                FakeFetch(
                    error=TimeoutError()
                )
            ),
            AuthorizedHcsEvidenceV1Request(
                network="testnet",
                message_id=MESSAGE_ID,
            ),
        )
    )

    assert (
        timed_out.status,
        timed_out.reason_code,
    ) == (
        "unavailable",
        "CORE_AUTHORIZED_REQUEST_TIMEOUT",
    )

    unavailable = run(
        resolve_authorized_hcs_evidence_v1(
            config(
                FakeFetch(
                    error=OSError("network down")
                )
            ),
            AuthorizedHcsEvidenceV1Request(
                network="testnet",
                message_id=MESSAGE_ID,
            ),
        )
    )

    assert (
        unavailable.status,
        unavailable.reason_code,
    ) == (
        "unavailable",
        "CORE_AUTHORIZED_REQUEST_UNAVAILABLE",
    )


def test_invalid_message_binding_is_rejected() -> None:
    body = success()
    body["message_binding"] = {
        "schema_version": "vera.hcs-message-binding.v1",
        "algorithm": "sha3-512",
        "message_sha3_512": HASH,
        "message_bytes": 0,
    }

    result = run(
        resolve_authorized_hcs_evidence_v1(
            config(
                FakeFetch(
                    result=response(body)
                )
            ),
            AuthorizedHcsEvidenceV1Request(
                network="testnet",
                message_id=MESSAGE_ID,
                include_decrypted=True,
            ),
        )
    )

    assert (
        result.status,
        result.reason_code,
    ) == (
        "invalid",
        "CORE_AUTHORIZED_RESPONSE_INVALID",
    )