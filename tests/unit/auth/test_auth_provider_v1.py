import asyncio
from dataclasses import FrozenInstanceError

import pytest

from vera_anchor_verifier.auth import (
    AuthProviderContractErrorV1,
    CoreAuthorizationMaterialV1,
    CoreAuthorizationRequestV1,
    create_static_bearer_auth_provider_v1,
)
from vera_anchor_verifier.auth.auth_provider_v1 import (
    resolve_core_authorization_v1,
)

REQUEST = CoreAuthorizationRequestV1(
    origin="https://core.example.test",
    path="/v1/hcs/verify-decrypt",
    method="POST",
    network="testnet",
)


def run[T](coro) -> T:
    return asyncio.run(coro)


def test_static_bearer_provider_returns_scoped_authorization() -> None:
    provider = create_static_bearer_auth_provider_v1(
        "test-api-key"
    )

    material = run(
        resolve_core_authorization_v1(
            provider,
            REQUEST,
        )
    )

    assert material == CoreAuthorizationMaterialV1(
        authorization="Bearer test-api-key"
    )


@pytest.mark.parametrize(
    "token",
    [
        "",
        " leading",
        "trailing ",
        "contains space",
        "contains\ttab",
        "contains\nnewline",
        "contains\rreturn",
        "ümlaut",
        "x" * (4 * 1024 + 1),
    ],
)
def test_static_token_contract_fails_closed(
    token: str,
) -> None:
    with pytest.raises(
        TypeError,
        match="bounded printable ASCII token",
    ):
        create_static_bearer_auth_provider_v1(
            token
        )


@pytest.mark.parametrize(
    "authorization",
    [
        "",
        "Bearer",
        "Bearer ",
        " Bearer token",
        "Bearer token ",
        "Bearer good\r\nX-Evil: yes",
        "Bearer café",
        "1Bearer token",
        "Bearer\ttoken",
        "Bearer " + ("x" * (8 * 1024)),
    ],
)
def test_malformed_provider_output_is_contract_error(
    authorization: str,
) -> None:
    class Provider:
        def authorize(
            self,
            request: CoreAuthorizationRequestV1,
        ):
            del request

            return {
                "authorization": authorization,
            }

    with pytest.raises(
        AuthProviderContractErrorV1,
        match="invalid authorization material",
    ):
        run(
            resolve_core_authorization_v1(
                Provider(),
                REQUEST,
            )
        )


def test_accepts_custom_authorization_scheme() -> None:
    class Provider:
        def authorize(
            self,
            request: CoreAuthorizationRequestV1,
        ):
            del request

            return {
                "authorization": "Custom-Scheme abc123",
            }

    material = run(
        resolve_core_authorization_v1(
            Provider(),
            REQUEST,
        )
    )

    assert (
        material.authorization
        == "Custom-Scheme abc123"
    )


def test_accepts_material_dataclass() -> None:
    class Provider:
        def authorize(
            self,
            request: CoreAuthorizationRequestV1,
        ):
            del request

            return CoreAuthorizationMaterialV1(
                authorization="Bearer abc123"
            )

    material = run(
        resolve_core_authorization_v1(
            Provider(),
            REQUEST,
        )
    )

    assert material.authorization == "Bearer abc123"


def test_async_provider_is_supported() -> None:
    seen: CoreAuthorizationRequestV1 | None = None

    class Provider:
        async def authorize(
            self,
            request: CoreAuthorizationRequestV1,
        ):
            nonlocal seen
            seen = request

            return {
                "authorization": "Bearer async-key",
            }

    material = run(
        resolve_core_authorization_v1(
            Provider(),
            REQUEST,
        )
    )

    assert seen == REQUEST
    assert material.authorization == "Bearer async-key"


def test_provider_execution_failure_propagates_unchanged() -> None:
    error = RuntimeError(
        "identity provider unavailable"
    )

    class Provider:
        async def authorize(
            self,
            request: CoreAuthorizationRequestV1,
        ):
            del request
            raise error

    with pytest.raises(RuntimeError) as caught:
        run(
            resolve_core_authorization_v1(
                Provider(),
                REQUEST,
            )
        )

    assert caught.value is error


@pytest.mark.parametrize(
    "value",
    [
        None,
        "Bearer token",
        123,
        [],
        {},
        {"other": "Bearer token"},
    ],
)
def test_invalid_provider_result_shape_is_contract_error(
    value: object,
) -> None:
    class Provider:
        def authorize(
            self,
            request: CoreAuthorizationRequestV1,
        ):
            del request
            return value

    with pytest.raises(
        AuthProviderContractErrorV1,
    ):
        run(
            resolve_core_authorization_v1(
                Provider(),
                REQUEST,
            )
        )


def test_missing_authorize_method_is_contract_error() -> None:
    with pytest.raises(
        AuthProviderContractErrorV1,
        match=r"authorize\(\)",
    ):
        run(
            resolve_core_authorization_v1(
                object(),  # type: ignore[arg-type]
                REQUEST,
            )
        )


def test_authorization_request_is_immutable() -> None:
    with pytest.raises(FrozenInstanceError):
        REQUEST.network = "mainnet"  # type: ignore[misc]


def test_provider_receives_only_scoped_request_metadata() -> None:
    seen: CoreAuthorizationRequestV1 | None = None

    class Provider:
        def authorize(
            self,
            request: CoreAuthorizationRequestV1,
        ):
            nonlocal seen
            seen = request

            return {
                "authorization": "Bearer scoped",
            }

    run(
        resolve_core_authorization_v1(
            Provider(),
            REQUEST,
        )
    )

    assert seen == CoreAuthorizationRequestV1(
        origin="https://core.example.test",
        path="/v1/hcs/verify-decrypt",
        method="POST",
        network="testnet",
    )

    assert not hasattr(seen, "body")
    assert not hasattr(seen, "intent")
    assert not hasattr(seen, "url")