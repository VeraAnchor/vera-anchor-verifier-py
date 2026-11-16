"""Authorization-provider contract for scoped Core evidence acquisition."""

import inspect
import re
from collections.abc import Awaitable, Mapping
from dataclasses import dataclass
from typing import Literal, Protocol, cast

from ..contracts import HederaNetwork

_MAX_AUTHORIZATION_BYTES = 8 * 1024
_MAX_STATIC_TOKEN_BYTES = 4 * 1024

_AUTHORIZATION_RE = re.compile(
    rb"^[A-Za-z][A-Za-z0-9+.\-]* [\x21-\x7e]+$"
)
_STATIC_TOKEN_RE = re.compile(rb"^[\x21-\x7e]+$")


@dataclass(frozen=True, slots=True)
class CoreAuthorizationRequestV1:
    origin: str
    path: Literal["/v1/hcs/verify-decrypt"]
    method: Literal["POST"]
    network: HederaNetwork


@dataclass(frozen=True, slots=True)
class CoreAuthorizationMaterialV1:
    authorization: str


type AuthProviderResultV1 = (
    CoreAuthorizationMaterialV1
    | Mapping[str, object]
)

type AuthProviderReturnV1 = (
    AuthProviderResultV1
    | Awaitable[AuthProviderResultV1]
)


class AuthProviderV1(Protocol):
    """Supplies credentials for one already-scoped Core request."""

    def authorize(
        self,
        request: CoreAuthorizationRequestV1,
    ) -> AuthProviderReturnV1: ...


class AuthProviderContractErrorV1(TypeError):
    """The provider violated the authorization-provider contract."""

    def __init__(
        self,
        message: str = (
            "AuthProvider returned invalid authorization material"
        ),
    ) -> None:
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class _StaticBearerAuthProviderV1:
    token: str

    def authorize(
        self,
        request: CoreAuthorizationRequestV1,
    ) -> CoreAuthorizationMaterialV1:
        del request

        return CoreAuthorizationMaterialV1(
            authorization=f"Bearer {self.token}"
        )


def _utf8(value: str) -> bytes:
    try:
        return value.encode(
            "utf-8",
            errors="strict",
        )
    except UnicodeEncodeError as exc:
        raise AuthProviderContractErrorV1() from exc


def _authorization(
    value: object,
) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value.strip() != value
    ):
        raise AuthProviderContractErrorV1()

    encoded = _utf8(value)

    if (
        len(encoded) > _MAX_AUTHORIZATION_BYTES
        or _AUTHORIZATION_RE.fullmatch(encoded) is None
    ):
        raise AuthProviderContractErrorV1()

    return value


def _material(
    value: object,
) -> CoreAuthorizationMaterialV1:
    authorization: object

    if isinstance(
        value,
        CoreAuthorizationMaterialV1,
    ):
        authorization = value.authorization

    elif isinstance(value, Mapping):
        authorization = value.get("authorization")

    else:
        raise AuthProviderContractErrorV1()

    return CoreAuthorizationMaterialV1(
        authorization=_authorization(
            authorization
        )
    )


def create_static_bearer_auth_provider_v1(
    token: str,
) -> AuthProviderV1:
    """Create the current bearer-token/API-key provider."""
    if (
        not isinstance(token, str)
        or not token
        or token.strip() != token
    ):
        raise TypeError(
            "Bearer token must be a bounded printable ASCII token"
        )

    try:
        encoded = token.encode(
            "ascii",
            errors="strict",
        )
    except UnicodeEncodeError as exc:
        raise TypeError(
            "Bearer token must be a bounded printable ASCII token"
        ) from exc

    if (
        len(encoded) > _MAX_STATIC_TOKEN_BYTES
        or _STATIC_TOKEN_RE.fullmatch(encoded) is None
    ):
        raise TypeError(
            "Bearer token must be a bounded printable ASCII token"
        )

    return _StaticBearerAuthProviderV1(
        token=token,
    )


async def resolve_core_authorization_v1(
    provider: AuthProviderV1,
    request: CoreAuthorizationRequestV1,
) -> CoreAuthorizationMaterialV1:
    """
    Resolve authorization without swallowing provider execution failures.

    Contract violations become AuthProviderContractErrorV1. Exceptions raised
    by the provider itself propagate unchanged so the acquisition layer can
    classify provider availability independently.
    """
    authorize = getattr(
        provider,
        "authorize",
        None,
    )

    if not callable(authorize):
        raise AuthProviderContractErrorV1(
            "AuthProviderV1 with authorize() is required"
        )

    result = authorize(request)

    if inspect.isawaitable(result):
        result = await cast(
            Awaitable[AuthProviderResultV1],
            result,
        )

    return _material(result)