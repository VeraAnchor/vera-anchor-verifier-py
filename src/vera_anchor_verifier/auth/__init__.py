"""Optional authorization for authenticated evidence acquisition."""

from .auth_provider_v1 import (
    AuthProviderContractErrorV1,
    AuthProviderV1,
    CoreAuthorizationMaterialV1,
    CoreAuthorizationRequestV1,
    create_static_bearer_auth_provider_v1,
)

__all__ = [
    "AuthProviderContractErrorV1",
    "AuthProviderV1",
    "CoreAuthorizationMaterialV1",
    "CoreAuthorizationRequestV1",
    "create_static_bearer_auth_provider_v1",
]