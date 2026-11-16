"""Normalize private Dataset Registry version-creation events."""

import math
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal, cast

from ...contracts import HederaNetwork

_SCHEMA_VERSION = "core.dataset_registry.event.v1"
_EVENT = "dataset_version.created"
_MAX_ENTITY_ID = 320
_MAX_SAFE_INTEGER = (1 << 53) - 1

_DATASET_KEY_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$",
    re.ASCII,
)
_HEX_512_RE = re.compile(
    r"^[0-9a-f]{128}$",
    re.IGNORECASE | re.ASCII,
)
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE | re.ASCII,
)

type DatasetRegistryVersionCreatedV1Status = Literal[
    "resolved",
    "unavailable",
    "unsupported",
    "invalid",
    "conflict",
]


@dataclass(frozen=True, slots=True)
class DatasetRegistryVersionCreatedV1:
    schema_version: Literal["core.dataset_registry.event.v1"]
    event: Literal["dataset_version.created"]
    entity_id: str
    hedera_network: HederaNetwork
    dataset_version_id: str
    dataset_key: str
    version: int
    dataset_fingerprint: str
    manifest_hash: str | None
    schema_hash: str | None


@dataclass(frozen=True, slots=True)
class DatasetRegistryVersionCreatedV1Result:
    status: DatasetRegistryVersionCreatedV1Status
    reason_code: str | None
    event: DatasetRegistryVersionCreatedV1 | None


_INVALID = object()


def _object(
    value: object,
) -> Mapping[str, object] | None:
    if not isinstance(value, Mapping):
        return None

    return cast(
        Mapping[str, object],
        value,
    )


def _optional_digest(
    value: object,
) -> str | None | object:
    if value is None or value == "":
        return None

    if (
        not isinstance(value, str)
        or _HEX_512_RE.fullmatch(value) is None
    ):
        return _INVALID

    return value.lower()


def _safe_positive_integer(
    value: object,
) -> int | None:
    if isinstance(value, bool):
        return None

    if isinstance(value, int):
        if 1 <= value <= _MAX_SAFE_INTEGER:
            return value
        return None

    if (
        isinstance(value, float)
        and math.isfinite(value)
        and value.is_integer()
        and 1 <= value <= _MAX_SAFE_INTEGER
    ):
        return int(value)

    return None


def _result(
    status: DatasetRegistryVersionCreatedV1Status,
    reason_code: str,
) -> DatasetRegistryVersionCreatedV1Result:
    return DatasetRegistryVersionCreatedV1Result(
        status=status,
        reason_code=reason_code,
        event=None,
    )


def parse_dataset_registry_version_created_v1(
    payload: object,
    expected_network: HederaNetwork | None = None,
) -> DatasetRegistryVersionCreatedV1Result:
    """Parse a Dataset Registry version-creation envelope."""
    if payload is None:
        return _result(
            "unavailable",
            "AUTHORIZED_DATASET_PAYLOAD_UNAVAILABLE",
        )

    envelope = _object(payload)

    if envelope is None:
        return _result(
            "invalid",
            "AUTHORIZED_DATASET_PAYLOAD_INVALID",
        )

    if (
        envelope.get("_type") != _SCHEMA_VERSION
        or envelope.get("event") != _EVENT
    ):
        return _result(
            "unsupported",
            "AUTHORIZED_DATASET_EVENT_UNSUPPORTED",
        )

    network = envelope.get("hedera_network")

    if network not in ("mainnet", "testnet"):
        return _result(
            "invalid",
            "AUTHORIZED_DATASET_NETWORK_INVALID",
        )

    if (
        expected_network is not None
        and network != expected_network
    ):
        return _result(
            "conflict",
            "AUTHORIZED_DATASET_NETWORK_MISMATCH",
        )

    body = _object(
        envelope.get("payload")
    )

    if body is None:
        return _result(
            "invalid",
            "AUTHORIZED_DATASET_EVENT_PAYLOAD_INVALID",
        )

    dataset_key = body.get("dataset_key")
    version = _safe_positive_integer(
        body.get("version")
    )
    fingerprint = body.get(
        "dataset_fingerprint"
    )
    version_id = body.get(
        "dataset_version_id"
    )
    entity_id = envelope.get("entity_id")

    if (
        not isinstance(dataset_key, str)
        or dataset_key.strip() != dataset_key
        or _DATASET_KEY_RE.fullmatch(
            dataset_key
        )
        is None
        or version is None
        or not isinstance(fingerprint, str)
        or _HEX_512_RE.fullmatch(
            fingerprint
        )
        is None
        or not isinstance(version_id, str)
        or _UUID_RE.fullmatch(version_id) is None
        or not isinstance(entity_id, str)
        or not entity_id
        or len(entity_id) > _MAX_ENTITY_ID
        or entity_id
        != f"{dataset_key}@{version}"
    ):
        return _result(
            "invalid",
            "AUTHORIZED_DATASET_EVENT_PAYLOAD_INVALID",
        )

    manifest_hash = _optional_digest(
        body.get("manifest_hash")
    )
    schema_hash = _optional_digest(
        body.get("schema_hash")
    )

    if (
        manifest_hash is _INVALID
        or schema_hash is _INVALID
    ):
        return _result(
            "invalid",
            "AUTHORIZED_DATASET_EVENT_PAYLOAD_INVALID",
        )

    return DatasetRegistryVersionCreatedV1Result(
        status="resolved",
        reason_code=None,
        event=DatasetRegistryVersionCreatedV1(
            schema_version=(
                "core.dataset_registry.event.v1"
            ),
            event="dataset_version.created",
            entity_id=entity_id,
            hedera_network=network,
            dataset_version_id=(
                version_id.lower()
            ),
            dataset_key=dataset_key,
            version=version,
            dataset_fingerprint=(
                fingerprint.lower()
            ),
            manifest_hash=cast(
                str | None,
                manifest_hash,
            ),
            schema_hash=cast(
                str | None,
                schema_hash,
            ),
        ),
    )