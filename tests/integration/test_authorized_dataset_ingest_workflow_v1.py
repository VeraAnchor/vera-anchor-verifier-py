import asyncio
import base64
import copy
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Literal, cast

import pytest

from vera_anchor_verifier import sha3_512_hex
from vera_anchor_verifier.auth import create_static_bearer_auth_provider_v1
from vera_anchor_verifier.contracts import VerificationSubject
from vera_anchor_verifier.policy.contract_v1 import (
    VERIFICATION_POLICY_SCHEMA_VERSION,
    VerificationPolicyV1,
)
from vera_anchor_verifier.policy.evaluate_v1 import (
    triangulate_authorized_dataset_with_policy_v1,
    triangulate_authorized_ingest_with_policy_v1,
)
from vera_anchor_verifier.profiles.source_v1_helpers import SourceV1File
from vera_anchor_verifier.reports.validation_v1 import (
    validate_portable_verification_report_v1,
)
from vera_anchor_verifier.resolvers.authorized_observation_v1 import (
    AuthorizedHcsObservationsV1Config,
)
from vera_anchor_verifier.resolvers.core_authorized_v1 import (
    CoreAuthorizedFetchResponseV1,
    CoreAuthorizedV1Config,
)
from vera_anchor_verifier.resolvers.hedera_mirror_v1 import (
    HederaMirrorFetchResponseV1,
    HederaMirrorV1Config,
)
from vera_anchor_verifier.triangulation.authorized_dataset_v1 import (
    AuthorizedDatasetTriangulationV1Input,
)
from vera_anchor_verifier.triangulation.authorized_ingest_v1 import (
    AuthorizedIngestTriangulationV1Input,
)

CORE = "https://core.example.test"
MIRROR = "https://mirror.example.test/api/v1"
TOPIC = "0.0.12345"
SEQUENCE = 5
MESSAGE_ID = f"{SEQUENCE}@{TOPIC}"
MESSAGE = b"authorized-encrypted-message"
MESSAGE_DIGEST = sha3_512_hex(MESSAGE)

DATASET_KEY = "conformance.dataset.basic.v1"
DATASET_FINGERPRINT = (
    "98eef5d06e916c1a14a4f28ee1fcf91fb5f596d5586e829119a57520fe122a70"
    "96dae0d78c381b261c29bb3c36e2bf183e08c89d1a4e2e9a80331f3f717bcd8e"
)
DATASET_ROOT = (
    "8fccfd1270991327edf23c5f224c66ec1b08c9c3f3a8783aeafb986c8d3352dc"
    "cb03ff78645af3334098bfe924d54df2a684f06d711b93d3785df52c6de88a92"
)
DATASET_BUNDLE: dict[str, object] = {
    "bundle_version": "v1",
    "hash_contract": {
        "contract_id": "hf-contract-v1",
        "frame": "hf:frame:v1",
        "canonical_json": "hf:canonical-json:v1",
        "algorithm": "sha3-512",
        "encoding": "hex_lower",
    },
    "dataset_identity": {
        "dataset_key": DATASET_KEY,
        "version_label": "v1",
        "program": "conformance",
    },
    "rules": {
        "path_normalization": "posix_rel_no_dotdot",
        "follow_symlinks": False,
        "redact_paths": False,
        "ordering": "path_rel_ascii_asc",
        "merkle_rule": "dup_last_on_odd",
    },
    "files": [
        {
            "path_rel": "hello.txt",
            "bytes": 12,
            "sha3_512": (
                "4a936cbc1db296bd08d1c0bbf5a66a1897f35ee6d93047e0edff893dfbcba02f"
                "1e1570e85d1187ea26bea6d54199e0656f1b7c21b9cc2102b8ed2a12769f4531"
            ),
            "leaf_hash": DATASET_ROOT,
        }
    ],
    "merkle": {"leaf_count": 1, "root": DATASET_ROOT},
    "summary": {"file_count": 1, "total_bytes": 12},
}

INGEST_KEY = "conformance.ingest.json.v1"
INGEST_FINGERPRINT = (
    "5c766d0267998f962054378126aaa0a29b50ac0b9c3caf0df0cf1bfc8bbd76d2"
    "49e157452bbe7ce74bb3b2935e3275c765d6ba7a766f100dc2b76b2773beae15"
)
INGEST_BUNDLE_DIGEST = (
    "a50d0ec38d250b5e28f7f2d176cb5b8d85d718f4a0d21f2b6cf1797ca81a43d"
    "a35aa94deac635397787e484b8027324ef82c763d6a4fe8c5671b153ce6c3c2f7"
)
INGEST_ROOT = (
    "bd97e1bb4a1b5908303c409f7d377a6f488504c2f1ea5a621c29c3da84221052"
    "c840ba06894717cb3026b7074db24d25eaaf0b94c6992ee00ecb27a2a8107aad"
)
INGEST_IDEMPOTENCY = (
    "aeaf614fc89f74399a4f13872e1c2022aae62caaff0c0053c64a6b49d6b9369a"
    "2b86a360bd4ce02df3928c4d2e5999c615c1b254843ea37707ecd9bcbc930b9d"
)
INGEST_BUNDLE: dict[str, object] = {
    "bundle_version": "v1",
    "hash_contract": {
        "contract_id": "hf-contract-v1",
        "frame": "hf:frame:v1",
        "canonical_json": "hf:canonical-json:v1",
        "algorithm": "sha3-512",
        "encoding": "hex_lower",
    },
    "identity": {
        "object_key": INGEST_KEY,
        "object_kind": "json",
        "version_label": "v1",
        "program": "conformance",
    },
    "rules": {
        "path_normalization": "posix_rel_no_dotdot",
        "follow_symlinks": False,
        "redact_paths": False,
        "normalize_line_endings": False,
        "ordering": "deterministic_sort_v1",
        "merkle_rule": "dup_last_on_odd",
    },
    "items": [
        {
            "item_kind": "json",
            "media_type": "application/json",
            "bytes": 52,
            "sha3_512": (
                "6387ef50e965bdc0654a7718977ce7891f05b9e66088231b74c9e5f2c012eb4b"
                "7e3e942021df06905ed7c4b528357bd4b76016e7f3f7053dbec5fdd01478aeef"
            ),
            "leaf_hash": INGEST_ROOT,
        }
    ],
    "merkle": {"leaf_count": 1, "root": INGEST_ROOT},
    "summary": {"item_count": 1, "total_bytes": 52},
}
INGEST_MATERIAL: dict[str, object] = {
    "kind": "json",
    "value": {
        "alpha": 1,
        "beta": ["x", 2],
        "nested": {"enabled": True},
    },
}

type Profile = Literal["dataset", "ingest"]
type MirrorState = Literal["resolved", "unavailable", "conflict"]


def run[T](coro) -> T:
    return asyncio.run(coro)


def encoded(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":")).encode()


def dataset_files() -> list[SourceV1File]:
    return [
        cast(
            SourceV1File,
            {
                "path_rel": "hello.txt",
                "source": [b"hello world\n"],
            },
        )
    ]


def subject(
    profile: Profile,
    key: str,
    network: Literal["mainnet", "testnet"] = "testnet",
) -> VerificationSubject:
    return cast(
        VerificationSubject,
        {
            "kind": profile,
            "id": key,
            "hedera_network": network,
        },
    )


def dataset_registry_payload(
    fingerprint: str = DATASET_FINGERPRINT,
) -> dict[str, object]:
    return {
        "_type": "core.dataset_registry.event.v1",
        "event": "dataset_version.created",
        "entity_id": f"{DATASET_KEY}@3",
        "ts": "2026-11-05T00:00:00.000Z",
        "actor_user_id": "22222222-2222-4222-8222-222222222222",
        "hedera_network": "testnet",
        "service_event_hash": "c" * 128,
        "payload": {
            "dataset_version_id": "11111111-1111-4111-8111-111111111111",
            "dataset_key": DATASET_KEY,
            "version": 3,
            "dataset_fingerprint": fingerprint,
            "manifest_hash": "d" * 128,
            "schema_hash": "e" * 128,
            "bytes_estimate": 128,
            "row_count": 4,
            "col_count": 2,
            "set_active": False,
        },
    }


def ingest_receipt(
    fingerprint: str = INGEST_FINGERPRINT,
) -> dict[str, object]:
    return {
        "v": "v1",
        "kind": "ingest_receipt",
        "mode": "register_and_anchor",
        "hedera_network": "testnet",
        "identity": {
            "object_key": INGEST_KEY,
            "object_kind": "json",
            "version_label": "v1",
            "program": "conformance",
        },
        "rules": {
            "path_normalization": "posix_rel_no_dotdot",
            "follow_symlinks": False,
            "redact_paths": False,
            "normalize_line_endings": False,
            "ordering": "deterministic_sort_v1",
            "merkle_rule": "dup_last_on_odd",
        },
        "evidence": {
            "fingerprint": fingerprint,
            "bundle_digest": INGEST_BUNDLE_DIGEST,
            "merkle_root": INGEST_ROOT,
            "idempotency_key": INGEST_IDEMPOTENCY,
            "item_count": 1,
            "total_bytes": 52,
        },
        "anchor": {
            "domain": "global",
            "proof_date": "2026-01-01",
        },
        "pointers": {
            "evidence_pointer": "vera://ingest-conformance/json-v1",
        },
        "receipt_id": (
            "ec284e7cd963e0db2937edd9b518a016d6e93985a60b43bb4609101baee02275e"
            "753416d160a79b9170d593d724629f506e76ef7fe1aa041d4121c773cfa2ebe"
        ),
    }


def policy(profile: Profile, key: str) -> VerificationPolicyV1:
    required = (
        (
            "dataset.source_binding",
            "triangulation.provided_authorized.dataset_fingerprint",
        )
        if profile == "dataset"
        else (
            "ingest.source_binding",
            "triangulation.provided_authorized.merkle_root",
        )
    )
    kind = (
        "authorized_dataset_triangulation"
        if profile == "dataset"
        else "authorized_ingest_triangulation"
    )

    return VerificationPolicyV1(
        schema_version=VERIFICATION_POLICY_SCHEMA_VERSION,
        subject=subject(profile, key),
        report_kind=kind,
        required_checks=required,
        required_assurance=("mirror_corroboration",),
        on_unresolved="review",
    )


def dataset_input() -> AuthorizedDatasetTriangulationV1Input:
    return {
        "bundle": copy.deepcopy(DATASET_BUNDLE),
        "files": dataset_files(),
        "intent": {
            "subject": subject("dataset", DATASET_KEY),
            "expected": [],
        },
        "hcs_reference": {"message_id": MESSAGE_ID},
    }


def ingest_input() -> AuthorizedIngestTriangulationV1Input:
    return {
        "bundle": copy.deepcopy(INGEST_BUNDLE),
        "material": copy.deepcopy(INGEST_MATERIAL),
        "intent": {
            "subject": subject("ingest", INGEST_KEY),
            "expected": [],
        },
        "hcs_reference": {"message_id": MESSAGE_ID},
    }


@dataclass
class Transport:
    profile: Profile
    core_status: int = 200
    mirror_state: MirrorState = "resolved"
    profile_conflict: bool = False
    core_calls: list[dict[str, object]] = field(default_factory=list)
    mirror_calls: list[dict[str, object]] = field(default_factory=list)

    async def core_fetch(
        self,
        url: str,
        headers: Mapping[str, str],
        body: bytes,
        timeout_ms: int,
        max_response_bytes: int,
    ) -> CoreAuthorizedFetchResponseV1:
        self.core_calls.append(
            {
                "url": url,
                "headers": dict(headers),
                "body": body,
            }
        )

        assert url == f"{CORE}/v1/hcs/verify-decrypt"
        assert headers["Authorization"] == "Bearer test-api-key"
        assert json.loads(body) == {
            "hedera_network": "testnet",
            "message_id": MESSAGE_ID,
            "mode": "decrypt_only",
            "include_decrypted": True,
        }
        assert 250 <= timeout_ms <= 60_000
        assert 1024 <= max_response_bytes <= 2 * 1024 * 1024

        if self.core_status != 200:
            return self._core_response(
                {"error": "unavailable"},
                self.core_status,
            )

        payload: object
        if self.profile == "dataset":
            payload = dataset_registry_payload(
                "0" * 128
                if self.profile_conflict
                else DATASET_FINGERPRINT
            )
        else:
            payload = ingest_receipt(
                "0" * 128
                if self.profile_conflict
                else INGEST_FINGERPRINT
            )

        return self._core_response(
            {
                "ok": True,
                "hedera_network": "testnet",
                "mode": "decrypt_only",
                "verified": None,
                "topic": {
                    "name": (
                        "dataset_registry_events"
                        if self.profile == "dataset"
                        else "merkle_anchor"
                    ),
                    "topic_id": TOPIC,
                    "key_version": 1,
                },
                "encryption": {
                    "topic_key_version": 1,
                    "user_key_version": 1,
                },
                "tx": {
                    "id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                    "message_id": MESSAGE_ID,
                    "transaction_id": None,
                    "sequence_number": SEQUENCE,
                    "consensus_timestamp": "1234567890.123456789",
                    "status": "confirmed",
                    "mirror_verified": False,
                    "mirror_verified_at": None,
                },
                "hash": {
                    "expected": MESSAGE_DIGEST,
                    "computed": MESSAGE_DIGEST,
                    "match": None,
                },
                "message_binding": {
                    "schema_version": "vera.hcs-message-binding.v1",
                    "algorithm": "sha3-512",
                    "message_sha3_512": MESSAGE_DIGEST,
                    "message_bytes": len(MESSAGE),
                },
                "payload": payload,
            }
        )

    async def mirror_fetch(
        self,
        url: str,
        headers: Mapping[str, str],
        timeout_ms: int,
        max_response_bytes: int,
    ) -> HederaMirrorFetchResponseV1:
        self.mirror_calls.append(
            {
                "url": url,
                "headers": dict(headers),
            }
        )

        assert "authorization" not in {
            key.lower()
            for key in headers
        }
        assert headers == {"Accept": "application/json"}
        assert 250 <= timeout_ms <= 15_000
        assert max_response_bytes <= 4 * 1024 * 1024

        if self.mirror_state == "unavailable":
            return HederaMirrorFetchResponseV1(
                status=404,
                headers={},
                body=encoded({}),
            )

        message = (
            b"contradictory-authorized-message"
            if self.mirror_state == "conflict"
            else MESSAGE
        )
        return HederaMirrorFetchResponseV1(
            status=200,
            headers={"Content-Type": "application/json"},
            body=encoded(
                {
                    "topic_id": TOPIC,
                    "sequence_number": SEQUENCE,
                    "consensus_timestamp": "1234567890.123456789",
                    "message": base64.b64encode(message).decode("ascii"),
                }
            ),
        )

    @staticmethod
    def _core_response(
        value: object,
        status: int = 200,
    ) -> CoreAuthorizedFetchResponseV1:
        body = encoded(value)
        return CoreAuthorizedFetchResponseV1(
            status=status,
            headers={
                "Content-Type": "application/json",
                "Content-Length": str(len(body)),
            },
            body=body,
        )

    def config(self) -> AuthorizedHcsObservationsV1Config:
        return AuthorizedHcsObservationsV1Config(
            core=CoreAuthorizedV1Config(
                base_url=CORE,
                auth_provider=create_static_bearer_auth_provider_v1(
                    "test-api-key"
                ),
                fetch_impl=self.core_fetch,
            ),
            mirror=HederaMirrorV1Config(
                base_urls={"testnet": MIRROR},
                fetch_impl=self.mirror_fetch,
            ),
        )


def context(result) -> Mapping[str, object]:
    return cast(Mapping[str, object], result.report.context)


def resolution(result) -> Mapping[str, object]:
    return cast(
        Mapping[str, object],
        context(result)["resolution"],
    )


def verify(profile: Profile, transport: Transport):
    if profile == "dataset":
        return run(
            triangulate_authorized_dataset_with_policy_v1(
                transport.config(),
                dataset_input(),
                policy("dataset", DATASET_KEY),
            )
        )

    return run(
        triangulate_authorized_ingest_with_policy_v1(
            transport.config(),
            ingest_input(),
            policy("ingest", INGEST_KEY),
        )
    )


@pytest.mark.parametrize(
    ("profile", "kind"),
    [
        ("dataset", "authorized_dataset_triangulation"),
        ("ingest", "authorized_ingest_triangulation"),
    ],
)
def test_authorized_workflow_resolves_and_scopes_credentials(
    profile: Profile,
    kind: str,
) -> None:
    transport = Transport(profile)
    result = verify(profile, transport)

    assert result.policy.decision == "allow"
    assert result.policy.authority == "sdk_verification"
    assert result.report.kind == kind
    assert context(result)["consistency"] == "consistent"
    assert resolution(result)["authorized_core"] == "resolved"
    assert resolution(result)["hedera_mirror"] == "resolved"

    assert len(transport.core_calls) == 1
    assert len(transport.mirror_calls) == 1
    assert (
        transport.core_calls[0]["headers"]["Authorization"]
        == "Bearer test-api-key"
    )
    assert "authorization" not in {
        key.lower()
        for key in cast(
            Mapping[str, str],
            transport.mirror_calls[0]["headers"],
        )
    }
    assert (
        validate_portable_verification_report_v1(result.report).status
        == "valid"
    )


@pytest.mark.parametrize(
    ("profile", "core_status", "mirror_state"),
    [
        ("dataset", 403, "resolved"),
        ("ingest", 403, "resolved"),
        ("dataset", 200, "unavailable"),
        ("ingest", 200, "unavailable"),
    ],
)
def test_unavailable_authority_remains_non_authorizing(
    profile: Profile,
    core_status: int,
    mirror_state: MirrorState,
) -> None:
    transport = Transport(
        profile,
        core_status=core_status,
        mirror_state=mirror_state,
    )
    result = verify(profile, transport)

    assert result.policy.decision == "review"
    assert context(result)["consistency"] == "incomplete"

    if core_status == 403:
        assert resolution(result)["authorized_core"] == "forbidden"
        assert transport.mirror_calls == []
    else:
        assert resolution(result)["authorized_core"] == "resolved"
        assert resolution(result)["hedera_mirror"] == "unavailable"

    assert (
        validate_portable_verification_report_v1(result.report).status
        == "valid"
    )


@pytest.mark.parametrize(
    ("profile", "mirror_state", "profile_conflict"),
    [
        ("dataset", "conflict", False),
        ("ingest", "conflict", False),
        ("dataset", "resolved", True),
        ("ingest", "resolved", True),
    ],
)
def test_authorized_conflicts_deny(
    profile: Profile,
    mirror_state: MirrorState,
    profile_conflict: bool,
) -> None:
    transport = Transport(
        profile,
        mirror_state=mirror_state,
        profile_conflict=profile_conflict,
    )
    result = verify(profile, transport)

    assert result.policy.decision == "deny"
    assert context(result)["consistency"] == "conflict"

    if mirror_state == "conflict":
        assert resolution(result)["hedera_mirror"] == "resolved"
    elif profile == "dataset":
        assert resolution(result)["dataset_registry_event"] == "resolved"
    else:
        assert resolution(result)["ingest_receipt"] == "conflict"

    assert (
        validate_portable_verification_report_v1(result.report).status
        == "valid"
    )


@pytest.mark.parametrize(
    ("profile", "key"),
    [
        ("dataset", DATASET_KEY),
        ("ingest", INGEST_KEY),
    ],
)
def test_policy_network_substitution_stops_before_io(
    profile: Profile,
    key: str,
) -> None:
    transport = Transport(profile)
    wrong = VerificationPolicyV1(
        schema_version=VERIFICATION_POLICY_SCHEMA_VERSION,
        subject=subject(profile, key, "mainnet"),
        report_kind=(
            "authorized_dataset_triangulation"
            if profile == "dataset"
            else "authorized_ingest_triangulation"
        ),
        required_checks=(
            f"{profile}.source_binding",
        ),
        required_assurance=("mirror_corroboration",),
    )

    with pytest.raises(TypeError, match="policy intent"):
        if profile == "dataset":
            run(
                triangulate_authorized_dataset_with_policy_v1(
                    transport.config(),
                    dataset_input(),
                    wrong,
                )
            )
        else:
            run(
                triangulate_authorized_ingest_with_policy_v1(
                    transport.config(),
                    ingest_input(),
                    wrong,
                )
            )

    assert transport.core_calls == []
    assert transport.mirror_calls == []