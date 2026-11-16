import asyncio
import base64
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Literal, cast
from urllib.parse import urlsplit

import pytest

from vera_anchor_verifier import sha3_512_hex
from vera_anchor_verifier.contracts import VerificationSubject
from vera_anchor_verifier.policy.contract_v1 import (
    VERIFICATION_POLICY_SCHEMA_VERSION,
    VerificationPolicyV1,
)
from vera_anchor_verifier.policy.evaluate_v1 import (
    triangulate_dataset_with_policy_v1,
    triangulate_ingest_with_policy_v1,
)
from vera_anchor_verifier.profiles.source_v1_helpers import SourceV1File
from vera_anchor_verifier.reports.validation_v1 import (
    validate_portable_verification_report_v1,
)
from vera_anchor_verifier.resolvers.explorer_transport_v1 import (
    ExplorerFetchResponseV1,
    ExplorerPublicTransportV1,
)
from vera_anchor_verifier.resolvers.hedera_mirror_v1 import (
    HederaMirrorFetchResponseV1,
    HederaMirrorV1Config,
)
from vera_anchor_verifier.triangulation.public_v1 import (
    PublicTriangulationV1Config,
)

EXPLORER = "https://explorer.example.test"
MIRROR = "https://mirror.example.test/api/v1"
ANCHOR = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
VERSION = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
TOPIC = "0.0.12345"
TX = "0.0.77@1234567890.123456789"
MESSAGE = b"encrypted-publication-envelope"
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
                "4a936cbc1db296bd08d1c0bbf5a66a1897f35ee6d93047e0edff893dfbcba02"
                "f1e1570e85d1187ea26bea6d54199e0656f1b7c21b9cc2102b8ed2a12769f4531"
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
type State = Literal[
    "consistent",
    "unavailable",
    "conflict",
    "wrong_anchor",
    "wrong_network",
]


def run[T](coro) -> T:
    return asyncio.run(coro)


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


def intent(profile: Profile, key: str) -> dict[str, object]:
    return {
        "subject": subject(profile, key),
        "expected": [],
    }


def policy(
    profile: Profile,
    key: str,
    network: Literal["mainnet", "testnet"] = "testnet",
) -> VerificationPolicyV1:
    return VerificationPolicyV1(
        schema_version=VERIFICATION_POLICY_SCHEMA_VERSION,
        subject=subject(profile, key, network),
        report_kind="public_triangulation",
        required_checks=(
            f"{profile}.source_binding",
            f"{profile}.bundle_consistency",
            "triangulation.public_record_hedera.message_sha3_512",
        ),
        required_assurance=("mirror_corroboration",),
        on_unresolved="review",
    )


def encoded(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":")).encode()


@dataclass
class Transport:
    profile: Profile
    key: str
    fingerprint: str
    bundle_digest: str | None = None
    state: State = "consistent"
    requests: list[str] = field(default_factory=list)

    async def explorer_fetch(
        self,
        url: str,
        method: str,
        headers: Mapping[str, str],
        body: bytes | None,
        timeout_ms: int,
        max_response_bytes: int,
    ) -> ExplorerFetchResponseV1:
        del headers, timeout_ms, max_response_bytes
        self.requests.append(url)
        path = urlsplit(url).path

        if self.profile == "dataset" and path == f"/v1/datasets/{self.key}":
            assert method == "GET"
            assert body is None
            return self._explorer(
                {
                    "hedera_network": (
                        "mainnet" if self.state == "wrong_network" else "testnet"
                    ),
                    "dataset_key": self.key,
                    "dataset_version_id": VERSION,
                    "dataset_fingerprint": self.fingerprint,
                    "publication_version_transaction_id": TX,
                    "publication_version_message_id": f"5@{TOPIC}",
                    "publication_version_topic_id": TOPIC,
                    "publication_version_sequence_number": 5,
                }
            )

        if self.profile == "ingest" and path == f"/v1/merkle/anchors/{ANCHOR}":
            assert method == "GET"
            assert body is None
            return self._explorer(
                {
                    "hedera_network": (
                        "mainnet" if self.state == "wrong_network" else "testnet"
                    ),
                    "anchor_request_id": (
                        "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
                        if self.state == "wrong_anchor"
                        else ANCHOR
                    ),
                    "ingest_object_key": self.key,
                    "ingest_fingerprint": self.fingerprint,
                    "ingest_bundle_digest": self.bundle_digest,
                    "publication_anchor_transaction_id": TX,
                    "publication_anchor_message_id": f"5@{TOPIC}",
                    "publication_anchor_topic_id": TOPIC,
                    "publication_anchor_sequence_number": 5,
                }
            )

        if path == "/v1/hcs/verify-decrypt":
            assert method == "POST"
            assert body is not None

            if self.profile == "dataset":
                entity_kind = "dataset_version"
                entity_id = VERSION
                proof: dict[str, object] = {
                    "dataset_key": self.key,
                    "fingerprint": self.fingerprint,
                }
            else:
                entity_kind = "merkle_anchor"
                entity_id = ANCHOR
                proof = {
                    "ingest_object_key": self.key,
                    "ingest_fingerprint": self.fingerprint,
                    "ingest_bundle_digest": self.bundle_digest,
                }

            return self._explorer(
                {
                    "hedera_network": "testnet",
                    "verified": True,
                    "hash": {"match": True},
                    "tx": {
                        "transaction_id": TX,
                        "message_id": f"5@{TOPIC}",
                    },
                    "topic": {"topic_id": TOPIC},
                    "message_binding": {
                        "schema_version": "vera.hcs-message-binding.v1",
                        "algorithm": "sha3-512",
                        "message_sha3_512": MESSAGE_DIGEST,
                        "message_bytes": len(MESSAGE),
                    },
                    "payload": {
                        "schema": "va:explorer_publication_receipt:v1",
                        "event_type": "published",
                        "event_version": 1,
                        "entity_kind": entity_kind,
                        "entity_id": entity_id,
                        "visibility": "public",
                        "proof": proof,
                    },
                }
            )

        raise AssertionError(f"Unexpected Explorer request: {url}")

    async def mirror_fetch(
        self,
        url: str,
        headers: Mapping[str, str],
        timeout_ms: int,
        max_response_bytes: int,
    ) -> HederaMirrorFetchResponseV1:
        del headers, timeout_ms, max_response_bytes
        self.requests.append(url)
        path = urlsplit(url).path

        if path == f"/api/v1/topics/{TOPIC}/messages/5":
            if self.state == "unavailable":
                return HederaMirrorFetchResponseV1(
                    status=404,
                    headers={},
                    body=encoded({}),
                )

            message = (
                b"mismatched-publication"
                if self.state == "conflict"
                else MESSAGE
            )
            return HederaMirrorFetchResponseV1(
                status=200,
                headers={},
                body=encoded(
                    {
                        "topic_id": TOPIC,
                        "sequence_number": 5,
                        "consensus_timestamp": "1234567890.123456789",
                        "message": base64.b64encode(message).decode(),
                    }
                ),
            )

        if path == "/api/v1/transactions/0.0.77-1234567890-123456789":
            return HederaMirrorFetchResponseV1(
                status=200,
                headers={},
                body=encoded(
                    {
                        "transactions": [
                            {
                                "transaction_id": (
                                    "0.0.77-1234567890-123456789"
                                ),
                                "result": "SUCCESS",
                                "consensus_timestamp": (
                                    "1234567890.123456790"
                                ),
                            }
                        ]
                    }
                ),
            )

        raise AssertionError(f"Unexpected Mirror request: {url}")

    @staticmethod
    def _explorer(
        body: object,
        status: int = 200,
    ) -> ExplorerFetchResponseV1:
        return ExplorerFetchResponseV1(
            status=status,
            headers={},
            body=encoded(body),
        )

    def config(self) -> PublicTriangulationV1Config:
        return PublicTriangulationV1Config(
            explorer=ExplorerPublicTransportV1(
                base_url=EXPLORER,
                fetch_impl=self.explorer_fetch,
            ),
            mirror=HederaMirrorV1Config(
                base_urls={"testnet": MIRROR},
                fetch_impl=self.mirror_fetch,
            ),
        )


def context(result) -> Mapping[str, object]:
    return cast(Mapping[str, object], result.report.context)


def resolution(result) -> Mapping[str, object]:
    return cast(Mapping[str, object], context(result)["resolution"])


def test_public_dataset_resolves_and_allows() -> None:
    transport = Transport(
        "dataset",
        DATASET_KEY,
        DATASET_FINGERPRINT,
    )

    result = run(
        triangulate_dataset_with_policy_v1(
            transport.config(),
            bundle=DATASET_BUNDLE,
            files=dataset_files(),
            intent=intent("dataset", DATASET_KEY),
            policy=policy("dataset", DATASET_KEY),
        )
    )

    assert result.policy.decision == "allow"
    assert result.policy.authority == "sdk_verification"
    assert result.report.kind == "public_triangulation"
    assert "publication_payload_binding" not in context(result)
    assert context(result)["consistency"] == "consistent"   
    assert resolution(result) == {
        "public_record": "resolved",
        "publication_disclosure": "resolved",
        "hedera_mirror": "resolved",
    }
    assert (
        validate_portable_verification_report_v1(result.report).status
        == "valid"
    )
    assert len(transport.requests) == 4


def test_public_ingest_resolves_and_allows() -> None:
    transport = Transport(
        "ingest",
        INGEST_KEY,
        INGEST_FINGERPRINT,
        INGEST_BUNDLE_DIGEST,
    )

    result = run(
        triangulate_ingest_with_policy_v1(
            transport.config(),
            bundle=INGEST_BUNDLE,
            material=INGEST_MATERIAL,
            intent=intent("ingest", INGEST_KEY),
            anchor_request_id=ANCHOR,
            policy=policy("ingest", INGEST_KEY),
        )
    )

    assert result.policy.decision == "allow"
    assert result.policy.authority == "sdk_verification"
    assert result.report.kind == "public_triangulation"
    assert resolution(result) == {
        "public_record": "resolved",
        "publication_disclosure": "resolved",
        "hedera_mirror": "resolved",
    }
    assert any(
        urlsplit(url).path == f"/v1/merkle/anchors/{ANCHOR}"
        for url in transport.requests
    )
    assert (
        validate_portable_verification_report_v1(result.report).status
        == "valid"
    )
    assert len(transport.requests) == 4


@pytest.mark.parametrize(
    ("profile", "state", "decision", "consistency"),
    [
        ("dataset", "unavailable", "review", "incomplete"),
        ("dataset", "conflict", "deny", "conflict"),
        ("ingest", "unavailable", "review", "incomplete"),
        ("ingest", "conflict", "deny", "conflict"),
    ],
)
def test_mirror_failure_semantics(
    profile: Profile,
    state: State,
    decision: str,
    consistency: str,
) -> None:
    if profile == "dataset":
        transport = Transport(
            profile,
            DATASET_KEY,
            DATASET_FINGERPRINT,
            state=state,
        )
        result = run(
            triangulate_dataset_with_policy_v1(
                transport.config(),
                bundle=DATASET_BUNDLE,
                files=dataset_files(),
                intent=intent(profile, DATASET_KEY),
                policy=policy(profile, DATASET_KEY),
            )
        )
    else:
        transport = Transport(
            profile,
            INGEST_KEY,
            INGEST_FINGERPRINT,
            INGEST_BUNDLE_DIGEST,
            state,
        )
        result = run(
            triangulate_ingest_with_policy_v1(
                transport.config(),
                bundle=INGEST_BUNDLE,
                material=INGEST_MATERIAL,
                intent=intent(profile, INGEST_KEY),
                anchor_request_id=ANCHOR,
                policy=policy(profile, INGEST_KEY),
            )
        )

    assert result.policy.decision == decision
    assert context(result)["consistency"] == consistency

    if state == "unavailable":
        assert resolution(result)["hedera_mirror"] != "resolved"
    else:
        assert resolution(result)["hedera_mirror"] == "resolved"

    assert (
        validate_portable_verification_report_v1(result.report).status
        == "valid"
    )


def test_wrong_policy_network_stops_before_io() -> None:
    dataset_transport = Transport(
        "dataset",
        DATASET_KEY,
        DATASET_FINGERPRINT,
    )

    with pytest.raises(TypeError, match="policy intent"):
        run(
            triangulate_dataset_with_policy_v1(
                dataset_transport.config(),
                bundle=DATASET_BUNDLE,
                files=dataset_files(),
                intent=intent("dataset", DATASET_KEY),
                policy=policy(
                    "dataset",
                    DATASET_KEY,
                    "mainnet",
                ),
            )
        )

    assert dataset_transport.requests == []

    ingest_transport = Transport(
        "ingest",
        INGEST_KEY,
        INGEST_FINGERPRINT,
        INGEST_BUNDLE_DIGEST,
    )

    with pytest.raises(TypeError, match="policy intent"):
        run(
            triangulate_ingest_with_policy_v1(
                ingest_transport.config(),
                bundle=INGEST_BUNDLE,
                material=INGEST_MATERIAL,
                intent=intent("ingest", INGEST_KEY),
                anchor_request_id=ANCHOR,
                policy=policy(
                    "ingest",
                    INGEST_KEY,
                    "mainnet",
                ),
            )
        )

    assert ingest_transport.requests == []


def test_ingest_anchor_substitution_denies_before_mirror() -> None:
    transport = Transport(
        "ingest",
        INGEST_KEY,
        INGEST_FINGERPRINT,
        INGEST_BUNDLE_DIGEST,
        "wrong_anchor",
    )

    result = run(
        triangulate_ingest_with_policy_v1(
            transport.config(),
            bundle=INGEST_BUNDLE,
            material=INGEST_MATERIAL,
            intent=intent("ingest", INGEST_KEY),
            anchor_request_id=ANCHOR,
            policy=policy("ingest", INGEST_KEY),
        )
    )

    assert result.policy.decision == "deny"
    assert resolution(result)["public_record"] == "conflict"
    assert resolution(result)["hedera_mirror"] == "not_requested"
    assert len(transport.requests) == 1


def test_wrong_network_public_records_never_authorize() -> None:
    dataset_transport = Transport(
        "dataset",
        DATASET_KEY,
        DATASET_FINGERPRINT,
        state="wrong_network",
    )

    dataset_result = run(
        triangulate_dataset_with_policy_v1(
            dataset_transport.config(),
            bundle=DATASET_BUNDLE,
            files=dataset_files(),
            intent=intent("dataset", DATASET_KEY),
            policy=policy("dataset", DATASET_KEY),
        )
    )

    assert dataset_result.policy.decision != "allow"

    ingest_transport = Transport(
        "ingest",
        INGEST_KEY,
        INGEST_FINGERPRINT,
        INGEST_BUNDLE_DIGEST,
        "wrong_network",
    )

    ingest_result = run(
        triangulate_ingest_with_policy_v1(
            ingest_transport.config(),
            bundle=INGEST_BUNDLE,
            material=INGEST_MATERIAL,
            intent=intent("ingest", INGEST_KEY),
            anchor_request_id=ANCHOR,
            policy=policy("ingest", INGEST_KEY),
        )
    )

    assert ingest_result.policy.decision != "allow"