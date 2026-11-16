import asyncio
import base64
import copy
import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import cast

from vera_anchor_verifier.contracts import VerificationIntent, VerificationSubject
from vera_anchor_verifier.policy.contract_v1 import (
    VERIFICATION_POLICY_SCHEMA_VERSION,
    VerificationPolicyExecutionScopeV1,
    VerificationPolicyV1,
)
from vera_anchor_verifier.policy.evaluate_v1 import (
    verify_execution_standards_with_policy_v1,
)
from vera_anchor_verifier.profiles.execution.recomputation_v1 import (
    compute_execution_domain_separated_sha3_512,
)
from vera_anchor_verifier.profiles.execution.verification_v1 import ExecutionV1Input
from vera_anchor_verifier.reports.validation_v1 import (
    validate_portable_verification_report_v1,
)
from vera_anchor_verifier.resolvers.hcs1_mirror_v1 import Hcs1MirrorV1Config
from vera_anchor_verifier.resolvers.hedera_mirror_v1 import HederaMirrorFetchResponseV1
from vera_anchor_verifier.standards.hcs.hcs1_v1 import Hcs1V1ContentOptions
from vera_anchor_verifier.standards.hcs.hcs11_v1 import (
    MAX_HCS11_V1_PROFILE_BYTES,
)
from vera_anchor_verifier.standards.hcs.hcs13_v1 import (
    finalize_hcs13_schema_v1,
)
from vera_anchor_verifier.standards.hcs.hcs14_v1 import (
    build_hcs14_did_uaid_v1,
)
from vera_anchor_verifier.standards.hcs.hcs26_v1 import (
    finalize_hcs26_skill_manifest_v1,
)
from vera_anchor_verifier.standards.hcs.json_canonical_v1 import (
    canonical_hcs_json_v1,
)

BASE = "https://testnet.mirrornode.hedera.com/api/v1"
JOB = "f365ad8e-bf03-5654-8b8c-9d54eddffac1"
COMMIT = "a" * 40


def run[T](coro) -> T:
    return asyncio.run(coro)


def b64(value: bytes | str) -> str:
    raw = value.encode() if isinstance(value, str) else value
    return base64.b64encode(raw).decode("ascii")


def sha256(value: bytes | str) -> str:
    raw = value.encode() if isinstance(value, str) else value
    return hashlib.sha256(raw).hexdigest()


def response(value: object, status: int = 200) -> HederaMirrorFetchResponseV1:
    return HederaMirrorFetchResponseV1(
        status=status,
        headers={"content-type": "application/json"},
        body=json.dumps(value, separators=(",", ":")).encode(),
    )


@dataclass
class Fixture:
    routes: dict[str, object]
    compressed: dict[bytes, bytes]
    evidence: dict[str, object]
    requests: list[str] = field(default_factory=list)

    async def fetch(
        self,
        url: str,
        headers: Mapping[str, str],
        timeout_ms: int,
        max_response_bytes: int,
    ) -> HederaMirrorFetchResponseV1:
        self.requests.append(url)
        assert headers == {"Accept": "application/json"}
        assert 250 <= timeout_ms <= 15_000
        assert 1024 <= max_response_bytes <= 4 * 1024 * 1024

        if url not in self.routes:
            return response({}, 404)

        return response(self.routes[url])

    def options(self) -> Hcs1V1ContentOptions:
        def decompress(data: bytes, limit: int) -> bytes:
            raw = self.compressed[data]

            if len(raw) > limit:
                raise ValueError("HCS1_FILE_TOO_LARGE")

            return raw

        return Hcs1V1ContentOptions(decompress_zstd=decompress)

    def config(self) -> Hcs1MirrorV1Config:
        return Hcs1MirrorV1Config(fetch_impl=self.fetch)


def registry(
    routes: dict[str, object],
    topic: str,
    sequence: int,
    memo: str,
    message: object,
) -> None:
    routes[f"{BASE}/topics/{topic}"] = {
        "topic_id": topic,
        "memo": memo,
    }
    routes[f"{BASE}/topics/{topic}/messages/{sequence}"] = {
        "topic_id": topic,
        "sequence_number": sequence,
        "consensus_timestamp": f"1792039124.{sequence:09d}",
        "message": b64(json.dumps(message, separators=(",", ":"))),
    }


def hcs1(
    routes: dict[str, object],
    compressed: dict[bytes, bytes],
    topic: str,
    raw: bytes,
) -> None:
    token = f"fixture:{topic}".encode()
    compressed[token] = raw

    payload = json.dumps(
        {
            "o": 0,
            "c": f"data:application/json;base64,{b64(token)}",
        },
        separators=(",", ":"),
    ).encode()

    routes[f"{BASE}/topics/{topic}"] = {
        "topic_id": topic,
        "memo": f"{sha256(raw)}:zstd:base64",
        "submit_key": {"key": "present"},
        "admin_key": None,
    }
    routes[f"{BASE}/topics/{topic}/messages?limit=100&order=asc"] = {
        "messages": [
            {
                "topic_id": topic,
                "sequence_number": 1,
                "message": b64(payload),
            }
        ],
        "links": {"next": None},
    }


def fixture() -> Fixture:
    routes: dict[str, object] = {}
    compressed: dict[bytes, bytes] = {}
    agents: dict[str, object] = {}

    for index, role in ((1, "requester"), (2, "executor")):
        account = f"0.0.{7100 + index}"
        registry_topic = f"0.0.{7000 + index}"
        profile_topic = f"0.0.{7200 + index}"
        did = f"did:web:agent{index}.example.org"

        uaid = build_hcs14_did_uaid_v1(
            base_did=did,
            uid=f"agent{index}",
            registry="self",
            proto="hcs-26",
            native_id=f"hedera:testnet:{account}",
        ).uaid

        profile = canonical_hcs_json_v1(
            {
                "version": "1.1",
                "type": 1,
                "display_name": f"Agent {index}",
                "uaid": uaid,
                "aiAgent": {
                    "type": 1,
                    "capabilities": [0],
                    "model": "agent",
                },
            },
            MAX_HCS11_V1_PROFILE_BYTES,
        )

        routes[f"{BASE}/accounts/{account}"] = {
            "account": account,
            "memo": f"hcs-11:hcs://2/{registry_topic}",
        }
        registry(
            routes,
            registry_topic,
            1,
            "hcs-2:0:86400",
            {
                "p": "hcs-2",
                "op": "register",
                "t_id": profile_topic,
            },
        )
        hcs1(
            routes,
            compressed,
            profile_topic,
            profile.encode(),
        )

        agents[role] = {
            "logical_id": f"agent{index}",
            "base_did": did,
            "hcs14_uaid": uaid,
            "hcs11": {
                "account_id": account,
                "profile_registry_topic_id": registry_topic,
                "profile_registry_sequence": 1,
                "profile_hcs1_ref": f"hcs://1/{profile_topic}",
                "profile_checksum_sha256": sha256(profile),
            },
        }

    schema = finalize_hcs13_schema_v1(
        {
            "type": "object",
            "properties": {
                "value": {"type": "integer"},
            },
        }
    )

    registry(
        routes,
        "0.0.9001",
        7,
        "hcs-2:0:86400",
        {
            "p": "hcs-2",
            "op": "register",
            "t_id": "0.0.9002",
        },
    )
    hcs1(
        routes,
        compressed,
        "0.0.9002",
        schema.canonical_payload.encode(),
    )

    skill_file = b"# Capability\n"
    manifest = finalize_hcs26_skill_manifest_v1(
        {
            "name": "Capability",
            "description": "A capability",
            "version": "1.0.0",
            "license": "MIT",
            "author": "Person",
            "commit": COMMIT,
            "files": [
                {
                    "path": "SKILL.md",
                    "hrl": "hcs://1/0.0.8100",
                    "sha256": sha256(skill_file),
                    "mime": "text/markdown",
                }
            ],
        }
    )

    registry(
        routes,
        "0.0.8001",
        42,
        "hcs-26:0:86400:0",
        {
            "p": "hcs-26",
            "op": "register",
            "t_id": "0.0.8002",
            "account_id": "0.0.7999",
            "metadata": "hcs://1/0.0.7998",
        },
    )
    registry(
        routes,
        "0.0.8002",
        3,
        "hcs-26:0:86400:1",
        {
            "p": "hcs-26",
            "op": "register",
            "skill_uid": 42,
            "version": "1.0.0",
            "t_id": "0.0.8003",
            "checksum": f"sha256:{manifest.sha256}",
            "status": "active",
        },
    )

    hcs1(
        routes,
        compressed,
        "0.0.8003",
        manifest.canonical_payload.encode(),
    )
    hcs1(
        routes,
        compressed,
        "0.0.8100",
        skill_file,
    )

    digest_payload = {
        "result": {"x": 1},
        "id": JOB,
    }
    binding = compute_execution_domain_separated_sha3_512(
        "vera-anchor:execution-binding:v1",
        digest_payload,
    )

    evidence: dict[str, object] = {
        "available": True,
        "contract_version": "1.0.0",
        "execution": {
            "program": "sage",
            "job_id": JOB,
            "proof_date": "2026-10-15",
            "hedera_network": "testnet",
        },
        "binding": {
            "schema": "ExecutionBindingV1",
            "canonicalization": "RFC8785-JCS",
            "digest_algorithm": "SHA3-512",
            "domain_separator": "vera-anchor:execution-binding:v1",
            "finalized_at": "2026-10-15T00:00:00Z",
            "digest_payload": digest_payload,
            "digest": binding,
        },
        "agents": agents,
        "capability": {
            "standard": "HCS-26",
            "discovery_registry_topic_id": "0.0.8001",
            "skill_uid": "42",
            "skill_version": "1.0.0",
            "version_registry_topic_id": "0.0.8002",
            "version_sequence_number": 3,
            "manifest_hcs1_ref": "hcs://1/0.0.8003",
            "manifest_checksum_sha256": manifest.sha256,
            "repository_uri": "https://example.org/repo",
            "repository_commit": COMMIT,
        },
        "standards": {
            "schemas": [
                {
                    "role": "parameters",
                    "ordinal": 0,
                    "registry_topic_id": "0.0.9001",
                    "registry_sequence_number": 7,
                    "hcs13_ref": "hcs://13/0.0.9001#7",
                    "schema_checksum_sha256": schema.sha256,
                }
            ]
        },
    }

    return Fixture(
        routes=routes,
        compressed=compressed,
        evidence=evidence,
    )


def intent() -> VerificationIntent:
    return cast(
        VerificationIntent,
        {
            "subject": {
                "kind": "execution",
                "id": JOB,
                "hedera_network": "testnet",
            },
            "expected": [],
        },
    )


def execution_input(
    evidence: dict[str, object],
    *,
    expected_program: str = "sage",
) -> ExecutionV1Input:
    return cast(
        ExecutionV1Input,
        {
            "profile": "sage-standards-v1",
            "expected_program": expected_program,
            "evidence": evidence,
            "intent": intent(),
        },
    )


def policy() -> VerificationPolicyV1:
    subject = cast(
        VerificationSubject,
        intent()["subject"],
    )

    return VerificationPolicyV1(
        schema_version=VERIFICATION_POLICY_SCHEMA_VERSION,
        subject=subject,
        report_kind="independent_standards",
        required_checks=(
            "binding.digest_recomputed",
            "standards.references_resolved",
        ),
        required_assurance=("mirror_corroboration",),
        execution_scope=VerificationPolicyExecutionScopeV1(
            profile="sage-standards-v1",
            expected_program="sage",
            requested_result_id=None,
        ),
        on_unresolved="review",
    )


def verify(
    fixture: Fixture,
    value: ExecutionV1Input | None = None,
):
    return run(
        verify_execution_standards_with_policy_v1(
            fixture.config(),
            value or execution_input(fixture.evidence),
            fixture.options(),
            policy(),
        )
    )


def requirement(workflow, key: str):
    return next(
        item
        for item in workflow.policy.requirements
        if item.key == key
    )


def standards_context(workflow) -> Mapping[str, object]:
    value = workflow.report.context["independent_standards"]

    assert isinstance(value, Mapping)

    return cast(
        Mapping[str, object],
        value,
    )


def standards_items(workflow) -> tuple[Mapping[str, object], ...]:
    raw = standards_context(workflow)["items"]

    assert isinstance(raw, Sequence)

    return tuple(
        cast(Mapping[str, object], item)
        for item in raw
    )


def test_resolved_standards_flow_allows_policy() -> None:
    f = fixture()
    result = verify(f)
    standards = standards_context(result)

    assert result.report.kind == "independent_standards"
    assert result.policy.authority == "sdk_verification"
    assert result.policy.decision == "allow"
    assert standards["status"] == "verified"
    assert standards["assurance"] == "mirror_corroborated"
    assert [
        item["status"]
        for item in standards_items(result)
    ] == [
        "resolved",
        "resolved",
        "resolved",
        "resolved",
    ]
    assert (
        requirement(
            result,
            "assurance.mirror_corroboration",
        ).outcome
        == "pass"
    )
    assert (
        validate_portable_verification_report_v1(
            result.report
        ).status
        == "valid"
    )
    assert len(f.requests) > 10


def test_direct_hcs1_memo_requires_historical_hcs2_binding() -> None:
    f = fixture()

    f.routes[f"{BASE}/accounts/0.0.7101"] = {
        "account": "0.0.7101",
        "memo": "hcs-11:hcs://1/0.0.7201",
    }

    result = verify(f)
    items = standards_items(result)

    assert result.policy.decision == "allow"
    assert items[0]["historical_consensus_timestamps_exact"] == [
        "1792039124.000000001"
    ]
    assert f.requests.count(
        f"{BASE}/accounts/0.0.7101"
    ) == 2
    assert (
        f"{BASE}/topics/0.0.7001/messages/1"
        in f.requests
    )


def test_missing_account_remains_unresolved_and_non_authorizing() -> None:
    f = fixture()
    del f.routes[f"{BASE}/accounts/0.0.7101"]

    result = verify(f)
    standards = standards_context(result)

    assert standards["status"] == "unavailable"
    assert standards["assurance"] == "not_established"
    assert standards_items(result)[0]["status"] == "unavailable"
    assert result.policy.decision == "review"
    assert (
        requirement(
            result,
            "assurance.mirror_corroboration",
        ).outcome
        == "unresolved"
    )
    assert (
        validate_portable_verification_report_v1(
            result.report
        ).status
        == "valid"
    )


def test_scope_mismatch_stops_before_network_io() -> None:
    f = fixture()

    result = verify(
        f,
        execution_input(
            f.evidence,
            expected_program="other",
        ),
    )

    assert f.requests == []
    assert result.policy.decision != "allow"
    assert (
        standards_context(result)["status"]
        == "not_performed"
    )


def test_schema_and_capability_conflicts_fail_closed() -> None:
    f = fixture()
    bad_schema = copy.deepcopy(f.evidence)
    standards = cast(
        dict[str, object],
        bad_schema["standards"],
    )
    schemas = cast(
        list[dict[str, object]],
        standards["schemas"],
    )
    schemas[0]["registry_sequence_number"] = 8

    schema_result = verify(
        f,
        execution_input(bad_schema),
    )
    schema_items = standards_items(schema_result)

    assert schema_items[-1]["status"] == "conflict"
    assert schema_items[-1]["reason_code"] == (
        "HCS13_EXECUTION_REFERENCE_SCOPE_MISMATCH"
    )
    assert schema_result.policy.decision == "deny"
    assert not any(
        "/topics/0.0.9001" in url
        for url in f.requests
    )

    g = fixture()
    bad_capability = copy.deepcopy(g.evidence)
    capability = cast(
        dict[str, object],
        bad_capability["capability"],
    )
    capability["repository_commit"] = "c" * 40

    capability_result = verify(
        g,
        execution_input(bad_capability),
    )
    capability_items = standards_items(
        capability_result
    )

    assert capability_items[2]["status"] == "conflict"
    assert capability_items[2]["reason_code"] == (
        "HCS26_EXECUTION_RELEASE_COMMIT_MISMATCH"
    )
    assert capability_result.policy.decision == "deny"