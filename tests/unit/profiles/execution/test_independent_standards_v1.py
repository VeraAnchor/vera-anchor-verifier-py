
import asyncio
from dataclasses import asdict
from types import SimpleNamespace
from typing import cast

import pytest

import vera_anchor_verifier.profiles.execution.independent_standards_v1 as adapter
from vera_anchor_verifier.contracts import VerificationIntent
from vera_anchor_verifier.profiles.execution.verification_v1 import ExecutionV1Input
from vera_anchor_verifier.resolvers.hcs1_mirror_v1 import Hcs1MirrorV1Config
from vera_anchor_verifier.standards.hcs.hcs13_v1 import parse_hcs13_reference_v1
from vera_anchor_verifier.standards.hcs.hcs14_v1 import build_hcs14_did_uaid_v1

JOB = "f365ad8e-bf03-5654-8b8c-9d54eddffac1"
DID = "did:web:agents.example.org"
COMMIT = "d" * 40

REQUESTER = "0.0.7001"
EXECUTOR = "0.0.7002"
REQUESTER_PROFILE = "0.0.7201"
EXECUTOR_PROFILE = "0.0.7202"
REQUESTER_REGISTRY = "0.0.7101"
EXECUTOR_REGISTRY = "0.0.7102"

DISCOVERY = "0.0.7301"
VERSION_TOPIC = "0.0.7302"
MANIFEST_TOPIC = "0.0.7303"
SCHEMA_TOPIC = "0.0.7401"
SCHEMA_SEQUENCE = 7

REQUESTER_SHA = "a" * 64
EXECUTOR_SHA = "b" * 64
MANIFEST_SHA = "c" * 64
SCHEMA_SHA = "e" * 64


def uaid(account: str, uid: str) -> str:
    return build_hcs14_did_uaid_v1(
        base_did=DID,
        uid=uid,
        registry="self",
        proto="hcs-26",
        native_id=f"hedera:testnet:{account}",
    ).uaid


def agent(account: str, role: str, profile: str, registry: str,
          sequence: int, checksum: str) -> dict[str, object]:
    return {
        "logical_id": role,
        "hcs14_uaid": uaid(account, role),
        "base_did": DID,
        "hcs11": {
            "account_id": account,
            "profile_registry_topic_id": registry,
            "profile_registry_sequence": sequence,
            "profile_hcs1_ref": f"hcs://1/{profile}",
            "profile_checksum_sha256": checksum,
        },
    }


def evidence() -> dict[str, object]:
    return {
        "available": True,
        "contract_version": "1.0.0",
        "execution": {
            "job_id": JOB,
            "program": "sage",
            "proof_date": "2026-10-15",
            "hedera_network": "testnet",
            "pipeline_hash": "f" * 128,
        },
        "agents": {
            "requester": agent(
                REQUESTER, "requester", REQUESTER_PROFILE,
                REQUESTER_REGISTRY, 11, REQUESTER_SHA,
            ),
            "executor": agent(
                EXECUTOR, "executor", EXECUTOR_PROFILE,
                EXECUTOR_REGISTRY, 12, EXECUTOR_SHA,
            ),
        },
        "capability": {
            "standard": "HCS-26",
            "discovery_registry_topic_id": DISCOVERY,
            "skill_uid": 42,
            "skill_version": "1.2.3",
            "version_registry_topic_id": VERSION_TOPIC,
            "version_sequence_number": 3,
            "manifest_hcs1_ref": f"hcs://1/{MANIFEST_TOPIC}",
            "manifest_checksum_sha256": MANIFEST_SHA,
            "repository_uri": "https://example.org/repo",
            "repository_commit": COMMIT,
        },
        "standards": {
            "schemas": [{
                "role": "parameters",
                "ordinal": 0,
                "registry_topic_id": SCHEMA_TOPIC,
                "registry_sequence_number": SCHEMA_SEQUENCE,
                "hcs13_ref": f"hcs://13/{SCHEMA_TOPIC}#{SCHEMA_SEQUENCE}",
                "schema_checksum_sha256": SCHEMA_SHA,
            }],
        },
    }


def intent() -> VerificationIntent:
    return cast(VerificationIntent, {
        "subject": {
            "kind": "execution",
            "id": JOB,
            "hedera_network": "testnet",
        },
        "expected": [],
    })


def execution_input(
    value: dict[str, object] | None = None,
    **extra: object,
) -> ExecutionV1Input:
    raw: dict[str, object] = {
        "profile": "sage-standards-v1",
        "expected_program": "sage",
        "evidence": value if value is not None else evidence(),
        "intent": intent(),
    }
    raw.update(extra)
    return cast(ExecutionV1Input, raw)


def verify(value: dict[str, object] | None = None, **extra: object):
    return asyncio.run(
        adapter.verify_execution_with_independent_standards_v1(
            Hcs1MirrorV1Config(),
            execution_input(value, **extra),
        )
    )


def finding(report, check_id: str):
    return next(
        entry for entry in report.findings
        if entry.check_id == check_id
    )


def item(report, key: str):
    return next(
        entry for entry in report.independent_standards.items
        if entry.key == key
    )


def hcs11_resolved(request):
    requester = request.account_id == REQUESTER
    timestamp = (
        "1792039124.000000001" if requester
        else "1792039124.000000002"
    )
    return SimpleNamespace(
        status="resolved",
        reason_code=None,
        resolver_id="hedera.mirror-rest.hcs11.v1",
        account_id=request.account_id,
        account_memo=SimpleNamespace(
            profile_reference=request.expected_profile_reference,
            protocol="hcs-2",
        ),
        registry_entry=SimpleNamespace(consensus_timestamp=timestamp),
        profile_reference=request.expected_hcs1_reference,
        content_sha256=request.expected_hcs1_sha256,
        canonical_profile_sha256=request.expected_profile_sha256,
        profile=SimpleNamespace(uaid=request.expected_uaid),
        did_binding="match",
    )


def install_resolved(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    calls: list[str] = []

    async def hcs11(config, request, decode_options=None):
        del config, decode_options
        calls.append(f"hcs11:{request.account_id}")
        return hcs11_resolved(request)

    async def hcs13(config, request, decode_options=None):
        del config, decode_options
        calls.append("hcs13")
        return SimpleNamespace(
            status="resolved",
            reason_code=None,
            resolver_id="hedera.mirror-rest.hcs13.v1",
            reference=parse_hcs13_reference_v1(request.reference),
            registry_consensus_timestamp_exact="1792039124.000000005",
            content_sha256=request.expected_schema_sha256,
            schema_sha256=request.expected_schema_sha256,
        )

    async def hcs26(config, request, decode_options=None):
        del config, decode_options
        calls.append("hcs26")
        return SimpleNamespace(
            status="resolved",
            reason_code=None,
            resolver_id="hedera.mirror-rest.hcs26.v1",
            discovery_consensus_timestamp_exact="1792039124.000000003",
            version_consensus_timestamp_exact="1792039124.000000004",
            content_sha256=request.expected_manifest_sha256,
            manifest_sha256=request.expected_manifest_sha256,
            skill_uid=request.expected_skill_uid,
            version=request.expected_version,
            historical_version_status="active",
            manifest={"commit": COMMIT},
        )

    async def unexpected_hcs2(*args, **kwargs):
        del args, kwargs
        raise AssertionError("Unexpected HCS-2 fallback")

    monkeypatch.setattr(adapter, "resolve_hcs11_profile_v1", hcs11)
    monkeypatch.setattr(adapter, "resolve_hcs13_schema_v1", hcs13)
    monkeypatch.setattr(adapter, "resolve_hcs26_skill_version_v1", hcs26)
    monkeypatch.setattr(adapter, "resolve_hcs2_register_v1", unexpected_hcs2)
    return calls


def test_resolves_exact_ordered_independent_plan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = install_resolved(monkeypatch)
    report = verify()
    standards = report.independent_standards

    assert standards.status == "verified"
    assert standards.assurance == "mirror_corroborated"
    assert [entry.key for entry in standards.items] == [
        "agent:requester",
        "agent:executor",
        "capability:hcs26",
        "schema:parameters:0",
    ]
    assert all(entry.status == "resolved" for entry in standards.items)
    assert calls == [
        f"hcs11:{REQUESTER}",
        f"hcs11:{EXECUTOR}",
        "hcs26",
        "hcs13",
    ]

    summary = finding(report, "standards.references_resolved")
    assert summary.outcome == "pass"
    assert summary.reason_code is None
    assert summary.observation_ids == tuple(
        f"standards.mirror.{index}" for index in range(4)
    )

    references = [
        entry for entry in report.findings
        if entry.check_id.startswith("standards.reference.")
    ]
    observations = [
        entry for entry in report.observations
        if entry.id.startswith("standards.mirror.")
    ]
    assert len(references) == 4
    assert all(entry.outcome == "pass" for entry in references)
    assert len(observations) == 4

    assert set(asdict(standards)) == {
        "network", "status", "assurance", "items",
    }


def install_direct_memo(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[list[str], list[int]]:
    calls = install_resolved(monkeypatch)
    requester_calls = [0]

    async def hcs11(config, request, decode_options=None):
        del config, decode_options
        calls.append(f"hcs11:{request.account_id}")

        if request.account_id != REQUESTER:
            return hcs11_resolved(request)

        requester_calls[0] += 1

        if requester_calls[0] == 1:
            return SimpleNamespace(
                status="conflict",
                reason_code="HCS11_ACCOUNT_REFERENCE_MISMATCH",
                resolver_id="hedera.mirror-rest.hcs11.v1",
                account_id=REQUESTER,
                account_memo=SimpleNamespace(
                    profile_reference=request.expected_hcs1_reference,
                    protocol="hcs-1",
                ),
                registry_entry=None,
                profile_reference=None,
                content_sha256=None,
                canonical_profile_sha256=None,
                profile=None,
                did_binding="not_checked",
            )

        result = hcs11_resolved(request)
        result.account_memo = SimpleNamespace(
            profile_reference=request.expected_hcs1_reference,
            protocol="hcs-1",
        )
        result.registry_entry = None
        return result

    monkeypatch.setattr(adapter, "resolve_hcs11_profile_v1", hcs11)
    return calls, requester_calls


def test_direct_hcs1_account_memo_requires_historical_hcs2_proof(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls, requester_calls = install_direct_memo(monkeypatch)

    async def hcs2(config, request):
        del config
        calls.append("hcs2:historical")
        assert request.registry_topic_id == REQUESTER_REGISTRY
        assert request.sequence_number == 11
        assert request.expected_t_id == REQUESTER_PROFILE
        return SimpleNamespace(
            status="resolved",
            reason_code=None,
            resolver_id="hedera.mirror-rest.hcs2.v1",
            consensus_timestamp="1792039000.000000111",
        )

    monkeypatch.setattr(adapter, "resolve_hcs2_register_v1", hcs2)
    report = verify()
    requester = item(report, "agent:requester")

    assert requester.status == "resolved"
    assert requester.historical_consensus_timestamps_exact == (
        "1792039000.000000111",
    )
    assert requester_calls == [2]
    assert "hcs2:historical" in calls


def test_direct_memo_historical_target_conflict_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install_direct_memo(monkeypatch)

    async def hcs2(config, request):
        del config, request
        return SimpleNamespace(
            status="conflict",
            reason_code="HCS2_TARGET_MISMATCH",
            resolver_id="hedera.mirror-rest.hcs2.v1",
            consensus_timestamp=None,
        )

    monkeypatch.setattr(adapter, "resolve_hcs2_register_v1", hcs2)
    report = verify()
    requester = item(report, "agent:requester")

    assert requester.status == "conflict"
    assert requester.reason_code == "HCS2_TARGET_MISMATCH"
    assert report.independent_standards.status == "failed"
    assert finding(report, "standards.references_resolved").outcome == "fail"


def test_hcs13_claim_scope_mismatch_never_reaches_resolver(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = install_resolved(monkeypatch)
    value = evidence()
    standards = cast(dict[str, object], value["standards"])
    schemas = cast(list[dict[str, object]], standards["schemas"])
    schemas[0]["registry_sequence_number"] = SCHEMA_SEQUENCE + 1

    async def forbidden(*args, **kwargs):
        del args, kwargs
        raise AssertionError("HCS-13 resolver must not run")

    monkeypatch.setattr(adapter, "resolve_hcs13_schema_v1", forbidden)
    report = verify(value)
    schema_item = item(report, "schema:parameters:0")

    assert schema_item.status == "conflict"
    assert schema_item.reason_code == (
        "HCS13_EXECUTION_REFERENCE_SCOPE_MISMATCH"
    )
    assert report.independent_standards.status == "failed"
    assert "hcs13" not in calls


def test_missing_hcs26_version_sequence_is_invalid_without_hcs26_io(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = install_resolved(monkeypatch)
    value = evidence()
    capability = cast(dict[str, object], value["capability"])
    capability["version_sequence_number"] = None

    async def forbidden(*args, **kwargs):
        del args, kwargs
        raise AssertionError("HCS-26 resolver must not run")

    monkeypatch.setattr(adapter, "resolve_hcs26_skill_version_v1", forbidden)
    report = verify(value)
    capability_item = item(report, "capability:hcs26")

    assert capability_item.status == "invalid"
    assert capability_item.reason_code == "HCS26_EXECUTION_REFERENCE_INVALID"
    assert report.independent_standards.status == "failed"
    assert "hcs26" not in calls


def test_duplicate_schema_plan_keys_stop_before_resolution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = install_resolved(monkeypatch)
    value = evidence()
    standards = cast(dict[str, object], value["standards"])
    schemas = cast(list[dict[str, object]], standards["schemas"])
    schemas.append(dict(schemas[0]))

    report = verify(value)
    assert report.independent_standards.status == "not_performed"
    assert report.independent_standards.items == ()
    assert finding(report, "standards.references_resolved").reason_code == (
        "STANDARDS_RESOLUTION_PLAN_INVALID"
    )
    assert calls == []


def test_execution_scope_mismatch_stops_before_resolution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = install_resolved(monkeypatch)
    value = evidence()
    execution = cast(dict[str, object], value["execution"])
    execution["hedera_network"] = "mainnet"

    report = verify(value)
    assert report.independent_standards.status == "not_performed"
    assert finding(report, "standards.references_resolved").reason_code == (
        "STANDARDS_EXECUTION_PREFLIGHT_FAILED"
    )
    assert calls == []


def test_unavailable_hcs11_keeps_summary_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install_resolved(monkeypatch)

    async def hcs11(config, request, decode_options=None):
        del config, decode_options
        if request.account_id != REQUESTER:
            return hcs11_resolved(request)
        return SimpleNamespace(
            status="unavailable",
            reason_code="HCS11_ACCOUNT_NOT_FOUND",
            resolver_id="hedera.mirror-rest.hcs11.v1",
            account_id=REQUESTER,
            account_memo=None,
            registry_entry=None,
            profile_reference=None,
            content_sha256=None,
            canonical_profile_sha256=None,
            profile=None,
            did_binding="not_checked",
        )

    monkeypatch.setattr(adapter, "resolve_hcs11_profile_v1", hcs11)
    report = verify()
    requester = item(report, "agent:requester")

    assert requester.status == "unavailable"
    assert requester.reason_code == "HCS11_ACCOUNT_NOT_FOUND"
    assert requester.assurance == "not_established"
    assert report.independent_standards.status == "unavailable"
    assert finding(report, "standards.references_resolved").outcome == (
        "indeterminate"
    )


def test_repository_commit_mismatch_is_independent_conflict(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install_resolved(monkeypatch)
    value = evidence()
    capability = cast(dict[str, object], value["capability"])
    capability["repository_commit"] = "f" * 40

    report = verify(value)
    capability_item = item(report, "capability:hcs26")

    assert capability_item.status == "conflict"
    assert capability_item.reason_code == (
        "HCS26_EXECUTION_RELEASE_COMMIT_MISMATCH"
    )
    assert report.independent_standards.status == "failed"

    observation = next(
        entry for entry in report.observations
        if entry.id == "standards.mirror.2"
    )
    assert any(
        fact.key == "hcs26.manifest_release_commit"
        and fact.value == COMMIT
        for fact in observation.facts
    )


def test_generic_execution_profile_is_rejected_before_resolution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = install_resolved(monkeypatch)

    with pytest.raises(TypeError, match="sage-standards-v1"):
        verify(
            profile="execution-v1",
            expected_program="cipher",
        )

    assert calls == []
