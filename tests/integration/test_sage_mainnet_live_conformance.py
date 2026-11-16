import asyncio
import json
import os
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest

from vera_anchor_verifier.contracts import VerificationSubject
from vera_anchor_verifier.policy.contract_v1 import (
    VERIFICATION_POLICY_SCHEMA_VERSION,
    VerificationPolicyExecutionScopeV1,
    VerificationPolicyV1,
)
from vera_anchor_verifier.policy.evaluate_v1 import (
    assess_portable_verification_policy_v1,
    triangulate_execution_with_policy_v1,
    verify_execution_with_policy_v1,
)
from vera_anchor_verifier.profiles.execution.verification_v1 import ExecutionV1Input
from vera_anchor_verifier.reports.validation_v1 import (
    validate_portable_verification_report_v1,
)
from vera_anchor_verifier.resolvers.explorer_execution_v1 import (
    ExplorerExecutionV1Request,
    resolve_explorer_execution_v1,
)
from vera_anchor_verifier.resolvers.explorer_transport_v1 import (
    ExplorerPublicTransportV1,
)
from vera_anchor_verifier.resolvers.hedera_mirror_v1 import HederaMirrorV1Config
from vera_anchor_verifier.triangulation.execution_public_v1 import (
    PublicExecutionTriangulationV1Config,
)

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(
        os.getenv("VA_LIVE_TESTS") != "1",
        reason="set VA_LIVE_TESTS=1 to run live conformance",
    ),
]

JOB = "4e4f624d-25b6-577f-93c6-075292e722d6"
RESULT = "b7e96d64-c2b0-5739-90e5-36cfeecc95bb"
EXPLORER = "https://explorer.veraanchor.com"
MIRROR = "https://mainnet-public.mirrornode.hedera.com/api/v1"
FIXTURE = (
    Path(__file__).parent
    / "fixtures"
    / "conformance"
    / "sage"
    / "mainnet"
    / "2026-10-21"
)


def run[T](coro) -> T:
    return asyncio.run(coro)


def load(name: str) -> dict[str, object]:
    value = json.loads((FIXTURE / name).read_text(encoding="utf-8-sig"))
    assert isinstance(value, dict)
    return value


def sample() -> tuple[dict[str, object], dict[str, object], ExecutionV1Input]:
    result = load("result.json")
    standards = load("standards.json")

    assert result["job_id"] == JOB
    assert result["result_id"] == RESULT
    assert result["id"] == RESULT
    assert result["hedera_network"] == "mainnet"
    assert result["program"] == "sage"

    execution = standards["execution"]
    assert isinstance(execution, dict)
    assert execution["job_id"] == JOB
    assert execution["result_id"] == RESULT
    assert execution["hedera_network"] == "mainnet"
    assert execution["program"] == "sage"

    value = cast(
        ExecutionV1Input,
        {
            "profile": "sage-standards-v1",
            "expected_program": "sage",
            "evidence": standards,
            "intent": {
                "subject": {
                    "kind": "execution",
                    "id": JOB,
                    "hedera_network": "mainnet",
                },
                "expected": [],
            },
            "result_id": RESULT,
        },
    )
    return result, standards, value


def policy(kind: str) -> VerificationPolicyV1:
    required = (
        ("binding.digest_recomputed", "standards.references_resolved")
        if kind == "independent_standards"
        else (
            "binding.digest_recomputed",
            "acceptance.digest_recomputed",
            "result_evidence.digest_recomputed",
        )
    )
    return VerificationPolicyV1(
        schema_version=VERIFICATION_POLICY_SCHEMA_VERSION,
        subject=cast(
            VerificationSubject,
            {
                "kind": "execution",
                "id": JOB,
                "hedera_network": "mainnet",
            },
        ),
        report_kind=cast(
            object,
            kind,
        ),
        required_checks=required,
        required_assurance=(
            ()
            if kind == "execution"
            else ("mirror_corroboration",)
        ),
        execution_scope=VerificationPolicyExecutionScopeV1(
            profile="sage-standards-v1",
            expected_program="sage",
            requested_result_id=RESULT,
        ),
        on_unresolved="review",
    )


def public_config() -> PublicExecutionTriangulationV1Config:
    return PublicExecutionTriangulationV1Config(
        explorer=ExplorerPublicTransportV1(
            base_url=EXPLORER,
            timeout_ms=15_000,
        ),
        mirror=HederaMirrorV1Config(
            base_urls={"mainnet": MIRROR},
            timeout_ms=15_000,
        ),
    )


def context(report, key: str) -> Mapping[str, object]:
    value = report.context[key]
    assert isinstance(value, Mapping)
    return value


def test_live_sage_fixture_and_offline_execution() -> None:
    result, standards, execution = sample()

    assert result["proof_date"] == "2026-10-21"
    assert standards["execution"]["pipeline_hash"] == result["pipeline_hash"]
    assert standards["result_evidence"]["result_hash"] == result["data_hash"]

    workflow = verify_execution_with_policy_v1(
        execution,
        policy("execution"),
    )

    assert workflow.report.kind == "execution"
    for check_id in (
        "binding.digest_recomputed",
        "acceptance.digest_recomputed",
        "result_evidence.digest_recomputed",
        "intent.subject",
        "intent.result",
    ):
        finding = next(
            entry
            for entry in workflow.report.core["findings"]
            if entry["check_id"] == check_id
        )
        assert finding["outcome"] == "pass"

    assert (
        validate_portable_verification_report_v1(workflow.report).status
        == "valid"
    )
    assert (
        assess_portable_verification_policy_v1(
            workflow.report,
            policy("execution"),
        ).decision
        != "allow"
    )


def test_live_sage_exact_explorer_scope() -> None:
    transport = ExplorerPublicTransportV1(
        base_url=EXPLORER,
        timeout_ms=15_000,
    )
    selected = ExplorerExecutionV1Request(
        job_id=JOB,
        result_id=RESULT,
        network="mainnet",
    )

    resolved = run(resolve_explorer_execution_v1(transport, selected))
    assert resolved.status == "resolved", resolved.reason_code
    assert resolved.evidence is not None

    substituted = run(
        resolve_explorer_execution_v1(
            transport,
            ExplorerExecutionV1Request(
                job_id=JOB,
                result_id="11111111-1111-4111-8111-111111111111",
                network="mainnet",
            ),
        )
    )
    crossed = run(
        resolve_explorer_execution_v1(
            transport,
            ExplorerExecutionV1Request(
                job_id=JOB,
                result_id=RESULT,
                network="testnet",
            ),
        )
    )

    assert substituted.status != "resolved"
    assert crossed.status != "resolved"


def test_live_sage_public_execution_triangulation() -> None:
    _, _, execution = sample()

    workflow = run(
        triangulate_execution_with_policy_v1(
            public_config(),
            execution,
            policy("execution_triangulation"),
        )
    )

    assert workflow.report.kind == "execution_triangulation"
    public = context(workflow.report, "public_execution")
    assert public["status"] == "resolved"
    assert public["public_record_acquisition"] == "resolved"
    assert public["hedera_resolution"] == "resolved"
    assert "publication_payload_binding" not in public

    assert (
        next(
            requirement
            for requirement in workflow.policy.requirements
            if requirement.key == "assurance.mirror_corroboration"
        ).outcome
        == "pass"
    )
    assert (
        validate_portable_verification_report_v1(workflow.report).status
        == "valid"
    )


def test_live_sage_policy_scope_rejected_before_io() -> None:
    _, _, execution = sample()
    changed = replace(
        policy("execution_triangulation"),
        subject=cast(
            VerificationSubject,
            {
                "kind": "execution",
                "id": JOB,
                "hedera_network": "testnet",
            },
        ),
    )

    async def forbidden(*args, **kwargs):
        del args, kwargs
        raise AssertionError("network I/O must not occur")

    config = PublicExecutionTriangulationV1Config(
        explorer=ExplorerPublicTransportV1(
            base_url=EXPLORER,
            fetch_impl=forbidden,
        ),
        mirror=HederaMirrorV1Config(
            base_urls={"mainnet": MIRROR},
            fetch_impl=forbidden,
        ),
    )

    with pytest.raises(TypeError, match="policy intent"):
        run(
            triangulate_execution_with_policy_v1(
                config,
                execution,
                changed,
            )
        )