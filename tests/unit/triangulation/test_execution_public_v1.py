import asyncio
from types import SimpleNamespace
from typing import cast

import pytest

import vera_anchor_verifier.triangulation.execution_public_v1 as module
from vera_anchor_verifier.profiles.execution.verification_v1 import (
    ExecutionV1Input,
    ExecutionV1Report,
)
from vera_anchor_verifier.resolvers.explorer_execution_v1 import (
    ExplorerExecutionV1Request,
)
from vera_anchor_verifier.resolvers.explorer_transport_v1 import (
    ExplorerPublicTransportV1,
)
from vera_anchor_verifier.resolvers.hedera_mirror_v1 import HederaMirrorV1Config
from vera_anchor_verifier.triangulation.execution_public_v1 import (
    PublicExecutionTriangulationV1Config,
    triangulate_public_execution_v1,
)

JOB = "11111111-1111-4111-8111-111111111111"
RESULT = "33333333-3333-4333-8333-333333333333"


def execution(result_id: str | None = RESULT) -> ExecutionV1Input:
    value: dict[str, object] = {
        "evidence": {},
        "intent": {
            "subject": {
                "kind": "execution",
                "id": JOB,
                "hedera_network": "testnet",
            },
            "expected": [],
        },
        "profile": "sage-standards-v1",
        "expected_program": "sage",
    }
    if result_id is not None:
        value["result_id"] = result_id
    return cast(ExecutionV1Input, value)


def source(
    *,
    bounds: str = "pass",
    kind: str = "execution",
    network: str | None = "testnet",
    result_id: str | None = RESULT,
) -> ExecutionV1Report:
    subject: dict[str, object] = {"kind": kind, "id": JOB}
    if network is not None:
        subject["hedera_network"] = network
    return cast(
        ExecutionV1Report,
        SimpleNamespace(
            findings=(
                SimpleNamespace(check_id="input.bounds", outcome=bounds),
            ),
            intent={"subject": subject},
            verification_scope=SimpleNamespace(requested_result_id=result_id),
        ),
    )


def config(
    mirror: HederaMirrorV1Config | None = None,
) -> PublicExecutionTriangulationV1Config:
    return PublicExecutionTriangulationV1Config(
        explorer=ExplorerPublicTransportV1(
            base_url="https://explorer.example"
        ),
        mirror=mirror,
    )


def forbidden(*args: object, **kwargs: object) -> None:
    raise AssertionError("downstream resolver must not be called")


def test_invalid_input_fails_before_network_io(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        module,
        "verify_execution_v1_with_intent",
        lambda value: source(bounds="fail"),
    )
    monkeypatch.setattr(module, "resolve_explorer_execution_v1", forbidden)

    with pytest.raises(TypeError, match="Invalid execution verification input"):
        asyncio.run(triangulate_public_execution_v1(config(), execution()))


def test_invalid_subject_fails_before_network_io(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        module,
        "verify_execution_v1_with_intent",
        lambda value: source(network=None),
    )
    monkeypatch.setattr(module, "resolve_explorer_execution_v1", forbidden)

    with pytest.raises(TypeError, match="Execution verification subject"):
        asyncio.run(triangulate_public_execution_v1(config(), execution()))


def test_unresolved_explorer_short_circuits_downstream_work(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requests: list[ExplorerExecutionV1Request] = []

    async def explorer(
        transport: ExplorerPublicTransportV1,
        request: ExplorerExecutionV1Request,
    ) -> object:
        requests.append(request)
        return SimpleNamespace(
            status="not_found",
            reason_code="EXPLORER_EXECUTION_NOT_FOUND",
            evidence=None,
        )

    monkeypatch.setattr(
        module,
        "verify_execution_v1_with_intent",
        lambda value: source(),
    )
    monkeypatch.setattr(module, "resolve_explorer_execution_v1", explorer)
    monkeypatch.setattr(module, "prepare_execution_triangulation_v1", forbidden)
    monkeypatch.setattr(module, "resolve_execution_hedera_v1", forbidden)
    monkeypatch.setattr(module, "compare_evidence_triangulation_v1", forbidden)

    result = asyncio.run(
        triangulate_public_execution_v1(config(), execution())
    )

    assert len(requests) == 1
    assert requests[0].job_id == JOB
    assert requests[0].network == "testnet"
    assert requests[0].result_id == RESULT
    assert result.status == "not_found"
    assert result.reason_code == "EXPLORER_EXECUTION_NOT_FOUND"
    assert result.public_record_acquisition == "not_found"
    assert result.hedera_resolution == "not_checked"
    assert result.plan is None
    assert result.mirror is None
    assert result.comparison is None


def test_resolved_execution_composes_exact_scope_and_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence = {"available": True}
    plan_observation = SimpleNamespace(id="execution.public")
    mirror_observation = SimpleNamespace(id="execution.hedera")
    source_report = object()
    relationships = (object(),)
    targets = (object(),)
    plan = SimpleNamespace(
        triangulation=SimpleNamespace(
            source_report=source_report,
            observations=(plan_observation,),
            relationships=relationships,
        ),
        hedera_targets=targets,
    )
    mirror = SimpleNamespace(
        status="resolved",
        reason_code=None,
        observation=mirror_observation,
    )
    comparison = SimpleNamespace(consistency="consistent")
    captured: dict[str, object] = {}

    async def explorer(
        transport: ExplorerPublicTransportV1,
        request: ExplorerExecutionV1Request,
    ) -> object:
        captured["request"] = request
        return SimpleNamespace(
            status="resolved",
            reason_code=None,
            evidence=evidence,
        )

    def prepare(value: object, public: object) -> object:
        captured["prepare"] = (value, public)
        return plan

    async def resolve_mirror(
        mirror_config: object,
        subject: object,
        scoped_targets: object,
    ) -> object:
        captured["mirror"] = (mirror_config, subject, scoped_targets)
        return mirror

    def compare(value: object) -> object:
        captured["comparison_input"] = value
        return comparison

    mirror_config = HederaMirrorV1Config()
    value = execution()

    monkeypatch.setattr(
        module,
        "verify_execution_v1_with_intent",
        lambda input_value: source(),
    )
    monkeypatch.setattr(module, "resolve_explorer_execution_v1", explorer)
    monkeypatch.setattr(module, "prepare_execution_triangulation_v1", prepare)
    monkeypatch.setattr(module, "resolve_execution_hedera_v1", resolve_mirror)
    monkeypatch.setattr(module, "compare_evidence_triangulation_v1", compare)

    result = asyncio.run(
        triangulate_public_execution_v1(config(mirror_config), value)
    )

    request = cast(ExplorerExecutionV1Request, captured["request"])
    assert (request.job_id, request.network, request.result_id) == (
        JOB,
        "testnet",
        RESULT,
    )
    assert captured["prepare"] == (value, evidence)

    used_config, used_subject, used_targets = cast(
        tuple[object, object, object],
        captured["mirror"],
    )
    assert used_config is mirror_config
    assert used_subject == source().intent["subject"]
    assert used_targets is targets

    comparison_input = captured["comparison_input"]
    assert comparison_input.source_report is source_report
    assert comparison_input.observations == (
        plan_observation,
        mirror_observation,
    )
    assert comparison_input.relationships is relationships

    assert result.status == "resolved"
    assert result.reason_code is None
    assert result.public_record_acquisition == "resolved"
    assert result.hedera_resolution == "resolved"
    assert result.plan is plan
    assert result.mirror is mirror
    assert result.comparison is comparison


@pytest.mark.parametrize(
    (
        "mirror_status",
        "mirror_reason",
        "comparison_consistency",
        "expected_status",
        "expected_reason",
    ),
    [
        (
            "conflict",
            "MIRROR_MESSAGE_SCOPE_MISMATCH",
            "consistent",
            "conflict",
            "MIRROR_MESSAGE_SCOPE_MISMATCH",
        ),
        (
            "resolved",
            None,
            "conflict",
            "conflict",
            "EXECUTION_SOURCE_OR_COMPARISON_CONFLICT",
        ),
        (
            "unavailable",
            "MIRROR_MESSAGE_UNAVAILABLE",
            "incomplete",
            "unavailable",
            "MIRROR_MESSAGE_UNAVAILABLE",
        ),
    ],
)
def test_final_status_preserves_mirror_and_comparison_semantics(
    monkeypatch: pytest.MonkeyPatch,
    mirror_status: str,
    mirror_reason: str | None,
    comparison_consistency: str,
    expected_status: str,
    expected_reason: str | None,
) -> None:
    plan = SimpleNamespace(
        triangulation=SimpleNamespace(
            source_report=object(),
            observations=(),
            relationships=(),
        ),
        hedera_targets=(),
    )

    async def explorer(*args: object) -> object:
        return SimpleNamespace(
            status="resolved",
            reason_code=None,
            evidence={"available": True},
        )

    async def mirror(*args: object) -> object:
        return SimpleNamespace(
            status=mirror_status,
            reason_code=mirror_reason,
            observation=SimpleNamespace(id="execution.hedera"),
        )

    monkeypatch.setattr(
        module,
        "verify_execution_v1_with_intent",
        lambda value: source(),
    )
    monkeypatch.setattr(module, "resolve_explorer_execution_v1", explorer)
    monkeypatch.setattr(
        module,
        "prepare_execution_triangulation_v1",
        lambda value, public: plan,
    )
    monkeypatch.setattr(module, "resolve_execution_hedera_v1", mirror)
    monkeypatch.setattr(
        module,
        "compare_evidence_triangulation_v1",
        lambda value: SimpleNamespace(
            consistency=comparison_consistency,
        ),
    )

    result = asyncio.run(
        triangulate_public_execution_v1(config(), execution())
    )

    assert result.status == expected_status
    assert result.reason_code == expected_reason
    assert result.hedera_resolution == mirror_status