"""Public execution evidence triangulation."""

from dataclasses import dataclass
from typing import Literal

from ..profiles.execution.verification_v1 import (
    ExecutionV1Input,
    verify_execution_v1_with_intent,
)
from ..resolvers.execution_mirror_v1 import (
    ExecutionMirrorV1Result,
    resolve_execution_hedera_v1,
)
from ..resolvers.explorer_execution_v1 import (
    ExplorerExecutionV1Request,
    resolve_explorer_execution_v1,
)
from ..resolvers.explorer_transport_v1 import ExplorerPublicTransportV1
from ..resolvers.hedera_mirror_v1 import HederaMirrorV1Config
from .compare_v1 import (
    TriangulationV1Input,
    TriangulationV1Result,
    compare_evidence_triangulation_v1,
)
from .execution_plan_v1 import (
    ExecutionTriangulationPlanV1,
    prepare_execution_triangulation_v1,
)

type PublicExecutionTriangulationStatusV1 = Literal[
    "resolved",
    "not_found",
    "unavailable",
    "invalid",
    "conflict",
    "verification_material_unavailable",
]
type PublicExecutionHederaResolutionV1 = Literal[
    "resolved",
    "unavailable",
    "conflict",
    "invalid",
    "not_checked",
]


@dataclass(frozen=True, slots=True)
class PublicExecutionTriangulationV1Config:
    explorer: ExplorerPublicTransportV1
    mirror: HederaMirrorV1Config | None = None


@dataclass(frozen=True, slots=True)
class PublicExecutionTriangulationV1Result:
    status: PublicExecutionTriangulationStatusV1
    reason_code: str | None
    public_record_acquisition: PublicExecutionTriangulationStatusV1
    hedera_resolution: PublicExecutionHederaResolutionV1
    plan: ExecutionTriangulationPlanV1 | None
    mirror: ExecutionMirrorV1Result | None
    comparison: TriangulationV1Result | None


async def triangulate_public_execution_v1(
    config: PublicExecutionTriangulationV1Config,
    execution: ExecutionV1Input,
) -> PublicExecutionTriangulationV1Result:
    """Acquire and independently triangulate public execution evidence."""
    initial = verify_execution_v1_with_intent(execution)
    input_bounds = next(
        (
            finding
            for finding in initial.findings
            if finding.check_id == "input.bounds"
        ),
        None,
    )
    if input_bounds is None or input_bounds.outcome != "pass":
        raise TypeError("Invalid execution verification input")

    subject = initial.intent["subject"]
    network = subject.get("hedera_network")
    if subject["kind"] != "execution" or network not in ("mainnet", "testnet"):
        raise TypeError("Execution verification subject is required")

    public_record = await resolve_explorer_execution_v1(
        config.explorer,
        ExplorerExecutionV1Request(
            job_id=subject["id"],
            network=network,
            result_id=initial.verification_scope.requested_result_id,
        ),
    )
    if public_record.status != "resolved" or public_record.evidence is None:
        return PublicExecutionTriangulationV1Result(
            status=public_record.status,
            reason_code=public_record.reason_code,
            public_record_acquisition=public_record.status,
            hedera_resolution="not_checked",
            plan=None,
            mirror=None,
            comparison=None,
        )

    plan = prepare_execution_triangulation_v1(
        execution,
        public_record.evidence,
    )
    mirror = await resolve_execution_hedera_v1(
        config.mirror if config.mirror is not None else HederaMirrorV1Config(),
        subject,
        plan.hedera_targets,
    )
    comparison = compare_evidence_triangulation_v1(
        TriangulationV1Input(
            source_report=plan.triangulation.source_report,
            observations=(
                *plan.triangulation.observations,
                mirror.observation,
            ),
            relationships=plan.triangulation.relationships,
        )
    )

    status: PublicExecutionTriangulationStatusV1 = (
        "conflict"
        if mirror.status == "conflict" or comparison.consistency == "conflict"
        else mirror.status
    )
    reason_code = (
        "EXECUTION_SOURCE_OR_COMPARISON_CONFLICT"
        if comparison.consistency == "conflict" and mirror.status != "conflict"
        else mirror.reason_code
    )
    return PublicExecutionTriangulationV1Result(
        status=status,
        reason_code=reason_code,
        public_record_acquisition="resolved",
        hedera_resolution=mirror.status,
        plan=plan,
        mirror=mirror,
        comparison=comparison,
    )


__all__ = [
    "PublicExecutionTriangulationV1Config",
    "PublicExecutionTriangulationV1Result",
    "triangulate_public_execution_v1",
]