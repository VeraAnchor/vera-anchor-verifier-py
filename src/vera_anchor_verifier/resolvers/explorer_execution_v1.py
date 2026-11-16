"""Resolve exact public SAGE execution verification material."""

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal, cast

from ..contracts import HederaNetwork
from ..profiles.execution.contract_v1 import PublicExecutionStandardsEvidence
from .explorer_transport_v1 import (
    ExplorerPublicTransportV1,
    read_explorer_public_v1,
)

_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE | re.ASCII,
)

type ExplorerExecutionStatusV1 = Literal[
    "resolved",
    "not_found",
    "unavailable",
    "invalid",
    "conflict",
    "verification_material_unavailable",
]


@dataclass(frozen=True, slots=True)
class ExplorerExecutionV1Request:
    job_id: str
    network: HederaNetwork
    result_id: str | None = None


@dataclass(frozen=True, slots=True)
class ExplorerExecutionV1Result:
    status: ExplorerExecutionStatusV1
    reason_code: str | None
    evidence: PublicExecutionStandardsEvidence | None


def _record(value: object) -> Mapping[str, object] | None:
    if isinstance(value, Mapping):
        return cast(Mapping[str, object], value)
    return None


def _identity(value: object) -> str | None:
    if not isinstance(value, str):
        return None

    normalized = value.strip().lower()

    if _UUID_RE.fullmatch(normalized) is None:
        return None

    return normalized


def _network(value: object) -> HederaNetwork | None:
    if value == "mainnet":
        return "mainnet"

    if value == "testnet":
        return "testnet"

    return None


def _result(
    status: ExplorerExecutionStatusV1,
    reason_code: str,
    evidence: PublicExecutionStandardsEvidence | None = None,
) -> ExplorerExecutionV1Result:
    return ExplorerExecutionV1Result(
        status=status,
        reason_code=reason_code,
        evidence=evidence,
    )


async def resolve_explorer_execution_v1(
    config: ExplorerPublicTransportV1,
    request: ExplorerExecutionV1Request,
) -> ExplorerExecutionV1Result:
    job = _identity(request.job_id)
    selected = (
        None
        if request.result_id is None
        else _identity(request.result_id)
    )
    network = _network(request.network)

    if (
        job is None
        or (
            request.result_id is not None
            and selected is None
        )
        or network is None
    ):
        raise TypeError(
            "Execution lookup requires a valid job, result and network scope"
        )

    if selected is not None:
        scoped = await read_explorer_public_v1(
            config,
            f"/v1/sage/results/{selected}",
            network,
        )

        if scoped.status != "ok":
            return _result(
                scoped.status,
                scoped.reason_code
                or "EXPLORER_RESULT_UNAVAILABLE",
            )

        row = _record(scoped.body)

        if row is None:
            return _result(
                "invalid",
                "EXPLORER_RESULT_INVALID",
            )

        result_id = _identity(
            row.get("result_id", row.get("id"))
        )
        job_id = _identity(row.get("job_id"))

        if result_id is None or job_id is None:
            return _result(
                "invalid",
                "EXPLORER_RESULT_SCOPE_MISSING",
            )

        if (
            result_id != selected
            or job_id != job
            or (
                row.get("hedera_network") is not None
                and row.get("hedera_network") != network
            )
        ):
            return _result(
                "conflict",
                "EXPLORER_RESULT_SCOPE_MISMATCH",
            )

    response = await read_explorer_public_v1(
        config,
        f"/v1/sage/jobs/{job}/standards",
        network,
        query=(
            {"resultId": selected}
            if selected is not None
            else None
        ),
    )

    if response.status != "ok":
        return _result(
            response.status,
            response.reason_code
            or "EXPLORER_EXECUTION_UNAVAILABLE",
        )

    body = _record(response.body)

    if body is None:
        return _result(
            "invalid",
            "EXPLORER_EXECUTION_INVALID",
        )

    execution = _record(body.get("execution"))

    if (
        execution is None
        or _identity(execution.get("job_id")) != job
        or execution.get("hedera_network") != network
    ):
        return _result(
            "conflict",
            "EXPLORER_EXECUTION_SCOPE_MISMATCH",
        )

    if body.get("available") is False:
        return _result(
            "verification_material_unavailable",
            "EXPLORER_STANDARDS_UNAVAILABLE",
        )

    if (
        body.get("available") is not True
        or body.get("contract_version") != "1.0.0"
    ):
        return _result(
            "invalid",
            "EXPLORER_EXECUTION_CONTRACT_UNSUPPORTED",
        )

    if selected is not None:
        result_evidence = _record(
            body.get("result_evidence")
        )
        actual = (
            _identity(result_evidence.get("result_id"))
            if result_evidence is not None
            else None
        )

        if result_evidence is None or actual is None:
            return _result(
                "verification_material_unavailable",
                "EXPLORER_RESULT_EVIDENCE_UNAVAILABLE",
            )

        execution_result_id = execution.get("result_id")

        if (
            actual != selected
            or (
                execution_result_id is not None
                and _identity(execution_result_id)
                != selected
            )
        ):
            return _result(
                "conflict",
                "EXPLORER_RESULT_EVIDENCE_SCOPE_MISMATCH",
            )

    return ExplorerExecutionV1Result(
        status="resolved",
        reason_code=None,
        evidence=cast(
            PublicExecutionStandardsEvidence,
            dict(body),
        ),
    )


__all__ = [
    "ExplorerExecutionV1Request",
    "ExplorerExecutionV1Result",
    "resolve_explorer_execution_v1",
]