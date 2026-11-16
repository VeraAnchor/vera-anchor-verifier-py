import asyncio
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from urllib.parse import parse_qs, urlsplit

import pytest

from vera_anchor_verifier.resolvers.explorer_execution_v1 import (
    ExplorerExecutionV1Request,
    resolve_explorer_execution_v1,
)
from vera_anchor_verifier.resolvers.explorer_transport_v1 import (
    ExplorerFetchResponseV1,
    ExplorerPublicTransportV1,
)

JOB = "11111111-1111-4111-8111-111111111111"
OTHER = "22222222-2222-4222-8222-222222222222"
RESULT = "33333333-3333-4333-8333-333333333333"


def run[T](coro) -> T:
    return asyncio.run(coro)


def evidence(
    *,
    result_id: str | None = None,
    job_id: str = JOB,
    network: str = "testnet",
) -> dict[str, object]:
    execution: dict[str, object] = {
        "job_id": job_id,
        "program": "sage",
        "proof_date": "2026-10-15",
        "hedera_network": network,
    }
    value: dict[str, object] = {
        "available": True,
        "contract_version": "1.0.0",
        "execution": execution,
    }

    if result_id is not None:
        execution["result_id"] = result_id
        value["result_evidence"] = {
            "result_id": result_id,
        }

    return value


@dataclass
class RouteFetch:
    responses: dict[str, tuple[int, object]]
    calls: list[str] = field(default_factory=list)

    async def __call__(
        self,
        url: str,
        method: str,
        headers: Mapping[str, str],
        body: bytes | None,
        timeout_ms: int,
        max_response_bytes: int,
    ) -> ExplorerFetchResponseV1:
        del method, headers, body, timeout_ms, max_response_bytes
        self.calls.append(url)

        path = urlsplit(url).path

        if path not in self.responses:
            raise AssertionError(
                f"Unexpected Explorer request: {path}"
            )

        status, payload = self.responses[path]

        return ExplorerFetchResponseV1(
            status=status,
            headers={},
            body=json.dumps(
                payload,
                separators=(",", ":"),
            ).encode(),
        )


def config(
    responses: dict[str, tuple[int, object]],
) -> tuple[ExplorerPublicTransportV1, RouteFetch]:
    fetch = RouteFetch(responses)

    return (
        ExplorerPublicTransportV1(
            base_url="https://explorer.example",
            fetch_impl=fetch,
        ),
        fetch,
    )


def test_resolves_exact_job_scoped_execution_evidence() -> None:
    transport, fetch = config({
        f"/v1/sage/jobs/{JOB}/standards": (
            200,
            evidence(),
        ),
    })

    result = run(
        resolve_explorer_execution_v1(
            transport,
            ExplorerExecutionV1Request(
                job_id=JOB,
                network="testnet",
            ),
        )
    )

    assert result.status == "resolved"
    assert result.reason_code is None
    assert result.evidence is not None
    assert len(fetch.calls) == 1

    query = parse_qs(
        urlsplit(fetch.calls[0]).query
    )
    assert query["network"] == ["testnet"]
    assert "resultId" not in query


def test_exact_result_is_scoped_before_standards_lookup() -> None:
    transport, fetch = config({
        f"/v1/sage/results/{RESULT}": (
            200,
            {
                "id": RESULT,
                "job_id": JOB,
                "hedera_network": "testnet",
            },
        ),
        f"/v1/sage/jobs/{JOB}/standards": (
            200,
            evidence(result_id=RESULT),
        ),
    })

    result = run(
        resolve_explorer_execution_v1(
            transport,
            ExplorerExecutionV1Request(
                job_id=JOB,
                result_id=RESULT,
                network="testnet",
            ),
        )
    )

    assert result.status == "resolved"
    assert len(fetch.calls) == 2

    first = urlsplit(fetch.calls[0])
    second = urlsplit(fetch.calls[1])

    assert first.path == f"/v1/sage/results/{RESULT}"
    assert second.path == (
        f"/v1/sage/jobs/{JOB}/standards"
    )
    assert parse_qs(second.query)["resultId"] == [
        RESULT
    ]
    assert parse_qs(second.query)["network"] == [
        "testnet"
    ]


def test_substituted_result_scope_stops_before_standards() -> None:
    transport, fetch = config({
        f"/v1/sage/results/{RESULT}": (
            200,
            {
                "id": RESULT,
                "job_id": OTHER,
                "hedera_network": "testnet",
            },
        ),
    })

    result = run(
        resolve_explorer_execution_v1(
            transport,
            ExplorerExecutionV1Request(
                job_id=JOB,
                result_id=RESULT,
                network="testnet",
            ),
        )
    )

    assert result.status == "conflict"
    assert result.reason_code == (
        "EXPLORER_RESULT_SCOPE_MISMATCH"
    )
    assert result.evidence is None
    assert len(fetch.calls) == 1


def test_requested_result_requires_result_specific_evidence() -> None:
    transport, fetch = config({
        f"/v1/sage/results/{RESULT}": (
            200,
            {
                "id": RESULT,
                "job_id": JOB,
                "hedera_network": "testnet",
            },
        ),
        f"/v1/sage/jobs/{JOB}/standards": (
            200,
            evidence(),
        ),
    })

    result = run(
        resolve_explorer_execution_v1(
            transport,
            ExplorerExecutionV1Request(
                job_id=JOB,
                result_id=RESULT,
                network="testnet",
            ),
        )
    )

    assert result.status == (
        "verification_material_unavailable"
    )
    assert result.reason_code == (
        "EXPLORER_RESULT_EVIDENCE_UNAVAILABLE"
    )
    assert result.evidence is None
    assert len(fetch.calls) == 2


def test_result_evidence_substitution_is_conflict() -> None:
    value = evidence(result_id=RESULT)
    value["result_evidence"] = {
        "result_id": OTHER,
    }

    transport, fetch = config({
        f"/v1/sage/results/{RESULT}": (
            200,
            {
                "id": RESULT,
                "job_id": JOB,
                "hedera_network": "testnet",
            },
        ),
        f"/v1/sage/jobs/{JOB}/standards": (
            200,
            value,
        ),
    })

    result = run(
        resolve_explorer_execution_v1(
            transport,
            ExplorerExecutionV1Request(
                job_id=JOB,
                result_id=RESULT,
                network="testnet",
            ),
        )
    )

    assert result.status == "conflict"
    assert result.reason_code == (
        "EXPLORER_RESULT_EVIDENCE_SCOPE_MISMATCH"
    )
    assert len(fetch.calls) == 2


def test_public_job_or_network_substitution_is_conflict() -> None:
    for value in (
        evidence(job_id=OTHER),
        evidence(network="mainnet"),
    ):
        transport, fetch = config({
            f"/v1/sage/jobs/{JOB}/standards": (
                200,
                value,
            ),
        })

        result = run(
            resolve_explorer_execution_v1(
                transport,
                ExplorerExecutionV1Request(
                    job_id=JOB,
                    network="testnet",
                ),
            )
        )

        assert result.status == "conflict"
        assert result.reason_code == (
            "EXPLORER_EXECUTION_SCOPE_MISMATCH"
        )
        assert len(fetch.calls) == 1


def test_unregistered_execution_material_remains_unavailable() -> None:
    transport, _ = config({
        f"/v1/sage/jobs/{JOB}/standards": (
            200,
            {
                "available": False,
                "contract_version": "1.0.0",
                "execution": {
                    "job_id": JOB,
                    "hedera_network": "testnet",
                },
            },
        ),
    })

    result = run(
        resolve_explorer_execution_v1(
            transport,
            ExplorerExecutionV1Request(
                job_id=JOB,
                network="testnet",
            ),
        )
    )

    assert result.status == (
        "verification_material_unavailable"
    )
    assert result.reason_code == (
        "EXPLORER_STANDARDS_UNAVAILABLE"
    )


def test_unsupported_execution_contract_is_invalid() -> None:
    value = evidence()
    value["contract_version"] = "2.0.0"

    transport, _ = config({
        f"/v1/sage/jobs/{JOB}/standards": (
            200,
            value,
        ),
    })

    result = run(
        resolve_explorer_execution_v1(
            transport,
            ExplorerExecutionV1Request(
                job_id=JOB,
                network="testnet",
            ),
        )
    )

    assert result.status == "invalid"
    assert result.reason_code == (
        "EXPLORER_EXECUTION_CONTRACT_UNSUPPORTED"
    )


def test_result_not_found_is_distinct_from_invalid() -> None:
    transport, fetch = config({
        f"/v1/sage/results/{RESULT}": (
            404,
            {"error": "not_found"},
        ),
    })

    result = run(
        resolve_explorer_execution_v1(
            transport,
            ExplorerExecutionV1Request(
                job_id=JOB,
                result_id=RESULT,
                network="testnet",
            ),
        )
    )

    assert result.status == "not_found"
    assert result.reason_code == "EXPLORER_NOT_FOUND"
    assert len(fetch.calls) == 1


def test_invalid_lookup_scope_performs_no_io() -> None:
    transport, fetch = config({})

    with pytest.raises(
        TypeError,
        match="valid job, result and network scope",
    ):
        run(
            resolve_explorer_execution_v1(
                transport,
                ExplorerExecutionV1Request(
                    job_id="not-a-job-id",
                    network="testnet",
                ),
            )
        )

    assert fetch.calls == []