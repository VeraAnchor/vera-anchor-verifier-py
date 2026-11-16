import asyncio
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Literal, cast

import pytest

from vera_anchor_verifier.contracts import HederaNetwork, VerificationSubject
from vera_anchor_verifier.resolvers.execution_mirror_v1 import (
    resolve_execution_hedera_v1,
)
from vera_anchor_verifier.resolvers.hedera_mirror_v1 import (
    HederaMirrorFetchResponseV1,
    HederaMirrorV1Config,
)
from vera_anchor_verifier.triangulation.execution_plan_v1 import (
    EXECUTION_HEDERA_OBSERVATION_V1_ID,
    ExecutionHederaTargetV1,
)

JOB = "11111111-1111-4111-8111-111111111111"
MIRROR = "https://mirror.example/api/v1"
TX = "0.0.11@1792033594.000000001"

type Side = Literal["provided_evidence", "public_record"]
type Role = Literal["acceptance_anchor", "result_evidence_anchor"]


def run[T](coro) -> T:
    return asyncio.run(coro)


def subject(network: HederaNetwork = "testnet") -> VerificationSubject:
    return cast(
        VerificationSubject,
        {"kind": "execution", "id": JOB, "hedera_network": network},
    )


def target(
    *,
    source: Side = "public_record",
    role: Role = "acceptance_anchor",
    network: HederaNetwork = "testnet",
    transaction_id: str | None = TX,
    topic_id: str | None = "0.0.22",
    sequence_number: int | None = 3,
) -> ExecutionHederaTargetV1:
    return ExecutionHederaTargetV1(
        source=source,
        role=role,
        network=network,
        transaction_id=transaction_id,
        topic_id=topic_id,
        sequence_number=sequence_number,
        observation_fact_prefix=f"ledger.{source}.{role}",
    )


def response(
    body: object,
    *,
    status: int = 200,
    headers: Mapping[str, str] | None = None,
) -> HederaMirrorFetchResponseV1:
    return HederaMirrorFetchResponseV1(
        status=status,
        headers=headers or {},
        body=json.dumps(body, separators=(",", ":")).encode(),
    )


@dataclass
class MirrorFetch:
    transaction_status: int = 200
    transaction_rows: list[object] | None = None
    message_status: int = 200
    message: object | None = None
    calls: list[str] = field(default_factory=list)
    limits: list[int] = field(default_factory=list)

    async def __call__(
        self,
        url: str,
        headers: Mapping[str, str],
        timeout_ms: int,
        max_response_bytes: int,
    ) -> HederaMirrorFetchResponseV1:
        self.calls.append(url)
        self.limits.append(max_response_bytes)
        assert headers == {"Accept": "application/json"}
        assert 250 <= timeout_ms <= 15_000

        if "/transactions/" in url:
            rows = self.transaction_rows
            if rows is None:
                rows = [{"transaction_id": TX, "result": "SUCCESS"}]
            return response({"transactions": rows}, status=self.transaction_status)

        if "/topics/" in url:
            body = self.message
            if body is None:
                body = {
                    "topic_id": "0.0.22",
                    "sequence_number": 3,
                    "consensus_timestamp": "1792033600.123456789",
                    "message": "YWJj",
                }
            return response(body, status=self.message_status)

        raise AssertionError(f"Unexpected URL: {url}")


def config(fetch: MirrorFetch) -> HederaMirrorV1Config:
    return HederaMirrorV1Config(
        base_urls={"testnet": MIRROR},
        fetch_impl=fetch,
    )


def facts(result) -> dict[str, object]:
    return {fact.key: fact for fact in result.observation.facts}


def test_resolves_exact_transaction_and_message_scope() -> None:
    fetch = MirrorFetch()
    result = run(resolve_execution_hedera_v1(config(fetch), subject(), (target(),)))

    assert result.status == "resolved"
    assert result.reason_code is None
    assert result.observation.id == EXECUTION_HEDERA_OBSERVATION_V1_ID
    assert result.observation.source == "hedera_mirror"
    assert result.observation.resolver_id == "hedera.execution-mirror.v1"

    indexed = facts(result)
    prefix = "ledger.public_record.acceptance_anchor"
    assert indexed[f"{prefix}.transaction_id"].value == TX
    assert indexed[f"{prefix}.topic_id"].value == "0.0.22"
    assert indexed[f"{prefix}.sequence_number"].value == "3"
    assert len(fetch.calls) == 2
    assert fetch.limits == [256 * 1024, 256 * 1024]


def test_empty_target_set_is_never_resolved() -> None:
    fetch = MirrorFetch()
    result = run(resolve_execution_hedera_v1(config(fetch), subject(), ()))

    assert result.status == "unavailable"
    assert result.reason_code == "MIRROR_LEDGER_TARGETS_MISSING"
    assert result.observation.facts == ()
    assert fetch.calls == []


@pytest.mark.parametrize(
    "rows",
    [
        [{"transaction_id": TX, "result": "INVALID_SIGNATURE"}],
        [
            {"transaction_id": TX, "result": "SUCCESS"},
            {"transaction_id": TX, "result": "SUCCESS"},
        ],
    ],
)
def test_failed_or_ambiguous_transaction_is_conflict(rows: list[object]) -> None:
    fetch = MirrorFetch(transaction_rows=rows)
    result = run(
        resolve_execution_hedera_v1(
            config(fetch),
            subject(),
            (target(topic_id=None, sequence_number=None),),
        )
    )

    assert result.status == "conflict"
    assert result.reason_code == "MIRROR_TRANSACTION_CONFLICT"
    assert result.observation.facts[0].state == "unavailable"
    assert result.observation.facts[0].reason_code == "MIRROR_TRANSACTION_CONFLICT"


def test_missing_transaction_remains_unavailable() -> None:
    fetch = MirrorFetch(transaction_status=404)
    result = run(
        resolve_execution_hedera_v1(
            config(fetch),
            subject(),
            (target(topic_id=None, sequence_number=None),),
        )
    )

    assert result.status == "unavailable"
    assert result.reason_code == "MIRROR_TRANSACTION_NOT_FOUND"


def test_wrong_message_scope_is_conflict() -> None:
    fetch = MirrorFetch(
        message={
            "topic_id": "0.0.999",
            "sequence_number": 3,
            "consensus_timestamp": "1792033600.123456789",
            "message": "YWJj",
        }
    )
    result = run(
        resolve_execution_hedera_v1(
            config(fetch),
            subject(),
            (target(transaction_id=None),),
        )
    )

    assert result.status == "conflict"
    assert result.reason_code == "MIRROR_MESSAGE_SCOPE_MISMATCH"


def test_invalid_message_is_invalid_not_unavailable() -> None:
    fetch = MirrorFetch(
        message={
            "topic_id": "0.0.22",
            "sequence_number": 3,
            "consensus_timestamp": "1792033600.123",
            "message": "###",
        }
    )
    result = run(
        resolve_execution_hedera_v1(
            config(fetch),
            subject(),
            (target(transaction_id=None),),
        )
    )

    assert result.status == "invalid"
    assert result.reason_code == "MIRROR_RESPONSE_INVALID"
    assert all(fact.state == "unavailable" for fact in result.observation.facts)


def test_cross_network_target_is_rejected_before_io() -> None:
    fetch = MirrorFetch()

    with pytest.raises(TypeError, match="Invalid scoped Hedera execution target"):
        run(
            resolve_execution_hedera_v1(
                config(fetch),
                subject(),
                (target(network="mainnet"),),
            )
        )

    assert fetch.calls == []


def test_noncanonical_transaction_is_rejected_before_io() -> None:
    fetch = MirrorFetch()

    with pytest.raises(TypeError, match="Invalid scoped Hedera execution target"):
        run(
            resolve_execution_hedera_v1(
                config(fetch),
                subject(),
                (target(transaction_id="0.0.11@1792033594.1"),),
            )
        )

    assert fetch.calls == []


def test_invalid_transport_bounds_are_rejected_before_io() -> None:
    fetch = MirrorFetch()
    bad = HederaMirrorV1Config(
        base_urls={"testnet": MIRROR},
        fetch_impl=fetch,
        timeout_ms=100,
    )

    with pytest.raises(TypeError, match="Invalid Mirror transport bounds"):
        run(resolve_execution_hedera_v1(bad, subject(), (target(),)))

    assert fetch.calls == []


def test_execution_response_budget_is_bounded_to_256k() -> None:
    limits: list[int] = []

    async def fetch(
        url: str,
        headers: Mapping[str, str],
        timeout_ms: int,
        max_response_bytes: int,
    ) -> HederaMirrorFetchResponseV1:
        del url, headers, timeout_ms
        limits.append(max_response_bytes)
        return HederaMirrorFetchResponseV1(
            status=200,
            headers={},
            body=b"x" * (max_response_bytes + 1),
        )

    result = run(
        resolve_execution_hedera_v1(
            HederaMirrorV1Config(
                base_urls={"testnet": MIRROR},
                fetch_impl=fetch,
            ),
            subject(),
            (target(topic_id=None, sequence_number=None),),
        )
    )

    assert limits == [256 * 1024]
    assert result.status == "invalid"
    assert result.reason_code == "MIRROR_TRANSACTION_INVALID"


def test_too_many_targets_are_rejected_before_io() -> None:
    fetch = MirrorFetch()
    targets = tuple(
        target(
            source="public_record" if index % 2 == 0 else "provided_evidence",
            role="acceptance_anchor" if index % 3 else "result_evidence_anchor",
        )
        for index in range(9)
    )

    with pytest.raises(TypeError, match="Invalid Hedera execution resolution scope"):
        run(resolve_execution_hedera_v1(config(fetch), subject(), targets))

    assert fetch.calls == []