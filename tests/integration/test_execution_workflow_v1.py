import asyncio
import json
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from typing import Literal, cast
from urllib.parse import parse_qs, urlsplit

import pytest

from vera_anchor_verifier.contracts import VerificationSubject
from vera_anchor_verifier.policy.contract_v1 import (
    VERIFICATION_POLICY_SCHEMA_VERSION,
    VerificationPolicyExecutionScopeV1,
    VerificationPolicyV1,
)
from vera_anchor_verifier.policy.evaluate_v1 import (
    triangulate_execution_with_policy_v1,
    verify_execution_with_policy_v1,
)
from vera_anchor_verifier.profiles.execution.recomputation_v1 import (
    compute_execution_domain_separated_sha3_512,
)
from vera_anchor_verifier.profiles.execution.verification_v1 import ExecutionV1Input
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
from vera_anchor_verifier.triangulation.execution_public_v1 import (
    PublicExecutionTriangulationV1Config,
)

JOB = "11111111-1111-4111-8111-111111111111"
OTHER = "22222222-2222-4222-8222-222222222222"
RESULT = "33333333-3333-4333-8333-333333333333"
HASH_A, HASH_B = "a" * 128, "b" * 128
ACCEPTANCE_TX = "0.0.11@1792033594.000000001"
RESULT_TX = "0.0.15@1792033599.000000002"
EXPLORER = "https://explorer.example.test"
MIRROR = "https://mirror.example.test/api/v1"

type Scenario = Literal[
    "consistent",
    "explorer_unavailable",
    "missing_mirror",
    "conflicting_topic",
    "substituted_result",
    "missing_result",
    "wrong_job",
    "wrong_network",
]
type PolicyKind = Literal["execution", "execution_triangulation"]

SUBJECT = cast(
    VerificationSubject,
    {"kind": "execution", "id": JOB, "hedera_network": "testnet"},
)


def run[T](coro) -> T:
    return asyncio.run(coro)


def encoded(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":")).encode()


def evidence(result_id: str | None = None) -> dict[str, object]:
    payload = {"result": {"x": 1}, "id": JOB}
    binding = compute_execution_domain_separated_sha3_512(
        "vera-anchor:execution-binding:v1", payload
    )
    accepted_at = "2026-10-15T00:00:00.000Z"
    acceptance = compute_execution_domain_separated_sha3_512(
        "vera-anchor:execution-acceptance:v1",
        {
            "record_type": "vera_anchor.execution_acceptance",
            "acceptance_schema": "ExecutionAcceptanceV1",
            "binding_digest_sha3_512": binding,
            "job_id": JOB,
            "proof_date": "2026-10-15",
            "hedera_network": "testnet",
            "admission_policy": {
                "policy_id": "standard",
                "require_hcs_confirmation_before_execution": True,
            },
            "accepted_at": accepted_at,
        },
    )
    execution: dict[str, object] = {
        "job_id": JOB,
        "program": "sage",
        "proof_date": "2026-10-15",
        "hedera_network": "testnet",
        "pipeline_hash": HASH_A,
    }
    if result_id:
        execution["result_id"] = result_id

    value: dict[str, object] = {
        "available": True,
        "contract_version": "1.0.0",
        "execution": execution,
        "binding": {
            "schema": "ExecutionBindingV1",
            "canonicalization": "RFC8785-JCS",
            "digest_algorithm": "SHA3-512",
            "domain_separator": "vera-anchor:execution-binding:v1",
            "finalized_at": "2026-10-15T00:00:00Z",
            "digest_payload": payload,
            "digest": binding,
        },
        "acceptance": {
            "schema": "ExecutionAcceptanceV1",
            "canonicalization": "RFC8785-JCS",
            "digest_algorithm": "SHA3-512",
            "domain_separator": "vera-anchor:execution-acceptance:v1",
            "digest": acceptance,
            "binding_digest": binding,
            "accepted_at": accepted_at,
            "admission_policy_id": "standard",
            "requires_hcs_confirmation": True,
            "state": "confirmed",
            "hcs": {
                "transaction_id": "0.0.11@1792033594.1",
                "topic_id": "0.0.22",
                "sequence_number": 3,
                "message_id": "3@0.0.22",
                "data_hash_sha3_512": HASH_B,
                "consensus_timestamp_exact": "1792033600.123456789",
            },
        },
    }
    if result_id:
        value["result_evidence"] = {
            "schema": "ResultEvidenceV1",
            "canonicalization": "RFC8785-JCS",
            "digest_algorithm": "SHA3-512",
            "domain_separator": "vera-anchor:result-evidence:v1",
            "result_id": result_id,
            "digest": HASH_A,
            "binding_digest": binding,
            "acceptance_digest": acceptance,
            "pipeline_hash": HASH_A,
            "sealed_at": "2026-10-15T01:00:00Z",
            "hcs": {
                "transaction_id": "0.0.15@1792033599.2",
                "topic_id": "0.0.23",
            },
        }
    return value


def execution_input(result_id: str | None = None) -> ExecutionV1Input:
    value: dict[str, object] = {
        "profile": "sage-standards-v1",
        "expected_program": "sage",
        "evidence": evidence(result_id),
        "intent": {"subject": SUBJECT, "expected": []},
    }
    if result_id:
        value["result_id"] = result_id
    return cast(ExecutionV1Input, value)


def policy(
    kind: PolicyKind,
    result_id: str | None = None,
) -> VerificationPolicyV1:
    return VerificationPolicyV1(
        schema_version=VERIFICATION_POLICY_SCHEMA_VERSION,
        subject=SUBJECT,
        report_kind=kind,
        required_checks=(
            "binding.digest_recomputed",
            "standards.references_resolved",
        ),
        required_assurance=(
            ("mirror_corroboration",)
            if kind == "execution_triangulation"
            else ()
        ),
        execution_scope=VerificationPolicyExecutionScopeV1(
            profile="sage-standards-v1",
            expected_program="sage",
            requested_result_id=result_id,
        ),
        on_unresolved="review",
    )


@dataclass
class Remote:
    scenario: Scenario = "consistent"
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
        self.requests.append(url)
        assert method == "GET" and body is None
        assert headers["Accept"] == "application/json"
        assert 250 <= timeout_ms <= 15_000
        assert max_response_bytes > 0
        parsed = urlsplit(url)

        if parsed.path == f"/v1/sage/results/{RESULT}":
            return ExplorerFetchResponseV1(
                status=200,
                headers={},
                body=encoded({
                    "id": RESULT,
                    "job_id": (
                        OTHER
                        if self.scenario == "substituted_result"
                        else JOB
                    ),
                    "hedera_network": "testnet",
                }),
            )

        if parsed.path != f"/v1/sage/jobs/{JOB}/standards":
            raise AssertionError(f"Unexpected Explorer request: {url}")

        if self.scenario == "explorer_unavailable":
            return ExplorerFetchResponseV1(
                status=503,
                headers={},
                body=encoded({"error": "unavailable"}),
            )

        selected = parse_qs(parsed.query).get("resultId", [None])[0]
        value = evidence(RESULT if selected == RESULT else None)
        execution = cast(dict[str, object], value["execution"])
        execution["job_id"] = (
            OTHER if self.scenario == "wrong_job" else JOB
        )
        execution["hedera_network"] = (
            "mainnet"
            if self.scenario == "wrong_network"
            else "testnet"
        )
        if self.scenario == "missing_result":
            value["result_evidence"] = None

        return ExplorerFetchResponseV1(
            status=200,
            headers={},
            body=encoded(value),
        )

    async def mirror_fetch(
        self,
        url: str,
        headers: Mapping[str, str],
        timeout_ms: int,
        max_response_bytes: int,
    ) -> HederaMirrorFetchResponseV1:
        self.requests.append(url)
        assert headers == {"Accept": "application/json"}
        assert 250 <= timeout_ms <= 15_000
        assert 1024 <= max_response_bytes <= 256 * 1024
        path = urlsplit(url).path

        if "/topics/" in path:
            if self.scenario == "missing_mirror":
                return HederaMirrorFetchResponseV1(
                    status=404,
                    headers={},
                    body=encoded({}),
                )

            return HederaMirrorFetchResponseV1(
                status=200,
                headers={},
                body=encoded({
                    "topic_id": (
                        "0.0.999"
                        if self.scenario == "conflicting_topic"
                        else "0.0.22"
                    ),
                    "sequence_number": 3,
                    "consensus_timestamp": "1792033600.123456789",
                    "message": "YWJj",
                }),
            )

        if "/transactions/" in path:
            transaction_id = (
                RESULT_TX
                if "/transactions/0.0.15-" in path
                else ACCEPTANCE_TX
            )
            return HederaMirrorFetchResponseV1(
                status=200,
                headers={},
                body=encoded({
                    "transactions": [{
                        "transaction_id": transaction_id,
                        "result": "SUCCESS",
                        "consensus_timestamp": "1792033600.123456789",
                    }]
                }),
            )

        raise AssertionError(f"Unexpected Mirror request: {url}")

    def config(self) -> PublicExecutionTriangulationV1Config:
        return PublicExecutionTriangulationV1Config(
            explorer=ExplorerPublicTransportV1(
                base_url=EXPLORER,
                fetch_impl=self.explorer_fetch,
            ),
            mirror=HederaMirrorV1Config(
                base_urls={"testnet": MIRROR},
                fetch_impl=self.mirror_fetch,
            ),
        )


def finding(report, check_id: str) -> object | None:
    return next(
        (
            item["outcome"]
            for item in report.core["findings"]
            if item["check_id"] == check_id
        ),
        None,
    )


def requirement(workflow, key: str):
    return next(
        item
        for item in workflow.policy.requirements
        if item.key == key
    )


def public_context(report) -> Mapping[str, object]:
    return cast(
        Mapping[str, object],
        report.context["public_execution"],
    )


def test_offline_recomputation_and_binding_tamper() -> None:
    valid = verify_execution_with_policy_v1(
        execution_input(),
        policy("execution"),
    )

    assert valid.report.kind == "execution"
    assert valid.policy.authority == "sdk_verification"
    assert finding(valid.report, "binding.digest_recomputed") == "pass"
    assert finding(valid.report, "intent.subject") == "pass"
    assert requirement(
        valid,
        "check.binding.digest_recomputed",
    ).outcome == "pass"
    assert (
        validate_portable_verification_report_v1(valid.report).status
        == "valid"
    )
    assert valid.policy.decision == "review"

    value = evidence()
    cast(dict[str, object], value["binding"])["digest"] = "0" * 128
    altered = execution_input()
    altered["evidence"] = value

    denied = verify_execution_with_policy_v1(
        altered,
        policy("execution"),
    )

    assert finding(denied.report, "binding.digest_recomputed") == "fail"
    assert denied.policy.decision == "deny"


def test_public_execution_composes_real_stack() -> None:
    remote = Remote()
    result = run(
        triangulate_execution_with_policy_v1(
            remote.config(),
            execution_input(),
            policy("execution_triangulation"),
        )
    )

    public = public_context(result.report)

    assert result.report.kind == "execution_triangulation"
    assert result.policy.authority == "sdk_verification"
    assert finding(result.report, "binding.digest_recomputed") == "pass"
    assert (
        public["status"]
        == public["public_record_acquisition"]
        == "resolved"
    )
    assert (
        public["mirror_status"]
        == public["hedera_resolution"]
        == "resolved"
    )
    assert requirement(
        result,
        "assurance.mirror_corroboration",
    ).outcome == "pass"
    assert (
        validate_portable_verification_report_v1(result.report).status
        == "valid"
    )
    assert len(remote.requests) == 5
    assert all(
        urlsplit(url).hostname
        in {"explorer.example.test", "mirror.example.test"}
        for url in remote.requests
    )


def test_requested_result_is_pinned_without_fallback() -> None:
    valid = Remote()
    result = run(
        triangulate_execution_with_policy_v1(
            valid.config(),
            execution_input(RESULT),
            policy("execution_triangulation", RESULT),
        )
    )

    scope = cast(
        Mapping[str, object],
        result.report.context["verification_scope"],
    )

    assert scope["requested_result_id"] == RESULT
    assert (
        public_context(result.report)["hedera_resolution"]
        == "resolved"
    )
    assert (
        urlsplit(valid.requests[0]).path
        == f"/v1/sage/results/{RESULT}"
    )
    assert (
        parse_qs(urlsplit(valid.requests[1]).query)["resultId"]
        == [RESULT]
    )
    assert not any("/latest" in url for url in valid.requests)
    assert sum(
        urlsplit(url).hostname == "mirror.example.test"
        for url in valid.requests
    ) == 6

    for scenario in ("substituted_result", "missing_result"):
        remote = Remote(cast(Scenario, scenario))
        rejected = run(
            triangulate_execution_with_policy_v1(
                remote.config(),
                execution_input(RESULT),
                policy("execution_triangulation", RESULT),
            )
        )

        assert rejected.policy.decision != "allow"
        assert (
            public_context(rejected.report)["hedera_resolution"]
            == "not_checked"
        )
        assert not any(
            urlsplit(url).hostname == "mirror.example.test"
            for url in remote.requests
        )


def test_scope_and_failure_semantics_remain_fail_closed() -> None:
    preflight = Remote()
    wrong_subject = cast(
        VerificationSubject,
        {
            "kind": "execution",
            "id": JOB,
            "hedera_network": "mainnet",
        },
    )

    with pytest.raises(TypeError, match="policy intent"):
        run(
            triangulate_execution_with_policy_v1(
                preflight.config(),
                execution_input(),
                replace(
                    policy("execution_triangulation"),
                    subject=wrong_subject,
                ),
            )
        )

    assert preflight.requests == []

    for scenario in ("wrong_job", "wrong_network"):
        remote = Remote(cast(Scenario, scenario))
        result = run(
            triangulate_execution_with_policy_v1(
                remote.config(),
                execution_input(),
                policy("execution_triangulation"),
            )
        )

        assert result.policy.decision == "deny"
        assert (
            public_context(result.report)["hedera_resolution"]
            == "not_checked"
        )
        assert len(remote.requests) == 1

    cases: tuple[tuple[Scenario, str, str, str], ...] = (
        (
            "explorer_unavailable",
            "unresolved",
            "POLICY_PUBLIC_EVIDENCE_INCOMPLETE",
            "review",
        ),
        (
            "missing_mirror",
            "unresolved",
            "POLICY_PUBLIC_EVIDENCE_INCOMPLETE",
            "review",
        ),
        (
            "conflicting_topic",
            "fail",
            "POLICY_PUBLIC_EVIDENCE_CONFLICT",
            "deny",
        ),
    )

    for scenario, outcome, reason, decision in cases:
        remote = Remote(scenario)
        result = run(
            triangulate_execution_with_policy_v1(
                remote.config(),
                execution_input(),
                policy("execution_triangulation"),
            )
        )
        public = requirement(
            result,
            "verification.public_evidence",
        )

        assert (public.outcome, public.reason_code) == (
            outcome,
            reason,
        )
        assert reason in result.policy.reason_codes
        assert result.policy.decision == decision
        assert (
            validate_portable_verification_report_v1(
                result.report
            ).status
            == "valid"
        )