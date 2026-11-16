"""Exact relying-party verification policy contract."""

from dataclasses import dataclass
from typing import Literal

from ..contracts import VerificationSubject
from ..reports.portable_v1 import (
    PortableVerificationReportKindV1,
    PortableVerificationReportV1,
)

VERIFICATION_POLICY_SCHEMA_VERSION = "va.verification-policy.v1"

type VerificationPolicyAssuranceV1 = Literal["mirror_corroboration"]
type VerificationPolicyDecisionStatusV1 = Literal["allow", "deny", "review"]
type VerificationPolicyRequirementOutcomeV1 = Literal["pass", "fail", "unresolved"]
type VerificationPolicyAuthorityV1 = Literal[
    "sdk_verification",
    "unauthenticated_report",
]


@dataclass(frozen=True, slots=True)
class VerificationPolicyExecutionScopeV1:
    profile: Literal["execution-v1", "sage-standards-v1"]
    expected_program: str | None
    requested_result_id: str | None


@dataclass(frozen=True, slots=True)
class VerificationPolicyV1:
    schema_version: Literal["va.verification-policy.v1"]
    subject: VerificationSubject
    report_kind: PortableVerificationReportKindV1
    required_checks: tuple[str, ...]
    required_assurance: tuple[VerificationPolicyAssuranceV1, ...] = ()
    execution_scope: VerificationPolicyExecutionScopeV1 | None = None
    on_unresolved: Literal["review", "deny"] = "review"


@dataclass(frozen=True, slots=True)
class VerificationPolicyRequirementV1:
    key: str
    outcome: VerificationPolicyRequirementOutcomeV1
    reason_code: str | None


@dataclass(frozen=True, slots=True)
class VerificationPolicyDecisionV1:
    decision: VerificationPolicyDecisionStatusV1
    report_sha3_512: str | None
    authority: VerificationPolicyAuthorityV1
    requirements: tuple[VerificationPolicyRequirementV1, ...]
    reason_codes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class VerificationPolicyWorkflowV1:
    report: PortableVerificationReportV1
    policy: VerificationPolicyDecisionV1


__all__ = [
    "VERIFICATION_POLICY_SCHEMA_VERSION",
    "VerificationPolicyAssuranceV1",
    "VerificationPolicyAuthorityV1",
    "VerificationPolicyDecisionStatusV1",
    "VerificationPolicyDecisionV1",
    "VerificationPolicyExecutionScopeV1",
    "VerificationPolicyRequirementOutcomeV1",
    "VerificationPolicyRequirementV1",
    "VerificationPolicyV1",
    "VerificationPolicyWorkflowV1",
]