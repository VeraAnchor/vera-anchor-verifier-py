"""Pure bounded consistency comparison for normalized verification observations."""

import math
import re
from dataclasses import dataclass
from typing import Literal, TypeGuard

from ..contracts import (
    EvidenceConsistency,
    VerificationFact,
    VerificationFinding,
    VerificationObservation,
    VerificationOutcome,
    VerificationReport,
    VerificationSubject,
)

MAX_TRIANGULATION_OBSERVATIONS = 32
MAX_TRIANGULATION_FACTS = 256
MAX_TRIANGULATION_RELATIONSHIPS = 3
MAX_TRIANGULATION_COMPARISONS = 64
MAX_TRIANGULATION_SOURCE_FINDINGS = 256

_ID_RE = re.compile(r"^[a-z][a-z0-9._:-]{0,127}$", re.ASCII)
_FACT_KEY_RE = re.compile(r"^[a-z][a-z0-9._:-]{0,159}$", re.ASCII)
_MAX_SAFE_INTEGER = (1 << 53) - 1

type TriangulationRelationshipId = Literal[
    "provided_public_record",
    "public_record_hedera",
    "provided_hedera",
    "provided_authorized",
    "authorized_hedera",
]
type RelationshipConsistency = EvidenceConsistency | Literal["not_applicable"]


@dataclass(frozen=True, slots=True)
class TriangulationFactPlanV1:
    key: str
    left_key: str
    right_key: str


@dataclass(frozen=True, slots=True)
class TriangulationRelationshipPlanV1:
    id: TriangulationRelationshipId
    left_observation_id: str
    right_observation_id: str
    comparisons: tuple[TriangulationFactPlanV1, ...]


@dataclass(frozen=True, slots=True)
class TriangulationV1Input:
    source_report: VerificationReport
    observations: tuple[VerificationObservation, ...]
    relationships: tuple[TriangulationRelationshipPlanV1, ...]


@dataclass(frozen=True, slots=True)
class TriangulationFactResultV1:
    key: str
    outcome: VerificationOutcome
    reason_code: str | None


@dataclass(frozen=True, slots=True)
class TriangulationRelationshipResultV1:
    id: TriangulationRelationshipId
    status: RelationshipConsistency
    fact_comparisons: tuple[TriangulationFactResultV1, ...]


@dataclass(frozen=True, slots=True)
class TriangulationV1Result:
    consistency: EvidenceConsistency
    relationships: tuple[TriangulationRelationshipResultV1, ...]
    report: VerificationReport


def _js_length(value: str) -> int:
    return len(value.encode("utf-16-le", "surrogatepass")) // 2


def _checked_id(value: object, field: str, pattern: re.Pattern[str]) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise TypeError(f"Invalid {field}")
    return value


def _matches_subject(
    actual: VerificationSubject,
    expected: VerificationSubject,
) -> bool:
    return (
        actual.get("kind") == expected.get("kind")
        and actual.get("id") == expected.get("id")
    )


def _valid_number(value: object) -> TypeGuard[int | float]:
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return -_MAX_SAFE_INTEGER <= value <= _MAX_SAFE_INTEGER
    return isinstance(value, float) and math.isfinite(value)


def _valid_fact_value(value: object) -> bool:
    if value is None or isinstance(value, (str, bool)):
        return not isinstance(value, str) or _js_length(value) <= 4096
    return _valid_number(value)


def _facts_by_key(
    observation: VerificationObservation,
) -> dict[str, VerificationFact]:
    facts = observation.facts
    if len(facts) > MAX_TRIANGULATION_FACTS:
        raise TypeError("Triangulation observation exceeds the fact limit")

    indexed: dict[str, VerificationFact] = {}
    for fact in facts:
        key = _checked_id(fact.key, "fact key", _FACT_KEY_RE)
        if key in indexed:
            raise TypeError(f"Duplicate observation fact: {key}")

        state: object = fact.state
        if state == "available":
            if not _valid_fact_value(fact.value):
                raise TypeError(f"Invalid available fact: {key}")
        elif state in ("unavailable", "not_applicable"):
            reason: object = fact.reason_code
            if reason is not None and (
                not isinstance(reason, str) or _js_length(reason) > 160
            ):
                raise TypeError(f"Invalid fact reason: {key}")
        else:
            raise TypeError(f"Invalid fact state: {key}")

        indexed[key] = fact
    return indexed


def _subject_valid(subject: object) -> bool:
    if not isinstance(subject, dict):
        return False
    return isinstance(subject.get("id"), str) and isinstance(subject.get("kind"), str)


def _observation_index(
    input: TriangulationV1Input,
) -> dict[str, VerificationObservation]:
    all_observations = (*input.source_report.observations, *input.observations)
    if len(all_observations) > MAX_TRIANGULATION_OBSERVATIONS:
        raise TypeError("Too many triangulation observations")

    indexed: dict[str, VerificationObservation] = {}
    for observation in all_observations:
        observation_id = _checked_id(observation.id, "observation id", _ID_RE)
        if observation_id in indexed:
            raise TypeError(f"Duplicate triangulation observation: {observation_id}")
        if not _subject_valid(observation.subject):
            raise TypeError(
                f"Invalid triangulation observation subject: {observation_id}"
            )
        _facts_by_key(observation)
        indexed[observation_id] = observation

    for observation in input.observations:
        if observation.source == "local_computation":
            raise TypeError("External observations cannot assert local computation")
    return indexed


def _role_allowed(
    relationship: TriangulationRelationshipId,
    left: VerificationObservation,
    right: VerificationObservation,
) -> bool:
    if relationship == "provided_public_record":
        return (
            left.source in ("provided_evidence", "local_computation")
            and right.source == "public_record"
        )
    if relationship == "provided_hedera":
        return (
            left.source in ("provided_evidence", "local_computation")
            and right.source == "hedera_mirror"
        )
    if relationship == "provided_authorized":
        return (
            left.source in ("provided_evidence", "local_computation")
            and right.source == "authorized_service"
        )
    if relationship == "authorized_hedera":
        return left.source == "authorized_service" and right.source == "hedera_mirror"
    return left.source == "public_record" and right.source == "hedera_mirror"


def _scope_outcome(
    actual: VerificationObservation,
    expected: VerificationSubject,
) -> tuple[VerificationOutcome, str | None]:
    if not _matches_subject(actual.subject, expected):
        return "fail", "OBSERVATION_SUBJECT_MISMATCH"
    if "hedera_network" not in expected:
        return "indeterminate", "EXPECTED_NETWORK_UNAVAILABLE"
    if "hedera_network" not in actual.subject:
        return "indeterminate", "OBSERVATION_NETWORK_UNAVAILABLE"
    if actual.subject["hedera_network"] != expected["hedera_network"]:
        return "fail", "OBSERVATION_NETWORK_MISMATCH"
    return "pass", None


def _unavailable_reason(fact: VerificationFact) -> str | None:
    return None if fact.state == "available" else fact.reason_code


def _number_sign(value: int | float) -> float:
    return math.copysign(1.0, float(value))


def _object_is(left: object, right: object) -> bool:
    if _valid_number(left):
        if not _valid_number(right):
            return False
        if left == 0 and right == 0:
            return _number_sign(left) == _number_sign(right)
        return left == right
    if _valid_number(right):
        return False
    if isinstance(left, bool) or isinstance(right, bool):
        return type(left) is type(right) and left == right
    if left is None or right is None:
        return left is right
    return type(left) is type(right) and left == right


def _compare_facts(
    left: VerificationFact | None,
    right: VerificationFact | None,
) -> tuple[VerificationOutcome, str | None]:
    if left is None or right is None:
        return "indeterminate", "FACT_MISSING"
    if left.state == "not_applicable" or right.state == "not_applicable":
        reason = (
            _unavailable_reason(left)
            or _unavailable_reason(right)
            or "FACT_NOT_APPLICABLE"
        )
        return "skipped", reason
    if left.state != "available" or right.state != "available":
        reason = (
            _unavailable_reason(left)
            or _unavailable_reason(right)
            or "FACT_UNAVAILABLE"
        )
        return "indeterminate", reason

    matches = _object_is(left.value, right.value)
    return ("pass", None) if matches else ("fail", "FACT_MISMATCH")


def _aggregate(
    results: tuple[TriangulationFactResultV1, ...],
) -> RelationshipConsistency:
    if not results or all(result.outcome == "skipped" for result in results):
        return "not_applicable"
    if any(result.outcome == "fail" for result in results):
        return "conflict"
    if any(result.outcome in ("indeterminate", "unsupported") for result in results):
        return "incomplete"
    return "consistent"


def _finding(
    check_id: str,
    outcome: VerificationOutcome,
    reason_code: str | None,
    observation_ids: tuple[str, ...],
) -> VerificationFinding:
    return VerificationFinding(
        check_id=check_id,
        outcome=outcome,
        reason_code=reason_code,
        observation_ids=observation_ids,
    )


def compare_evidence_triangulation_v1(
    input: TriangulationV1Input,
) -> TriangulationV1Result:
    """Compare bounded facts without asserting source authenticity."""
    source_report = input.source_report
    if (
        len(source_report.findings) > MAX_TRIANGULATION_SOURCE_FINDINGS
        or len(input.relationships) > MAX_TRIANGULATION_RELATIONSHIPS
    ):
        raise TypeError("Invalid triangulation input")

    indexed = _observation_index(input)
    used_relationships: set[TriangulationRelationshipId] = set()
    findings = list(source_report.findings)
    used_check_ids = {finding.check_id for finding in findings}
    results: list[TriangulationRelationshipResultV1] = []
    allowed_relationships = {
        "provided_public_record",
        "public_record_hedera",
        "provided_hedera",
        "provided_authorized",
        "authorized_hedera",
    }

    for relationship in input.relationships:
        if (
            relationship.id not in allowed_relationships
            or relationship.id in used_relationships
        ):
            raise TypeError("Unknown or duplicated triangulation relationship")
        used_relationships.add(relationship.id)

        if len(relationship.comparisons) > MAX_TRIANGULATION_COMPARISONS:
            raise TypeError("Too many triangulation fact comparisons")

        left_id = _checked_id(
            relationship.left_observation_id,
            "left observation id",
            _ID_RE,
        )
        right_id = _checked_id(
            relationship.right_observation_id,
            "right observation id",
            _ID_RE,
        )
        if left_id == right_id:
            raise TypeError("Triangulation cannot compare an observation with itself")

        left = indexed.get(left_id)
        right = indexed.get(right_id)
        if (
            left is not None
            and right is not None
            and not _role_allowed(relationship.id, left, right)
        ):
            raise TypeError(
                "Triangulation observation sources do not match "
                "their relationship roles"
            )

        left_facts = _facts_by_key(left) if left is not None else None
        right_facts = _facts_by_key(right) if right is not None else None
        compared: list[TriangulationFactResultV1] = []
        used_keys: set[str] = set()

        for comparison in relationship.comparisons:
            key = _checked_id(comparison.key, "comparison key", _FACT_KEY_RE)
            left_key = _checked_id(
                comparison.left_key,
                "left comparison key",
                _FACT_KEY_RE,
            )
            right_key = _checked_id(
                comparison.right_key,
                "right comparison key",
                _FACT_KEY_RE,
            )
            if key in used_keys:
                raise TypeError(f"Duplicate triangulation comparison: {key}")
            used_keys.add(key)

            check_id = f"triangulation.{relationship.id}.{key}"
            if check_id in used_check_ids:
                raise TypeError(f"Duplicate triangulation check: {check_id}")
            used_check_ids.add(check_id)

            outcome: VerificationOutcome
            reason: str | None
            if left is None or right is None:
                outcome = "indeterminate"
                reason = "OBSERVATION_UNAVAILABLE"
            else:
                left_scope = _scope_outcome(left, source_report.intent["subject"])
                right_scope = _scope_outcome(right, source_report.intent["subject"])

                if left_scope[0] == "fail" or right_scope[0] == "fail":
                    outcome = "fail"
                    reason = (
                        left_scope[1]
                        if left_scope[0] == "fail"
                        else right_scope[1]
                    )
                elif (
                    left_scope[0] != "pass" and left.source != "local_computation"
                ) or (
                    right_scope[0] != "pass" and right.source != "local_computation"
                ):
                    outcome = "indeterminate"
                    reason = "NETWORK_SCOPE_UNAVAILABLE"
                else:
                    outcome, reason = _compare_facts(
                        None if left_facts is None else left_facts.get(left_key),
                        None if right_facts is None else right_facts.get(right_key),
                    )

            compared.append(
                TriangulationFactResultV1(
                    key=key,
                    outcome=outcome,
                    reason_code=reason,
                )
            )
            findings.append(
                _finding(
                    check_id,
                    outcome,
                    reason,
                    tuple(
                        observation_id
                        for observation_id in (left_id, right_id)
                        if observation_id in indexed
                    ),
                )
            )

        compared_tuple = tuple(compared)
        results.append(
            TriangulationRelationshipResultV1(
                id=relationship.id,
                status=_aggregate(compared_tuple),
                fact_comparisons=compared_tuple,
            )
        )

    subject_kind = source_report.intent["subject"]["kind"]
    required_checks = (
        f"{subject_kind}.source_binding",
        f"{subject_kind}.bundle_consistency",
        "intent.subject",
    )
    required_results = tuple(
        next(
            (
                finding.outcome
                for finding in source_report.findings
                if finding.check_id == check_id
            ),
            None,
        )
        for check_id in required_checks
    )

    if any(finding.outcome == "fail" for finding in source_report.findings) or any(
        result.status == "conflict" for result in results
    ):
        consistency: EvidenceConsistency = "conflict"
    elif (
        any(outcome != "pass" for outcome in required_results)
        or not results
        or any(result.status != "consistent" for result in results)
    ):
        consistency = "incomplete"
    else:
        consistency = "consistent"

    report = VerificationReport(
        intent=source_report.intent,
        findings=tuple(findings),
        observations=(*source_report.observations, *input.observations),
    )
    return TriangulationV1Result(
        consistency=consistency,
        relationships=tuple(results),
        report=report,
    )