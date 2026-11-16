"""Independent online resolution of SAGE execution standards evidence."""

import math
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal, cast

from ...contracts import (
    HederaNetwork,
    VerificationFact,
    VerificationFinding,
    VerificationObservation,
    VerificationOutcome,
)
from ...resolvers.hcs1_mirror_v1 import Hcs1MirrorV1Config
from ...resolvers.hcs2_mirror_v1 import Hcs2MirrorV1Request, resolve_hcs2_register_v1
from ...resolvers.hcs11_mirror_v1 import Hcs11MirrorV1Request, resolve_hcs11_profile_v1
from ...resolvers.hcs13_mirror_v1 import Hcs13MirrorV1Request, resolve_hcs13_schema_v1
from ...resolvers.hcs26_mirror_v1 import Hcs26MirrorV1Request, resolve_hcs26_skill_version_v1
from ...standards.hcs.hcs1_v1 import Hcs1V1ContentOptions, parse_hcs1_reference_v1
from ...standards.hcs.hcs13_v1 import Hcs13V1Error, parse_hcs13_reference_v1
from ...standards.hcs.hcs14_v1 import Hcs14V1Error, parse_hcs14_did_uaid_v1
from .contract_v1 import PublicExecutionStandardsEvidence
from .standards_plan_v1 import (
    StandardsResolutionAgentTargetV1,
    StandardsResolutionCapabilityTargetV1,
    StandardsResolutionPlanItemV1,
    StandardsResolutionSchemaTargetV1,
    build_standards_resolution_plan,
)
from .verification_v1 import (
    ExecutionV1Input,
    ExecutionV1Report,
    verify_execution_v1_with_intent,
)

_TOPIC_RE = re.compile(r"^0\.0\.[0-9]+$", re.ASCII)
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_POSITIVE_RE = re.compile(r"^[1-9][0-9]*$", re.ASCII)
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_MAX_SAFE_INTEGER = (1 << 53) - 1
_MAX_REFERENCES = 16

type IndependentStandardsItemStatusV1 = Literal[
    "resolved",
    "conflict",
    "invalid",
    "unavailable",
    "unsupported",
]

type IndependentStandardsStatusV1 = Literal[
    "verified",
    "failed",
    "unavailable",
    "not_performed",
]

type IndependentStandardsAssuranceV1 = Literal[
    "mirror_corroborated",
    "not_established",
]


@dataclass(frozen=True, slots=True)
class IndependentStandardsV1Item:
    key: str
    standard: str
    reference: str
    status: IndependentStandardsItemStatusV1
    reason_code: str | None
    resolver_id: str | None
    historical_consensus_timestamps_exact: tuple[str, ...]
    current_topic_or_account_memo_observed: bool
    content_sha256: str | None
    assurance: IndependentStandardsAssuranceV1


@dataclass(frozen=True, slots=True)
class IndependentStandardsV1Summary:
    network: HederaNetwork
    status: IndependentStandardsStatusV1
    assurance: IndependentStandardsAssuranceV1
    items: tuple[IndependentStandardsV1Item, ...]


@dataclass(frozen=True, slots=True)
class IndependentStandardsV1Report(ExecutionV1Report):
    independent_standards: IndependentStandardsV1Summary


@dataclass(frozen=True, slots=True)
class _ObservationData:
    status: IndependentStandardsItemStatusV1
    code: str | None
    resolver: str | None
    times: tuple[str, ...]
    current_memo: bool
    sha256: str | None
    facts: tuple[VerificationFact, ...] = ()


def _js_length(value: str) -> int:
    return len(value.encode("utf-16-le", "surrogatepass")) // 2


def _mapping(value: object) -> Mapping[str, object]:
    if isinstance(value, Mapping):
        return cast(Mapping[str, object], value)
    return {}


def _mapping_or_none(value: object) -> Mapping[str, object] | None:
    if isinstance(value, Mapping):
        return cast(Mapping[str, object], value)
    return None


def _text(value: object) -> str:
    return value.strip() if isinstance(value, str) else ""


def _positive(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        text = str(value)
    elif isinstance(value, float):
        if not math.isfinite(value) or not value.is_integer():
            return None
        text = str(int(value))
    elif isinstance(value, str):
        text = value
    else:
        return None
    if _POSITIVE_RE.fullmatch(text) is None:
        return None
    number = int(text)
    if number > _MAX_SAFE_INTEGER:
        return None
    return number


def _nonnegative_safe_integer(value: object) -> bool:
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return 0 <= value <= _MAX_SAFE_INTEGER
    return (
        isinstance(value, float)
        and math.isfinite(value)
        and value.is_integer()
        and 0 <= value <= _MAX_SAFE_INTEGER
    )


def _hex(value: object) -> str | None:
    if isinstance(value, str) and _SHA256_RE.fullmatch(value) is not None:
        return value
    return None


def _topic(value: object) -> str | None:
    if (
        isinstance(value, str)
        and _js_length(value) <= 64
        and _TOPIC_RE.fullmatch(value) is not None
    ):
        return value
    return None


def _fact(
    key: str,
    value: str | int | bool,
) -> VerificationFact:
    return VerificationFact(
        key=key,
        state="available",
        value=value,
    )


def _unavailable(code: str) -> _ObservationData:
    return _ObservationData(
        status="unavailable",
        code=code,
        resolver=None,
        times=(),
        current_memo=False,
        sha256=None,
    )


def _invalid(code: str) -> _ObservationData:
    return _ObservationData(
        status="invalid",
        code=code,
        resolver=None,
        times=(),
        current_memo=False,
        sha256=None,
    )


def _mismatch(code: str) -> _ObservationData:
    return _ObservationData(
        status="conflict",
        code=code,
        resolver=None,
        times=(),
        current_memo=False,
        sha256=None,
    )


def _network_match(
    evidence: Mapping[str, object],
    network: HederaNetwork,
    job_id: str,
) -> bool:
    execution = _mapping(evidence.get("execution"))
    return (
        execution.get("hedera_network") == network
        and _text(execution.get("job_id")).lower() == job_id
        and _text(execution.get("program")).lower() == "sage"
    )


def _has_hcs1_reference(value: object) -> bool:
    try:
        parse_hcs1_reference_v1(value)
        return True
    except TypeError:
        return False


async def _resolve_agent(
    config: Hcs1MirrorV1Config,
    network: HederaNetwork,
    evidence: Mapping[str, object] | None,
    item: StandardsResolutionPlanItemV1,
    decode_options: Hcs1V1ContentOptions,
) -> _ObservationData:
    hcs11 = (
        _mapping_or_none(evidence.get("hcs11"))
        if evidence is not None
        else None
    )
    uaid_raw = (
        evidence.get("hcs14_uaid")
        if evidence is not None
        else None
    )
    base_did_raw = (
        evidence.get("base_did")
        if evidence is not None
        else None
    )
    if (
        hcs11 is None
        or not item.reference
        or not uaid_raw
        or not base_did_raw
    ):
        return _unavailable("HCS11_EXECUTION_REFERENCE_MISSING")

    account = _topic(hcs11.get("account_id"))
    registry_topic = _topic(hcs11.get("profile_registry_topic_id"))
    sequence = _positive(hcs11.get("profile_registry_sequence"))
    checksum = _hex(hcs11.get("profile_checksum_sha256"))

    if (
        account is None
        or registry_topic is None
        or sequence is None
        or checksum is None
        or not _has_hcs1_reference(item.reference)
        or item.reference != hcs11.get("profile_hcs1_ref")
    ):
        return _invalid("HCS11_EXECUTION_REFERENCE_INVALID")

    try:
        parse_hcs14_did_uaid_v1(uaid_raw)
    except Hcs14V1Error:
        return _invalid("HCS11_EXECUTION_UAID_INVALID")

    uaid = cast(str, uaid_raw)
    base_did = cast(str, base_did_raw)
    direct_registry_time: str | None = None

    try:
        result = await resolve_hcs11_profile_v1(
            config,
            Hcs11MirrorV1Request(
                hedera_network=network,
                account_id=account,
                hcs2_sequence_number=sequence,
                expected_profile_reference=f"hcs://2/{registry_topic}",
                expected_hcs1_reference=item.reference,
                expected_hcs1_sha256=checksum,
                expected_profile_sha256=checksum,
                expected_uaid=uaid,
                expected_base_did=base_did,
            ),
            decode_options,
        )

        if (
            result.status == "conflict"
            and result.reason_code == "HCS11_ACCOUNT_REFERENCE_MISMATCH"
            and result.account_memo is not None
            and result.account_memo.profile_reference == item.reference
            and result.account_memo.protocol == "hcs-1"
        ):
            result = await resolve_hcs11_profile_v1(
                config,
                Hcs11MirrorV1Request(
                    hedera_network=network,
                    account_id=account,
                    expected_profile_reference=item.reference,
                    expected_hcs1_reference=item.reference,
                    expected_hcs1_sha256=checksum,
                    expected_profile_sha256=checksum,
                    expected_uaid=uaid,
                    expected_base_did=base_did,
                ),
                decode_options,
            )

            if result.status == "resolved":
                expected_topic = parse_hcs1_reference_v1(
                    item.reference
                ).topic_id
                historical = await resolve_hcs2_register_v1(
                    config,
                    Hcs2MirrorV1Request(
                        hedera_network=network,
                        registry_topic_id=registry_topic,
                        sequence_number=sequence,
                        expected_t_id=expected_topic,
                    ),
                )

                if (
                    historical.status != "resolved"
                    or historical.consensus_timestamp is None
                ):
                    status: IndependentStandardsItemStatusV1 = (
                        "unavailable"
                        if historical.status == "resolved"
                        else historical.status
                    )
                    return _ObservationData(
                        status=status,
                        code=(
                            historical.reason_code
                            or "HCS11_HISTORICAL_REGISTRY_UNAVAILABLE"
                        ),
                        resolver=historical.resolver_id,
                        times=(),
                        current_memo=True,
                        sha256=result.content_sha256,
                    )

                direct_registry_time = historical.consensus_timestamp

    except Hcs14V1Error as exc:
        return _invalid(exc.code)

    timestamp = (
        result.registry_entry.consensus_timestamp
        if result.registry_entry is not None
        else direct_registry_time
    )
    facts: tuple[VerificationFact, ...] = ()

    if result.status == "resolved":
        facts = (
            _fact("hedera.account_id", result.account_id),
            _fact(
                "hcs11.profile_reference",
                cast(str, result.profile_reference),
            ),
            _fact(
                "hcs11.profile_sha256",
                cast(str, result.content_sha256),
            ),
            _fact(
                "hcs11.account_memo_temporal_scope",
                "current_observation",
            ),
            _fact("hcs14.did_binding", result.did_binding),
        )

    return _ObservationData(
        status=result.status,
        code=result.reason_code,
        resolver=result.resolver_id,
        times=(timestamp,) if timestamp is not None else (),
        current_memo=result.account_memo is not None,
        sha256=result.content_sha256,
        facts=facts,
    )


async def _resolve_schema(
    config: Hcs1MirrorV1Config,
    network: HederaNetwork,
    evidence: Mapping[str, object] | None,
    item: StandardsResolutionPlanItemV1,
    decode_options: Hcs1V1ContentOptions,
) -> _ObservationData:
    if evidence is None or not item.reference:
        return _unavailable("HCS13_EXECUTION_REFERENCE_MISSING")

    topic_id = _topic(evidence.get("registry_topic_id"))
    sequence = _positive(evidence.get("registry_sequence_number"))
    checksum = _hex(evidence.get("schema_checksum_sha256"))

    if (
        topic_id is None
        or sequence is None
        or checksum is None
        or item.reference != evidence.get("hcs13_ref")
    ):
        return _invalid("HCS13_EXECUTION_REFERENCE_INVALID")

    try:
        reference = parse_hcs13_reference_v1(item.reference)
    except Hcs13V1Error:
        return _invalid("HCS13_EXECUTION_REFERENCE_INVALID")

    if (
        reference.registry_topic_id != topic_id
        or reference.sequence_number != sequence
    ):
        return _mismatch("HCS13_EXECUTION_REFERENCE_SCOPE_MISMATCH")

    result = await resolve_hcs13_schema_v1(
        config,
        Hcs13MirrorV1Request(
            hedera_network=network,
            reference=item.reference,
            expected_schema_sha256=checksum,
        ),
        decode_options,
    )
    facts: tuple[VerificationFact, ...] = ()

    if result.status == "resolved":
        facts = (
            _fact("hcs13.reference", result.reference.ref),
            _fact(
                "hcs13.schema_sha256",
                cast(str, result.schema_sha256),
            ),
            _fact(
                "hcs13.registry_memo_temporal_scope",
                "current_observation",
            ),
        )

    return _ObservationData(
        status=result.status,
        code=result.reason_code,
        resolver=result.resolver_id,
        times=(
            (result.registry_consensus_timestamp_exact,)
            if result.registry_consensus_timestamp_exact is not None
            else ()
        ),
        current_memo=result.registry_consensus_timestamp_exact is not None,
        sha256=result.content_sha256,
        facts=facts,
    )


async def _resolve_capability(
    config: Hcs1MirrorV1Config,
    network: HederaNetwork,
    evidence: Mapping[str, object] | None,
    item: StandardsResolutionPlanItemV1,
    decode_options: Hcs1V1ContentOptions,
) -> _ObservationData:
    if evidence is None or not item.reference:
        return _unavailable("HCS26_EXECUTION_REFERENCE_MISSING")

    discovery = _topic(evidence.get("discovery_registry_topic_id"))
    version_topic = _topic(evidence.get("version_registry_topic_id"))
    skill_uid = _positive(evidence.get("skill_uid"))
    sequence = _positive(evidence.get("version_sequence_number"))
    checksum = _hex(evidence.get("manifest_checksum_sha256"))
    version = _text(evidence.get("skill_version"))

    if (
        discovery is None
        or version_topic is None
        or skill_uid is None
        or sequence is None
        or checksum is None
        or not version
        or not _has_hcs1_reference(item.reference)
        or item.reference != evidence.get("manifest_hcs1_ref")
        or _js_length(version) > 64
        or _text(evidence.get("standard")) != "HCS-26"
    ):
        return _invalid("HCS26_EXECUTION_REFERENCE_INVALID")

    result = await resolve_hcs26_skill_version_v1(
        config,
        Hcs26MirrorV1Request(
            hedera_network=network,
            discovery_topic_id=discovery,
            discovery_sequence_number=skill_uid,
            version_sequence_number=sequence,
            expected_skill_uid=skill_uid,
            expected_version_topic_id=version_topic,
            expected_version=version,
            expected_manifest_reference=item.reference,
            expected_manifest_sha256=checksum,
        ),
        decode_options,
    )
    times = tuple(
        value
        for value in (
            result.discovery_consensus_timestamp_exact,
            result.version_consensus_timestamp_exact,
        )
        if value is not None
    )
    repository_commit = evidence.get("repository_commit")
    observed_commit = (
        result.manifest.get("commit")
        if result.manifest is not None
        else None
    )

    if (
        result.status == "resolved"
        and repository_commit
        and isinstance(observed_commit, str)
        and repository_commit != observed_commit
    ):
        return _ObservationData(
            status="conflict",
            code="HCS26_EXECUTION_RELEASE_COMMIT_MISMATCH",
            resolver=result.resolver_id,
            times=times,
            current_memo=True,
            sha256=result.content_sha256,
            facts=(
                _fact(
                    "hcs26.manifest_release_commit",
                    observed_commit,
                ),
            ),
        )

    facts: tuple[VerificationFact, ...] = ()

    if result.status == "resolved":
        resolved_facts = [
            _fact("hcs26.skill_uid", cast(int, result.skill_uid)),
            _fact("hcs26.version", cast(str, result.version)),
            _fact(
                "hcs26.manifest_sha256",
                cast(str, result.manifest_sha256),
            ),
            _fact(
                "hcs26.historical_version_status",
                cast(str, result.historical_version_status),
            ),
            _fact(
                "hcs26.registry_memo_temporal_scope",
                "current_observation",
            ),
        ]

        if isinstance(observed_commit, str):
            resolved_facts.append(
                _fact(
                    "hcs26.manifest_release_commit",
                    observed_commit,
                )
            )

        facts = tuple(resolved_facts)

    return _ObservationData(
        status=result.status,
        code=result.reason_code,
        resolver=result.resolver_id,
        times=times,
        current_memo=result.discovery_consensus_timestamp_exact is not None,
        sha256=result.content_sha256,
        facts=facts,
    )


def _outcome(
    status: IndependentStandardsItemStatusV1,
) -> VerificationOutcome:
    if status == "resolved":
        return "pass"
    if status in {"conflict", "invalid"}:
        return "fail"
    if status == "unsupported":
        return "unsupported"
    return "indeterminate"


def _aggregate(
    items: list[IndependentStandardsV1Item],
) -> IndependentStandardsStatusV1:
    if any(
        item.status in {"invalid", "conflict"}
        for item in items
    ):
        return "failed"

    if (
        not items
        or any(item.status != "resolved" for item in items)
    ):
        return "unavailable"

    return "verified"


def _summary_outcome(
    status: IndependentStandardsStatusV1,
) -> VerificationOutcome:
    if status == "verified":
        return "pass"
    if status == "failed":
        return "fail"
    return "indeterminate"


def _finding_outcome(
    report: ExecutionV1Report,
    check_id: str,
) -> VerificationOutcome | None:
    for finding in report.findings:
        if finding.check_id == check_id:
            return finding.outcome
    return None


def _schemas_valid(schemas: object) -> bool:
    if type(schemas) is not list or not schemas:
        return False

    for index, raw in enumerate(cast(list[object], schemas)):
        entry = _mapping_or_none(raw)

        if entry is None:
            return False

        role = _text(entry.get("role"))
        ordinal = (
            index
            if entry.get("ordinal") is None
            else entry.get("ordinal")
        )

        if (
            not role
            or _js_length(role) > 128
            or _CONTROL_RE.search(role) is not None
            or not _nonnegative_safe_integer(ordinal)
        ):
            return False

    return True


async def verify_execution_with_independent_standards_v1(
    config: Hcs1MirrorV1Config,
    input: ExecutionV1Input,
    decode_options: Hcs1V1ContentOptions | None = None,
) -> IndependentStandardsV1Report:
    """
    Resolve the exact SAGE standards plan using SDK-owned public resolvers.
    Caller-supplied resolver summaries are never treated as independent proof.
    Mirror REST establishes corroboration, not Hedera consensus authentication.
    """
    if (
        isinstance(input, Mapping)
        and input.get("profile") is not None
        and input.get("profile") != "sage-standards-v1"
    ):
        raise TypeError(
            "Independent SAGE standards require sage-standards-v1 profile"
        )

    report = verify_execution_v1_with_intent(input)
    subject = report.intent["subject"]
    network_raw = subject.get("hedera_network")

    if network_raw not in {"mainnet", "testnet"}:
        raise TypeError("Execution network is required")

    network = network_raw
    evidence = _mapping(input.get("evidence"))
    options = decode_options or Hcs1V1ContentOptions()
    preflight = (
        _finding_outcome(report, "input.bounds") == "pass"
        and _finding_outcome(report, "intent.subject") == "pass"
        and _finding_outcome(report, "profile.program_scope") == "pass"
        and _finding_outcome(report, "intent.program") != "fail"
        and _finding_outcome(report, "intent.result") != "fail"
        and evidence.get("available") is True
        and _network_match(
            evidence,
            network,
            subject["id"],
        )
    )
    typed_evidence = cast(
        PublicExecutionStandardsEvidence,
        dict(evidence),
    )
    plan: tuple[StandardsResolutionPlanItemV1, ...] = ()

    if preflight:
        plan = build_standards_resolution_plan(typed_evidence)

    standards = _mapping(evidence.get("standards"))
    schemas = standards.get("schemas")
    unique_keys = {item.key for item in plan}
    plan_valid = (
        _schemas_valid(schemas)
        and 4 <= len(plan) <= _MAX_REFERENCES
        and len(unique_keys) == len(plan)
        and all(
            item.key
            and _js_length(item.key) <= 256
            and _js_length(item.reference) <= 256
            for item in plan
        )
    )
    run = preflight and plan_valid
    items: list[IndependentStandardsV1Item] = []
    observations = list(report.observations)
    findings = list(report.findings)
    standards_observation_ids: list[str] = []
    agents = _mapping(evidence.get("agents"))
    capability = _mapping_or_none(evidence.get("capability"))
    schema_entries = (
        cast(list[object], schemas)
        if type(schemas) is list
        else []
    )

    if run:
        # Sequential resolution bounds outstanding network work and guarantees
        # stable observation ordering across hosts and timeout behavior.
        for index, item in enumerate(plan):
            target = item.target

            if isinstance(target, StandardsResolutionAgentTargetV1):
                observed = await _resolve_agent(
                    config,
                    network,
                    _mapping_or_none(agents.get(target.role)),
                    item,
                    options,
                )
            elif isinstance(
                target,
                StandardsResolutionCapabilityTargetV1,
            ):
                observed = await _resolve_capability(
                    config,
                    network,
                    capability,
                    item,
                    options,
                )
            elif isinstance(
                target,
                StandardsResolutionSchemaTargetV1,
            ):
                schema_evidence = (
                    _mapping_or_none(schema_entries[target.index])
                    if 0 <= target.index < len(schema_entries)
                    else None
                )
                observed = await _resolve_schema(
                    config,
                    network,
                    schema_evidence,
                    item,
                    options,
                )
            else:
                raise AssertionError(
                    "Unexpected standards resolution target"
                )

            observation_id = f"standards.mirror.{index}"
            present = observed.resolver is not None

            if present:
                facts: list[VerificationFact] = [
                    _fact("standards.plan_key", item.key),
                    _fact(
                        "standards.requested_reference",
                        item.reference,
                    ),
                    _fact("hedera.requested_network", network),
                    _fact(
                        "standards.resolution_status",
                        observed.status,
                    ),
                ]
                facts.extend(
                    _fact(
                        f"hedera.consensus_timestamp_exact.{time_index}",
                        timestamp,
                    )
                    for time_index, timestamp in enumerate(observed.times)
                )

                if observed.sha256 is not None:
                    facts.append(
                        _fact(
                            "standards.content_sha256",
                            observed.sha256,
                        )
                    )

                facts.extend(observed.facts)
                observations.append(
                    VerificationObservation(
                        id=observation_id,
                        subject=subject,
                        source="hedera_mirror",
                        resolver_id=cast(str, observed.resolver),
                        facts=tuple(facts),
                    ),
                )
                standards_observation_ids.append(observation_id)

            items.append(
                IndependentStandardsV1Item(
                    key=item.key,
                    standard=item.standard,
                    reference=item.reference,
                    status=observed.status,
                    reason_code=observed.code,
                    resolver_id=observed.resolver,
                    historical_consensus_timestamps_exact=observed.times,
                    current_topic_or_account_memo_observed=observed.current_memo,
                    content_sha256=observed.sha256,
                    assurance=(
                        "mirror_corroborated"
                        if observed.status == "resolved"
                        else "not_established"
                    ),
                )
            )
            findings.append(
                VerificationFinding(
                    check_id=f"standards.reference.{index}",
                    outcome=_outcome(observed.status),
                    reason_code=observed.code,
                    observation_ids=(
                        (observation_id,)
                        if present
                        else ()
                    ),
                ),
            )

    state: IndependentStandardsStatusV1 = (
        _aggregate(items)
        if run
        else "not_performed"
    )

    if not preflight:
        reason = "STANDARDS_EXECUTION_PREFLIGHT_FAILED"
    elif not plan_valid:
        reason = "STANDARDS_RESOLUTION_PLAN_INVALID"
    elif state == "verified":
        reason = None
    elif state == "failed":
        reason = "STANDARDS_INDEPENDENT_REFERENCE_CONFLICT"
    else:
        reason = "STANDARDS_INDEPENDENT_REFERENCE_UNAVAILABLE"

    summary_id = "standards.references_resolved"
    summary = VerificationFinding(
        check_id=summary_id,
        outcome=_summary_outcome(state),
        reason_code=reason,
        observation_ids=tuple(standards_observation_ids),
    )

    for index, finding in enumerate(findings):
        if finding.check_id == summary_id:
            findings[index] = summary
            break
    else:
        findings.append(summary)

    standards_summary = IndependentStandardsV1Summary(
        network=network,
        status=state,
        assurance=(
            "mirror_corroborated"
            if state == "verified"
            else "not_established"
        ),
        items=tuple(items),
    )
    return IndependentStandardsV1Report(
        intent=report.intent,
        findings=tuple(findings),
        observations=tuple(observations),
        verification_scope=report.verification_scope,
        independent_standards=standards_summary,
    )


__all__ = [
    "IndependentStandardsV1Item",
    "IndependentStandardsV1Report",
    "verify_execution_with_independent_standards_v1",
]