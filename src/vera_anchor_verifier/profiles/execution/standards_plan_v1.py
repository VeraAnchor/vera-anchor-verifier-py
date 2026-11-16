"""Deterministic execution standards-resolution reference plan."""

import math
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal, cast

from .contract_v1 import PublicExecutionStandardsEvidence
from .recomputation_v1 import _json_number


@dataclass(frozen=True, slots=True)
class StandardsResolutionAgentTargetV1:
    kind: Literal["agent"]
    role: Literal["requester", "executor"]


@dataclass(frozen=True, slots=True)
class StandardsResolutionCapabilityTargetV1:
    kind: Literal["capability"]


@dataclass(frozen=True, slots=True)
class StandardsResolutionSchemaTargetV1:
    kind: Literal["schema"]
    index: int


type StandardsResolutionPlanTargetV1 = (
    StandardsResolutionAgentTargetV1
    | StandardsResolutionCapabilityTargetV1
    | StandardsResolutionSchemaTargetV1
)


@dataclass(frozen=True, slots=True)
class StandardsResolutionPlanItemV1:
    key: str
    standard: str
    reference: str
    target: StandardsResolutionPlanTargetV1


def _mapping(value: object) -> Mapping[str, object]:
    if isinstance(value, Mapping):
        return cast(Mapping[str, object], value)
    return {}


def _js_number_text(value: object) -> str:
    if isinstance(value, bool):
        return "1" if value else "0"

    if isinstance(value, (int, float)):
        if isinstance(value, float) and not math.isfinite(value):
            if math.isnan(value):
                return "NaN"
            return "Infinity" if value > 0 else "-Infinity"

        try:
            return _json_number(value)
        except TypeError:
            return "NaN"

    if isinstance(value, str):
        text = value.strip()

        if not text:
            return "0"
        if text in ("Infinity", "+Infinity"):
            return "Infinity"
        if text == "-Infinity":
            return "-Infinity"

        try:
            if text.lower().startswith(("0x", "+0x", "-0x")):
                return str(int(text, 16))
            if text.lower().startswith(("0b", "+0b", "-0b")):
                return str(int(text, 2))
            if text.lower().startswith(("0o", "+0o", "-0o")):
                return str(int(text, 8))
            number = float(text)
        except ValueError:
            return "NaN"

        if math.isnan(number):
            return "NaN"
        if math.isinf(number):
            return "Infinity" if number > 0 else "-Infinity"
        return _json_number(number)

    return "NaN"


def _js_text(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return _js_number_text(value)
    if isinstance(value, Mapping):
        return "[object Object]"
    if isinstance(value, list):
        return ",".join(_js_text(item) for item in value).strip()
    return str(value).strip()


def build_standards_resolution_plan(
    evidence: PublicExecutionStandardsEvidence,
) -> tuple[StandardsResolutionPlanItemV1, ...]:
    agents = _mapping(evidence.get("agents"))
    requester = _mapping(agents.get("requester"))
    executor = _mapping(agents.get("executor"))

    requester_hcs11 = _mapping(requester.get("hcs11"))
    executor_hcs11 = _mapping(executor.get("hcs11"))
    capability = _mapping(evidence.get("capability"))

    items: list[StandardsResolutionPlanItemV1] = [
        StandardsResolutionPlanItemV1(
            key="agent:requester",
            standard="HCS-11/HCS-14",
            reference=_js_text(requester_hcs11.get("profile_hcs1_ref")),
            target=StandardsResolutionAgentTargetV1(
                kind="agent",
                role="requester",
            ),
        ),
        StandardsResolutionPlanItemV1(
            key="agent:executor",
            standard="HCS-11/HCS-14",
            reference=_js_text(executor_hcs11.get("profile_hcs1_ref")),
            target=StandardsResolutionAgentTargetV1(
                kind="agent",
                role="executor",
            ),
        ),
        StandardsResolutionPlanItemV1(
            key="capability:hcs26",
            standard="HCS-26",
            reference=_js_text(capability.get("manifest_hcs1_ref")),
            target=StandardsResolutionCapabilityTargetV1(kind="capability"),
        ),
    ]

    standards = _mapping(evidence.get("standards"))
    raw_schemas = standards.get("schemas")
    schemas = raw_schemas if isinstance(raw_schemas, list) else []

    for index, raw_schema in enumerate(schemas):
        schema = _mapping(raw_schema)
        raw_ordinal = schema.get("ordinal")
        ordinal = str(index) if raw_ordinal is None else _js_number_text(raw_ordinal)

        items.append(
            StandardsResolutionPlanItemV1(
                key=(
                    "schema:"
                    f"{_js_text(schema.get('role')).lower()}:"
                    f"{ordinal}"
                ),
                standard="HCS-13",
                reference=_js_text(schema.get("hcs13_ref")),
                target=StandardsResolutionSchemaTargetV1(
                    kind="schema",
                    index=index,
                ),
            )
        )

    return tuple(items)