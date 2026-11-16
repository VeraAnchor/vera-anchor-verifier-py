from typing import cast

from vera_anchor_verifier.profiles.execution.contract_v1 import (
    PublicExecutionStandardsEvidence,
)
from vera_anchor_verifier.profiles.execution.standards_plan_v1 import (
    StandardsResolutionAgentTargetV1,
    StandardsResolutionCapabilityTargetV1,
    StandardsResolutionPlanItemV1,
    StandardsResolutionSchemaTargetV1,
    build_standards_resolution_plan,
)


def evidence() -> PublicExecutionStandardsEvidence:
    return {
        "available": True,
        "contract_version": "1.0.0",
        "agents": {
            "requester": {
                "logical_id": "requester",
                "hcs11": {
                    "profile_hcs1_ref": (
                        "hcs://1/0.0.1001/requester.json"
                    ),
                },
            },
            "executor": {
                "logical_id": "executor",
                "hcs11": {
                    "profile_hcs1_ref": (
                        "hcs://1/0.0.1002/executor.json"
                    ),
                },
            },
        },
        "capability": {
            "standard": "HCS-26",
            "skill_uid": (
                "expression_clustering_v1"
            ),
            "manifest_hcs1_ref": (
                "hcs://1/0.0.2001/capability.json"
            ),
        },
        "standards": {
            "schemas": [
                {
                    "role": "sage_parameters",
                    "ordinal": 4,
                    "hcs13_ref": (
                        "hcs://13/0.0.3001#41"
                    ),
                },
                {
                    "role": "result_evidence",
                    "ordinal": 9,
                    "hcs13_ref": (
                        "hcs://13/0.0.3002#42"
                    ),
                },
            ],
        },
    }


def test_builds_exact_ordered_plan() -> None:
    assert build_standards_resolution_plan(
        evidence()
    ) == (
        StandardsResolutionPlanItemV1(
            key="agent:requester",
            standard="HCS-11/HCS-14",
            reference=(
                "hcs://1/0.0.1001/requester.json"
            ),
            target=(
                StandardsResolutionAgentTargetV1(
                    kind="agent",
                    role="requester",
                )
            ),
        ),
        StandardsResolutionPlanItemV1(
            key="agent:executor",
            standard="HCS-11/HCS-14",
            reference=(
                "hcs://1/0.0.1002/executor.json"
            ),
            target=(
                StandardsResolutionAgentTargetV1(
                    kind="agent",
                    role="executor",
                )
            ),
        ),
        StandardsResolutionPlanItemV1(
            key="capability:hcs26",
            standard="HCS-26",
            reference=(
                "hcs://1/0.0.2001/capability.json"
            ),
            target=(
                StandardsResolutionCapabilityTargetV1(
                    kind="capability",
                )
            ),
        ),
        StandardsResolutionPlanItemV1(
            key="schema:sage_parameters:4",
            standard="HCS-13",
            reference=(
                "hcs://13/0.0.3001#41"
            ),
            target=(
                StandardsResolutionSchemaTargetV1(
                    kind="schema",
                    index=0,
                )
            ),
        ),
        StandardsResolutionPlanItemV1(
            key="schema:result_evidence:9",
            standard="HCS-13",
            reference=(
                "hcs://13/0.0.3002#42"
            ),
            target=(
                StandardsResolutionSchemaTargetV1(
                    kind="schema",
                    index=1,
                )
            ),
        ),
    )


def test_normalizes_without_reordering_schema_targets() -> None:
    value = evidence()

    assert value["agents"] is not None
    assert value["capability"] is not None
    assert value["standards"] is not None

    requester = value["agents"]["requester"]
    executor = value["agents"]["executor"]

    assert requester is not None
    assert executor is not None
    assert requester["hcs11"] is not None
    assert executor["hcs11"] is not None

    requester["hcs11"]["profile_hcs1_ref"] = (
        "  hcs://1/0.0.1001/requester.json  "
    )
    executor["hcs11"]["profile_hcs1_ref"] = (
        "\thcs://1/0.0.1002/executor.json\n"
    )
    value["capability"]["manifest_hcs1_ref"] = (
        " hcs://1/0.0.2001/capability.json "
    )

    value["standards"]["schemas"] = cast(
        list,
        [
            {
                "role": "  ZETA  ",
                "ordinal": None,
                "hcs13_ref": (
                    "  hcs://13/0.0.3001#20  "
                ),
            },
            {
                "role": " Alpha ",
                "hcs13_ref": (
                    "hcs://13/0.0.3001#1"
                ),
            },
            {
                "role": "OUTPUT",
                "ordinal": 0,
                "hcs13_ref": (
                    "hcs://13/0.0.3001#3"
                ),
            },
            {
                "role": "metrics",
                "ordinal": "7",
                "hcs13_ref": (
                    "hcs://13/0.0.3001#4"
                ),
            },
        ],
    )

    plan = build_standards_resolution_plan(
        value
    )

    assert tuple(
        item.key
        for item in plan[3:]
    ) == (
        "schema:zeta:0",
        "schema:alpha:1",
        "schema:output:0",
        "schema:metrics:7",
    )

    assert tuple(
        item.target.index
        for item in plan[3:]
        if isinstance(
            item.target,
            StandardsResolutionSchemaTargetV1,
        )
    ) == (
        0,
        1,
        2,
        3,
    )


def test_keeps_missing_mandatory_slots_visible() -> None:
    value = cast(
        PublicExecutionStandardsEvidence,
        {
            "available": True,
            "contract_version": "1.0.0",
            "agents": {
                "requester": None,
                "executor": None,
            },
            "capability": None,
            "standards": {
                "schemas": [],
            },
        },
    )

    plan = build_standards_resolution_plan(
        value
    )

    assert tuple(
        (
            item.key,
            item.reference,
        )
        for item in plan
    ) == (
        (
            "agent:requester",
            "",
        ),
        (
            "agent:executor",
            "",
        ),
        (
            "capability:hcs26",
            "",
        ),
    )


def test_preserves_duplicate_and_malformed_schema_identity() -> None:
    value = evidence()

    assert value["standards"] is not None

    value["standards"]["schemas"] = cast(
        list,
        [
            None,
            {
                "role": "",
                "ordinal": 1,
                "hcs13_ref": "",
            },
            {
                "role": "INPUT",
                "ordinal": 2,
                "hcs13_ref": (
                    "hcs://13/0.0.3001#2"
                ),
            },
            {
                "role": " input ",
                "ordinal": 2,
                "hcs13_ref": (
                    "hcs://13/0.0.3002#3"
                ),
            },
        ],
    )

    plan = build_standards_resolution_plan(
        value
    )

    assert tuple(
        item.key
        for item in plan[3:]
    ) == (
        "schema::0",
        "schema::1",
        "schema:input:2",
        "schema:input:2",
    )


def test_projects_only_plan_fields_and_handles_max_schema_count() -> None:
    value = cast(
        dict[str, object],
        evidence(),
    )

    value["secret"] = (
        "TOP-LEVEL-SECRET"
    )

    standards = value[
        "standards"
    ]

    assert isinstance(
        standards,
        dict,
    )

    standards["schemas"] = [
        {
            "role": "schema",
            "ordinal": index,
            "hcs13_ref": (
                f"hcs://13/0.0.4001#{index + 1}"
            ),
            "secret": (
                f"SECRET-{index}"
            ),
        }
        for index in range(
            256
        )
    ]

    plan = (
        build_standards_resolution_plan(
            cast(
                PublicExecutionStandardsEvidence,
                value,
            )
        )
    )

    assert len(plan) == 259
    assert plan[3].key == (
        "schema:schema:0"
    )
    assert plan[-1].key == (
        "schema:schema:255"
    )

    assert all(
        not hasattr(
            item,
            "secret",
        )
        for item in plan
    )