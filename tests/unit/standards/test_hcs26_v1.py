import json
from typing import cast

import pytest

from vera_anchor_verifier.standards.hcs.hcs26_v1 import (
    Hcs26V1Error,
    Hcs26VersionVerificationInput,
    finalize_hcs26_skill_manifest_v1,
    parse_hcs26_discovery_register_v1,
    parse_hcs26_discovery_update_v1,
    parse_hcs26_memo_v1,
    parse_hcs26_skill_manifest_v1,
    parse_hcs26_version_register_v1,
    verify_hcs26_skill_version_v1,
)

A = "a" * 64
B = "b" * 64
COMMIT = "c" * 40

MANIFEST_SHA = (
    "cbf649819f4269e9a60f2222aebde24a"
    "c3babb28e36ee51f83a7ed808a9953a6"
)


def manifest() -> dict[str, object]:
    return {
        "name": "SAGE Verifiable Compute",
        "description": (
            "Execute deterministic SAGE scientific workloads "
            "with Vera Anchor provenance."
        ),
        "version": "1.0.0",
        "license": "Apache-2.0",
        "author": {
            "name": "Vera Anchor",
            "contact": "engineering@veraanchor.ai",
            "url": "https://veraanchor.ai",
        },
        "tags": [1403, 50401, 1403],
        "languages": ["javascript", "python"],
        "homepage": "https://veraanchor.ai/sage",
        "repo": "https://github.com/veraanchor/sage",
        "commit": COMMIT,
        "entrypoints": [
            {
                "path": "scripts/run.js",
                "language": "javascript",
                "args": ["--deterministic"],
            }
        ],
        "files": [
            {
                "path": "scripts/run.js",
                "hrl": "hcs://1/0.0.55555",
                "sha256": B,
                "mime": "application/javascript",
            },
            {
                "path": "SKILL.md",
                "hrl": "hcs://1/0.0.44444",
                "sha256": A.upper(),
                "mime": "text/markdown",
            },
        ],
    }


def version_register(
    overrides: dict[str, object] | None = None,
) -> str:
    value: dict[str, object] = {
        "p": "hcs-26",
        "op": "register",
        "skill_uid": 42,
        "version": "1.0.0",
        "t_id": "0.0.33333",
        "checksum": f"sha256:{MANIFEST_SHA}",
        "status": "active",
    }

    if overrides:
        value.update(overrides)

    return json.dumps(
        value,
        separators=(",", ":"),
    )


def test_parses_topic_memo_variants() -> None:
    discovery = parse_hcs26_memo_v1(
        "hcs-26:0:86400:0"
    )

    assert discovery.indexed is True
    assert discovery.ttl == 86400
    assert discovery.type == "discovery"
    assert discovery.type_code == 0

    version = parse_hcs26_memo_v1(
        "hcs-26:1:0:1"
    )

    assert version.indexed is False
    assert version.ttl == 0
    assert version.type == "version"
    assert version.type_code == 1

    with pytest.raises(
        Hcs26V1Error,
        match="HCS26_MEMO_INVALID",
    ):
        parse_hcs26_memo_v1(
            "hcs-26:0:86400:2"
        )

    with pytest.raises(
        Hcs26V1Error,
        match="HCS26_TTL_INVALID",
    ):
        parse_hcs26_memo_v1(
            "hcs-26:0:31536001:0"
        )


def test_parses_discovery_update_and_version_registers() -> None:
    discovery = (
        parse_hcs26_discovery_register_v1(
            json.dumps(
                {
                    "p": "hcs-26",
                    "op": "register",
                    "t_id": "0.0.234567",
                    "account_id": "0.0.78910",
                    "metadata": (
                        "hcs://1/0.0.22222"
                    ),
                }
            )
        )
    )

    assert (
        discovery["t_id"]
        == "0.0.234567"
    )
    assert (
        discovery["account_id"]
        == "0.0.78910"
    )
    assert (
        discovery["metadata"]
        == "hcs://1/0.0.22222"
    )

    update = (
        parse_hcs26_discovery_update_v1(
            json.dumps(
                {
                    "p": "hcs-26",
                    "op": "update",
                    "uid": "42",
                    "metadata": {
                        "name": "Updated",
                    },
                }
            )
        )
    )

    assert update["uid"] == "42"
    assert update["metadata"] == {
        "name": "Updated",
    }

    version = (
        parse_hcs26_version_register_v1(
            version_register(
                {
                    "checksum": (
                        MANIFEST_SHA
                    ),
                }
            )
        )
    )

    assert version.skill_uid == 42
    assert version.status == "active"
    assert (
        version.checksum
        == f"sha256:{MANIFEST_SHA}"
    )


def test_rejects_invalid_registry_wire_shape() -> None:
    with pytest.raises(
        Hcs26V1Error,
        match="HCS26_OPERATION_INVALID",
    ):
        parse_hcs26_discovery_register_v1(
            '{"p":"hcs-26","op":"delete"}'
        )

    with pytest.raises(
        Hcs26V1Error,
        match="HCS26_UPDATE_EMPTY",
    ):
        parse_hcs26_discovery_update_v1(
            
                '{"p":"hcs-26","op":"update",'
                '"uid":"42"}'
            
        )

    with pytest.raises(
        Hcs26V1Error,
        match="HCS26_FIELD_UNSUPPORTED",
    ):
        parse_hcs26_version_register_v1(
            version_register(
                {"extra": True}
            )
        )

    with pytest.raises(
        Hcs26V1Error,
        match="HCS26_CHECKSUM_INVALID",
    ):
        parse_hcs26_version_register_v1(
            version_register(
                {
                    "checksum": (
                        "A" * 64
                    ),
                }
            )
        )


def test_rejects_oversized_and_ambiguous_wire_messages() -> None:
    with pytest.raises(
        Hcs26V1Error,
        match="HCS26_MESSAGE_TOO_LARGE",
    ):
        parse_hcs26_version_register_v1(
            json.dumps(
                {
                    "p": "hcs-26",
                    "op": "register",
                    "skill_uid": 42,
                    "version": "1.0.0",
                    "t_id": "0.0.33333",
                    "checksum": A,
                    "m": "x" * 950,
                }
            )
        )

    with pytest.raises(
        Hcs26V1Error,
        match="HCS26_MESSAGE_INVALID",
    ):
        parse_hcs26_version_register_v1(
            
                '{"p":"hcs-26",'
                '"op":"register",'
                '"op":"update"}'
            
        )

    with pytest.raises(
        Hcs26V1Error,
        match="HCS26_MESSAGE_INVALID",
    ):
        parse_hcs26_version_register_v1(
            
                '{"p":"hcs-26",'
                '"op":"register",'
                '"o\\u0070":"update"}'
            
        )


def test_recomputes_frozen_skill_manifest_vector() -> None:
    value = (
        finalize_hcs26_skill_manifest_v1(
            manifest()
        )
    )

    assert value.byte_length == 868
    assert value.sha256 == MANIFEST_SHA

    parsed = (
        parse_hcs26_skill_manifest_v1(
            json.dumps(
                manifest()
            )
        )
    )

    assert parsed.sha256 == MANIFEST_SHA

    files = parsed.manifest["files"]

    assert isinstance(files, list)

    assert [
        file["path"]
        for file in files
        if isinstance(file, dict)
    ] == [
        "SKILL.md",
        "scripts/run.js",
    ]

    assert parsed.manifest["tags"] == [
        1403,
        50401,
    ]


def test_verifies_version_checksum_and_expectations() -> None:
    evidence = Hcs26VersionVerificationInput(
        version_register=(
            version_register()
        ),
        manifest=json.dumps(
            manifest()
        ),
        expected_skill_uid=42,
        expected_manifest_topic_id=(
            "0.0.33333"
        ),
        expected_version="1.0.0",
        expected_sha256=MANIFEST_SHA,
    )

    passed = (
        verify_hcs26_skill_version_v1(
            evidence
        )
    )

    assert passed.status == "pass"
    assert passed.reason_code is None
    assert (
        passed.checksum_match
        == "match"
    )
    assert (
        passed.version_status
        == "active"
    )
    assert passed.sha256 == MANIFEST_SHA

    wrong_uid = (
        verify_hcs26_skill_version_v1(
            Hcs26VersionVerificationInput(
                version_register=(
                    evidence.version_register
                ),
                manifest=evidence.manifest,
                expected_skill_uid=41,
            )
        )
    )

    assert wrong_uid.status == "fail"
    assert wrong_uid.reason_code == (
        "HCS26_SKILL_UID_MISMATCH"
    )

    wrong_checksum = (
        verify_hcs26_skill_version_v1(
            Hcs26VersionVerificationInput(
                version_register=(
                    version_register(
                        {
                            "checksum": A,
                        }
                    )
                ),
                manifest=evidence.manifest,
            )
        )
    )

    assert (
        wrong_checksum.status
        == "fail"
    )
    assert wrong_checksum.reason_code == (
        "HCS26_CHECKSUM_MISMATCH"
    )
    assert (
        wrong_checksum.checksum_match
        == "mismatch"
    )

    wrong_version = (
        verify_hcs26_skill_version_v1(
            Hcs26VersionVerificationInput(
                version_register=(
                    version_register(
                        {
                            "version": (
                                "2.0.0"
                            ),
                        }
                    )
                ),
                manifest=evidence.manifest,
            )
        )
    )

    assert wrong_version.status == "fail"
    assert wrong_version.reason_code == (
        "HCS26_VERSION_MISMATCH"
    )


def test_preserves_historical_status_without_policy_claim() -> None:
    result = (
        verify_hcs26_skill_version_v1(
            Hcs26VersionVerificationInput(
                version_register=(
                    version_register(
                        {
                            "status": "yanked",
                        }
                    )
                ),
                manifest=json.dumps(
                    manifest()
                ),
            )
        )
    )

    assert result.status == "pass"
    assert result.version_status == "yanked"


def test_rejects_unsafe_manifest_paths_and_references() -> None:
    base = manifest()
    files = cast(
        list[dict[str, object]],
        base["files"],
    )

    traversal = {
        **base,
        "files": [
            {
                **file,
                "path": "../SKILL.md",
            }
            for file in files
        ],
    }

    with pytest.raises(
        Hcs26V1Error,
        match="HCS26_PATH_INVALID",
    ):
        finalize_hcs26_skill_manifest_v1(
            traversal
        )

    with pytest.raises(
        Hcs26V1Error,
        match="HCS26_PATH_DUPLICATE",
    ):
        finalize_hcs26_skill_manifest_v1(
            {
                **base,
                "files": [
                    files[1],
                    files[1],
                ],
            }
        )

    with pytest.raises(
        Hcs26V1Error,
        match="HCS26_SKILL_MD_REQUIRED",
    ):
        finalize_hcs26_skill_manifest_v1(
            {
                **base,
                "files": [
                    files[0],
                ],
            }
        )

    with pytest.raises(
        Hcs26V1Error,
        match="HCS1_REF_INVALID",
    ):
        finalize_hcs26_skill_manifest_v1(
            {
                **base,
                "files": [
                    files[0],
                    {
                        **files[1],
                        "hrl": (
                            "https://example.com"
                        ),
                    },
                ],
            }
        )

    with pytest.raises(
        Hcs26V1Error,
        match="HCS26_FIELD_UNSUPPORTED",
    ):
        finalize_hcs26_skill_manifest_v1(
            {
                **base,
                "extra": 42,
            }
        )


def test_rejects_malformed_and_oversized_manifests() -> None:
    with pytest.raises(
        Hcs26V1Error,
        match="HCS26_MANIFEST_JSON_INVALID",
    ):
        parse_hcs26_skill_manifest_v1(
            '{"name":"a","name":"b"}'
        )

    with pytest.raises(
        Hcs26V1Error,
        match="HCS26_MANIFEST_JSON_INVALID",
    ):
        parse_hcs26_skill_manifest_v1(
            "not-json"
        )

    with pytest.raises(
        Hcs26V1Error,
        match="HCS26_MANIFEST_TOO_LARGE",
    ):
        finalize_hcs26_skill_manifest_v1(
            {
                **manifest(),
                "entrypoints": [
                    "x" * (300 * 1024)
                ],
            }
        )