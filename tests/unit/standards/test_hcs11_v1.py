import json

import pytest

from vera_anchor_verifier.standards.hcs.hcs11_v1 import (
    MAX_HCS11_V1_PROFILE_BYTES,
    Hcs11V1Error,
    Hcs11V1Input,
    parse_hcs11_account_memo_v1,
    parse_hcs11_ai_agent_profile_v1,
    verify_hcs11_ai_agent_profile_v1,
)

BASE_DID = (
    "did:web:agents.veraanchor.ai"
)
NATIVE = (
    "hedera:testnet:0.0.123456"
)
UAID = (
    "uaid:did:"
    "agents.veraanchor.ai;"
    "uid=sage;"
    "registry=self;"
    "proto=hcs-26;"
    f"nativeId={NATIVE}"
)
SOURCE_PROFILE_UAID = (
    "uaid:did:sage;"
    "uid=sage;"
    "registry=self;"
    "proto=hcs-26;"
    "nativeId=hedera:testnet:0.0.123456"
)
SHA256 = (
    "f461c50805bdfadb1d2966c04a62e273"
    "cdb108e84201448323ab826c982f8f3e"
)


def profile() -> dict[str, object]:
    return {
        "version": "1.1",
        "type": 1,
        "display_name": "SAGE",
        "uaid": SOURCE_PROFILE_UAID,
        "alias": "sage",
        "bio": (
            "Vera Anchor SAGE compute agent"
        ),
        "profileImage": (
            "hcs://1/0.0.7001"
        ),
        "properties": {
            "network": "testnet",
            "service": "sage",
            "nested": {
                "z": 2,
                "a": 1,
            },
        },
        "aiAgent": {
            "type": 1,
            "capabilities": [
                17,
                0,
                7,
            ],
            "model": (
                "vera-anchor-sage"
            ),
            "creator": "Vera Anchor",
        },
    }


def input_json(
    overrides: (
        dict[str, object]
        | None
    ) = None,
) -> str:
    value = profile()

    if overrides:
        value.update(overrides)

    return json.dumps(
        value,
        separators=(",", ":"),
    )


def test_parses_supported_account_memo_references() -> None:
    hcs1 = (
        parse_hcs11_account_memo_v1(
            "hcs-11:hcs://1/0.0.1234"
        )
    )

    assert hcs1.protocol == "hcs-1"
    assert (
        hcs1.topic_id
        == "0.0.1234"
    )

    hcs2 = (
        parse_hcs11_account_memo_v1(
            "hcs-11:hcs://2/0.0.1234"
        )
    )

    assert hcs2.protocol == "hcs-2"

    with pytest.raises(
        Hcs11V1Error,
        match=(
            "HCS11_PROFILE_REF_INVALID"
        ),
    ):
        parse_hcs11_account_memo_v1(
            
                "hcs-11:"
                "https://elsewhere/agent"
            
        )


def test_recomputes_frozen_canonical_sha256_vector() -> None:
    result = (
        verify_hcs11_ai_agent_profile_v1(
            Hcs11V1Input(
                profile=input_json(),
                expected_sha256=SHA256,
            )
        )
    )

    assert result.status == "pass"
    assert result.reason_code is None
    assert result.sha256 == SHA256
    assert result.profile is not None
    assert (
        result.profile
        .aiAgent
        .capabilities
        == (
            0,
            7,
            17,
        )
    )
    assert (
        result.memo_reference_match
        == "not_checked"
    )


def test_reordered_properties_and_capabilities_have_same_digest() -> None:
    value = profile()

    value["properties"] = {
        "nested": {
            "a": 1,
            "z": 2,
        },
        "service": "sage",
        "network": "testnet",
    }

    value["aiAgent"] = {
        "capabilities": [
            0,
            7,
            17,
        ],
        "creator": "Vera Anchor",
        "model": "vera-anchor-sage",
        "type": 1,
    }

    result = (
        verify_hcs11_ai_agent_profile_v1(
            Hcs11V1Input(
                profile=json.dumps(
                    value,
                    separators=(",", ":"),
                ),
                expected_sha256=SHA256,
            )
        )
    )

    assert result.status == "pass"
    assert result.sha256 == SHA256


def test_detects_checksum_and_uaid_substitution() -> None:
    checksum = (
        verify_hcs11_ai_agent_profile_v1(
            Hcs11V1Input(
                profile=input_json(),
                expected_sha256=(
                    "0" * 64
                ),
            )
        )
    )

    assert checksum.reason_code == (
        "HCS11_CHECKSUM_MISMATCH"
    )

    uaid = (
        verify_hcs11_ai_agent_profile_v1(
            Hcs11V1Input(
                profile=input_json(),
                expected_uaid=UAID,
            )
        )
    )

    assert uaid.reason_code == (
        "HCS11_UAID_MISMATCH"
    )


def test_compares_memo_only_to_independent_expectation() -> None:
    unchecked = (
        verify_hcs11_ai_agent_profile_v1(
            Hcs11V1Input(
                profile=input_json(),
                account_memo=(
                    "hcs-11:"
                    "hcs://1/0.0.1234"
                ),
            )
        )
    )

    assert unchecked.status == "pass"
    assert (
        unchecked.memo_reference_match
        == "not_checked"
    )

    matched = (
        verify_hcs11_ai_agent_profile_v1(
            Hcs11V1Input(
                profile=input_json(),
                account_memo=(
                    "hcs-11:"
                    "hcs://1/0.0.1234"
                ),
                expected_profile_reference=(
                    "hcs://1/0.0.1234"
                ),
            )
        )
    )

    assert matched.status == "pass"
    assert (
        matched.memo_reference_match
        == "match"
    )

    mismatch = (
        verify_hcs11_ai_agent_profile_v1(
            Hcs11V1Input(
                profile=input_json(),
                account_memo=(
                    "hcs-11:"
                    "hcs://1/0.0.1234"
                ),
                expected_profile_reference=(
                    "hcs://1/0.0.9999"
                ),
            )
        )
    )

    assert mismatch.status == "fail"
    assert mismatch.reason_code == (
        "HCS11_PROFILE_REFERENCE_MISMATCH"
    )
    assert (
        mismatch.memo_reference_match
        == "mismatch"
    )


def test_rejects_unsupported_profile_material() -> None:
    wrong_type = (
        verify_hcs11_ai_agent_profile_v1(
            Hcs11V1Input(
                profile=input_json(
                    {
                        "type": 2,
                    }
                )
            )
        )
    )

    assert wrong_type.reason_code == (
        "HCS11_PROFILE_TYPE_UNSUPPORTED"
    )

    duplicate_capabilities = (
        verify_hcs11_ai_agent_profile_v1(
            Hcs11V1Input(
                profile=input_json(
                    {
                        "aiAgent": {
                            "type": 1,
                            "capabilities": [
                                7,
                                7,
                            ],
                            "model": "sage",
                        },
                    }
                )
            )
        )
    )

    assert (
        duplicate_capabilities.reason_code
        == "HCS11_CAPABILITIES_INVALID"
    )

    unsupported_field = (
        verify_hcs11_ai_agent_profile_v1(
            Hcs11V1Input(
                profile=input_json(
                    {
                        "inboundTopicId": (
                            "0.0.1234"
                        ),
                    }
                )
            )
        )
    )

    assert (
        unsupported_field.reason_code
        == "HCS11_FIELD_UNSUPPORTED"
    )


def test_rejects_duplicate_json_keys_including_escaped_aliases() -> None:
    duplicate = input_json().replace(
        '"version":"1.1"',
        (
            '"version":"1.1",'
            '"version":"1.2"'
        ),
    )

    result = (
        verify_hcs11_ai_agent_profile_v1(
            Hcs11V1Input(
                profile=duplicate
            )
        )
    )

    assert result.reason_code == (
        "HCS11_PROFILE_JSON_INVALID"
    )

    escaped = input_json().replace(
        '"version":"1.1"',
        (
            '"version":"1.1",'
            '"vers\\u0069on":"1.2"'
        ),
    )

    result = (
        verify_hcs11_ai_agent_profile_v1(
            Hcs11V1Input(
                profile=escaped
            )
        )
    )

    assert result.reason_code == (
        "HCS11_PROFILE_JSON_INVALID"
    )


def test_rejects_malformed_utf8_and_oversized_content() -> None:
    malformed = (
        verify_hcs11_ai_agent_profile_v1(
            Hcs11V1Input(
                profile=bytes(
                    [
                        123,
                        255,
                        125,
                    ]
                )
            )
        )
    )

    assert malformed.reason_code == (
        "HCS11_PROFILE_JSON_INVALID"
    )

    oversized = (
        verify_hcs11_ai_agent_profile_v1(
            Hcs11V1Input(
                profile=(
                    "x"
                    * (
                        MAX_HCS11_V1_PROFILE_BYTES
                        + 1
                    )
                )
            )
        )
    )

    assert oversized.reason_code == (
        "HCS11_PROFILE_TOO_LARGE"
    )


def test_treats_other_version_as_unsupported() -> None:
    result = (
        verify_hcs11_ai_agent_profile_v1(
            Hcs11V1Input(
                profile=input_json(
                    {
                        "version": "1.2",
                    }
                )
            )
        )
    )

    assert (
        result.status
        == "unsupported"
    )
    assert result.reason_code == (
        "HCS11_VERSION_UNSUPPORTED"
    )


def test_did_binding_and_missing_account_memo() -> None:
    value = profile()

    value["uaid"] = UAID

    encoded = json.dumps(
        value,
        separators=(",", ":"),
    )

    binding = (
        verify_hcs11_ai_agent_profile_v1(
            Hcs11V1Input(
                profile=encoded,
                expected_base_did=BASE_DID,
            )
        )
    )

    assert binding.status == "pass"

    wrong_did = (
        verify_hcs11_ai_agent_profile_v1(
            Hcs11V1Input(
                profile=encoded,
                expected_base_did=(
                    "did:web:other.example"
                ),
            )
        )
    )

    assert wrong_did.reason_code == (
        "HCS14_DID_BINDING_MISMATCH"
    )

    missing_memo = (
        verify_hcs11_ai_agent_profile_v1(
            Hcs11V1Input(
                profile=input_json(),
                expected_profile_reference=(
                    "hcs://1/0.0.1234"
                ),
            )
        )
    )

    assert missing_memo.reason_code == (
        "HCS11_ACCOUNT_MEMO_UNAVAILABLE"
    )


def test_direct_parser_returns_normalized_profile() -> None:
    parsed = (
        parse_hcs11_ai_agent_profile_v1(
            input_json()
        )
    )

    assert parsed.version == "1.1"
    assert parsed.type == 1
    assert (
        parsed.aiAgent.capabilities
        == (
            0,
            7,
            17,
        )
    )