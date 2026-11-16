import pytest

from vera_anchor_verifier.standards.hcs.hcs14_v1 import (
    Hcs14V1Error,
    build_hcs14_did_uaid_v1,
    parse_hcs14_did_uaid_v1,
    verify_hcs14_did_binding_v1,
)

BASE_DID = (
    "did:web:agents.veraanchor.ai"
)
SUFFIXED_DID = (
    f"{BASE_DID}?version=1"
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
SRC = (
    "zFrWvUrxPsHrJVpTfYyQ6qu2m3Nsj"
    "cigsLcnT8wo7FiSTRTeDoEu6"
)


def test_parses_canonical_uaid() -> None:
    value = (
        parse_hcs14_did_uaid_v1(
            UAID
        )
    )

    assert value.target == "did"
    assert (
        value.id
        == "agents.veraanchor.ai"
    )
    assert (
        value.params["uid"]
        == "sage"
    )
    assert (
        value.params["registry"]
        == "self"
    )
    assert (
        value.params["proto"]
        == "hcs-26"
    )
    assert (
        value.params["nativeId"]
        == NATIVE
    )

    with pytest.raises(
        TypeError,
    ):
        value.params[
            "uid"
        ] = "other"  # type: ignore[index]


def test_matches_frozen_unsanitized_and_sanitized_vectors() -> None:
    plain = (
        build_hcs14_did_uaid_v1(
            base_did=BASE_DID,
            uid="sage",
            registry="self",
            proto="hcs-26",
            native_id=NATIVE,
        )
    )

    assert plain.uaid == UAID

    sanitized = (
        build_hcs14_did_uaid_v1(
            base_did=SUFFIXED_DID,
            uid="sage",
            registry="self",
            proto="hcs-26",
            native_id=NATIVE,
        )
    )

    assert sanitized.uaid == (
        f"{UAID};src={SRC}"
    )

    binding = (
        verify_hcs14_did_binding_v1(
            uaid=(
                f"{UAID};src={SRC}"
            ),
            base_did=SUFFIXED_DID,
        )
    )

    assert binding.status == "pass"
    assert binding.reason_code is None


def test_binding_failure_modes() -> None:
    wrong_did = (
        verify_hcs14_did_binding_v1(
            uaid=UAID,
            base_did=(
                "did:web:other.example"
            ),
        )
    )

    assert wrong_did.reason_code == (
        "HCS14_DID_BINDING_MISMATCH"
    )

    missing_src = (
        verify_hcs14_did_binding_v1(
            uaid=UAID,
            base_did=SUFFIXED_DID,
        )
    )

    assert missing_src.reason_code == (
        "HCS14_SRC_REQUIRED"
    )

    invalid_src = (
        verify_hcs14_did_binding_v1(
            uaid=f"{UAID};src=z0",
            base_did=SUFFIXED_DID,
        )
    )

    assert invalid_src.reason_code == (
        "HCS14_SRC_INVALID"
    )

    unexpected_src = (
        verify_hcs14_did_binding_v1(
            uaid=f"{UAID};src=z2",
            base_did=BASE_DID,
        )
    )

    assert unexpected_src.reason_code == (
        "HCS14_SRC_UNEXPECTED"
    )


def test_rejects_unsupported_target_and_invalid_parameters() -> None:
    with pytest.raises(
        Hcs14V1Error,
        match=(
            "HCS14_TARGET_UNSUPPORTED"
        ),
    ):
        parse_hcs14_did_uaid_v1(
            UAID.replace(
                "uaid:did:",
                "uaid:aid:",
            )
        )

    with pytest.raises(
        Hcs14V1Error,
        match=(
            "HCS14_PARAMETER_INVALID"
        ),
    ):
        parse_hcs14_did_uaid_v1(
            f"{UAID};uid=again"
        )

    with pytest.raises(
        Hcs14V1Error,
        match=(
            "HCS14_PARAMETER_INVALID"
        ),
    ):
        parse_hcs14_did_uaid_v1(
            f"{UAID};test=one"
        )

    with pytest.raises(
        Hcs14V1Error,
        match=(
            "HCS14_PARAMETER_ORDER_INVALID"
        ),
    ):
        parse_hcs14_did_uaid_v1(
            UAID.replace(
                (
                    "uid=sage;"
                    "registry=self"
                ),
                (
                    "registry=self;"
                    "uid=sage"
                ),
            )
        )

    with pytest.raises(
        Hcs14V1Error,
        match=(
            "HCS14_FIELD_INVALID"
        ),
    ):
        parse_hcs14_did_uaid_v1(
            UAID.replace(
                "uid=sage",
                "uid=bad\nname",
            )
        )


def test_requires_canonical_required_parameters() -> None:
    with pytest.raises(
        Hcs14V1Error,
        match=(
            "HCS14_PARAMETER_MISSING"
        ),
    ):
        parse_hcs14_did_uaid_v1(
            
                "uaid:did:"
                "agents.veraanchor.ai;"
                "uid=sage;"
                "registry=self;"
                f"nativeId={NATIVE}"
            
        )

    # In serialized UAID syntax, ";" is the parameter delimiter.
    # It therefore creates a malformed second parameter before field
    # validation can occur.
    with pytest.raises(
        Hcs14V1Error,
        match=(
            "HCS14_PARAMETER_INVALID"
        ),
    ):
        parse_hcs14_did_uaid_v1(
            UAID.replace(
                "uid=sage",
                "uid=bad;value",
            )
        )

    # Builder inputs are validated before serialization, so a semicolon
    # inside a supplied field is rejected as an invalid field value.
    with pytest.raises(
        Hcs14V1Error,
        match=(
            "HCS14_FIELD_INVALID"
        ),
    ):
        build_hcs14_did_uaid_v1(
            base_did=BASE_DID,
            uid="bad;value",
            registry="self",
            proto="hcs-26",
            native_id=NATIVE,
        )