import json
from dataclasses import replace
from typing import cast

import pytest

from vera_anchor_verifier.contracts import (
    VerificationFact,
    VerificationFinding,
    VerificationIntent,
    VerificationObservation,
    VerificationReport,
    VerificationSubject,
)
from vera_anchor_verifier.reports.core_v1 import (
    VERIFICATION_CORE_SCHEMA_VERSION,
    canonicalize_verification_core_v1,
    compute_verification_core_digest_v1,
)

EXPECTED_DIGEST = (
    "d32f4b858f4c765666889e7312985223"
    "d9db17b3ce3d4ad517aa428069d93e6ac"
    "c7c595ae22dc89d60e6b525eeb678557b"
    "d674944a98bf56abb3b044d87dc6fb"
)


def sample() -> VerificationReport:
    subject = cast(
        VerificationSubject,
        {
            "kind": "dataset",
            "id": "study-1",
            "hedera_network": "testnet",
        },
    )
    intent = cast(
        VerificationIntent,
        {
            "subject": subject,
            "expected": [],
        },
    )

    return VerificationReport(
        intent=intent,
        observations=(
            VerificationObservation(
                id="dataset.bundle",
                subject=subject,
                source="local_computation",
                facts=(
                    VerificationFact(
                        key="item_count",
                        state="available",
                        value=2,
                    ),
                    VerificationFact(
                        key="bundle_digest",
                        state="available",
                        value="a" * 128,
                    ),
                ),
            ),
            VerificationObservation(
                id="dataset.receipt",
                subject=subject,
                source="provided_evidence",
                facts=(
                    VerificationFact(
                        key="receipt_status",
                        state="unavailable",
                        reason_code=(
                            "RECEIPT_NOT_SUPPLIED"
                        ),
                    ),
                ),
            ),
        ),
        findings=(
            VerificationFinding(
                check_id="dataset.source_binding",
                outcome="pass",
                reason_code=None,
                observation_ids=(
                    "dataset.bundle",
                ),
            ),
            VerificationFinding(
                check_id="dataset.receipt_binding",
                outcome="indeterminate",
                reason_code=(
                    "RECEIPT_NOT_SUPPLIED"
                ),
                observation_ids=(
                    "dataset.receipt",
                    "dataset.bundle",
                ),
            ),
        ),
    )


def test_produces_versioned_projection_and_js_digest() -> None:
    report = sample()

    projection = json.loads(
        canonicalize_verification_core_v1(
            report
        )
    )

    assert (
        projection["schema_version"]
        == VERIFICATION_CORE_SCHEMA_VERSION
    )
    assert len(
        projection["findings"]
    ) == 2

    assert (
        compute_verification_core_digest_v1(
            report
        )
        == EXPECTED_DIGEST
    )


def test_normalizes_set_like_order_without_mutation() -> None:
    first = sample()

    reversed_report = replace(
        first,
        observations=tuple(
            replace(
                observation,
                facts=tuple(
                    reversed(
                        observation.facts
                    )
                ),
            )
            for observation in reversed(
                first.observations
            )
        ),
        findings=tuple(
            replace(
                finding,
                observation_ids=tuple(
                    reversed(
                        finding.observation_ids
                    )
                ),
            )
            for finding in reversed(
                first.findings
            )
        ),
    )

    assert (
        canonicalize_verification_core_v1(
            reversed_report
        )
        == canonicalize_verification_core_v1(
            first
        )
    )

    assert (
        compute_verification_core_digest_v1(
            reversed_report
        )
        == compute_verification_core_digest_v1(
            first
        )
    )

    assert (
        first.findings[0].check_id
        == "dataset.source_binding"
    )


def test_digest_changes_with_finding_or_fact() -> None:
    first = sample()

    changed_finding = replace(
        first,
        findings=(
            replace(
                first.findings[0],
                outcome="fail",
                reason_code="SOURCE_MISMATCH",
            ),
            first.findings[1],
        ),
    )

    changed_bundle = replace(
        first.observations[0],
        facts=(
            VerificationFact(
                key="item_count",
                state="available",
                value=3,
            ),
            first.observations[0].facts[1],
        ),
    )

    changed_fact = replace(
        first,
        observations=(
            changed_bundle,
            first.observations[1],
        ),
    )

    assert (
        compute_verification_core_digest_v1(
            changed_finding
        )
        != compute_verification_core_digest_v1(
            first
        )
    )

    assert (
        compute_verification_core_digest_v1(
            changed_fact
        )
        != compute_verification_core_digest_v1(
            first
        )
    )


def test_preserves_raw_and_hf_commitment_distinction() -> None:
    first = sample()

    raw = replace(
        first,
        intent=cast(
            VerificationIntent,
            {
                **first.intent,
                "expected": [
                    {
                        "key": "bundle_digest",
                        "kind": "digest",
                        "contract": "raw-sha3-512",
                        "digest": "A" * 128,
                    }
                ],
            },
        ),
    )

    hf = replace(
        first,
        intent=cast(
            VerificationIntent,
            {
                **first.intent,
                "expected": [
                    {
                        "key": "bundle_digest",
                        "kind": "digest",
                        "contract": "hf-contract-v1",
                        "material": "json",
                        "domain": (
                            "va:dataset:bundle:v1"
                        ),
                        "digest": "a" * 128,
                    }
                ],
            },
        ),
    )

    assert (
        compute_verification_core_digest_v1(
            raw
        )
        != compute_verification_core_digest_v1(
            hf
        )
    )

    projection = json.loads(
        canonicalize_verification_core_v1(
            raw
        )
    )

    assert (
        projection["intent"]["expected"][0][
            "digest"
        ]
        == "a" * 128
    )


def test_accepts_authorized_service_provenance() -> None:
    first = sample()

    authorized = replace(
        first.observations[1],
        source="authorized_service",
        resolver_id="core.authorized-hcs.v1",
    )

    report = replace(
        first,
        observations=(
            first.observations[0],
            authorized,
        ),
    )

    canonical = (
        canonicalize_verification_core_v1(
            report
        )
    )

    assert (
        '"source":"authorized_service"'
        in canonical
    )


def test_rejects_duplicate_ids_and_dangling_references() -> None:
    first = sample()

    with pytest.raises(
        TypeError,
        match="Duplicate check id",
    ):
        canonicalize_verification_core_v1(
            replace(
                first,
                findings=(
                    *first.findings,
                    first.findings[0],
                ),
            )
        )

    with pytest.raises(
        TypeError,
        match="missing observation",
    ):
        canonicalize_verification_core_v1(
            replace(
                first,
                findings=(
                    replace(
                        first.findings[0],
                        observation_ids=(
                            "unknown.observation",
                        ),
                    ),
                ),
            )
        )

    with pytest.raises(
        TypeError,
        match="Duplicate observation id",
    ):
        canonicalize_verification_core_v1(
            replace(
                first,
                observations=(
                    first.observations[0],
                    first.observations[0],
                ),
            )
        )


def test_rejects_invalid_numeric_and_outcome_values() -> None:
    first = sample()

    invalid_outcome = {
        "check_id": "dataset.source_binding",
        "outcome": "verified",
        "reason_code": None,
        "observation_ids": (
            "dataset.bundle",
        ),
    }

    with pytest.raises(
        TypeError,
        match="Invalid finding outcome",
    ):
        canonicalize_verification_core_v1(
            replace(
                first,
                findings=cast(
                    tuple[
                        VerificationFinding,
                        ...,
                    ],
                    (invalid_outcome,),
                ),
            )
        )

    for invalid in (
        float("nan"),
        -0.0,
    ):
        bad_fact = replace(
            first.observations[0],
            facts=(
                VerificationFact(
                    key="count",
                    state="available",
                    value=invalid,
                ),
            ),
        )

        with pytest.raises(
            TypeError,
            match="Invalid numeric fact",
        ):
            canonicalize_verification_core_v1(
                replace(
                    first,
                    observations=(
                        bad_fact,
                    ),
                    findings=(),
                )
            )


def test_uses_ecmascript_number_rendering() -> None:
    first = sample()

    numeric = replace(
        first.observations[0],
        facts=(
            VerificationFact(
                key="integer_float",
                state="available",
                value=1.0,
            ),
            VerificationFact(
                key="small_float",
                state="available",
                value=1e-7,
            ),
        ),
    )

    canonical = (
        canonicalize_verification_core_v1(
            replace(
                first,
                observations=(
                    numeric,
                ),
                findings=(),
            )
        )
    )

    assert (
        '"integer_float","state":"available","value":1'
        in canonical
    )
    assert (
        '"small_float","state":"available","value":1e-7'
        in canonical
    )


def test_top_level_profile_extensions_are_not_bound() -> None:
    first = sample()

    extended = cast(
        VerificationReport,
        {
            "intent": first.intent,
            "findings": first.findings,
            "observations": first.observations,
            "verification_scope": {
                "profile": "sage-standards-v1",
            },
        },
    )

    assert (
        compute_verification_core_digest_v1(
            extended
        )
        == compute_verification_core_digest_v1(
            first
        )
    )