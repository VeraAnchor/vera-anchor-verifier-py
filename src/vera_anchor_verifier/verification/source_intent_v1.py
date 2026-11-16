"""Caller-intent binding for Dataset and Ingest v1 verification."""

import math
import re
from collections.abc import Mapping
from typing import cast

from ..contracts import (
    HederaNetwork,
    VerificationFact,
    VerificationFinding,
    VerificationIntent,
    VerificationObservation,
    VerificationObservationSource,
    VerificationOutcome,
    VerificationReport,
    VerificationSubject,
)
from ..profiles.dataset import (
    DatasetV1BundleComputed,
    DatasetV1ReceiptComputed,
    verify_dataset_v1_bundle,
    verify_dataset_v1_receipt,
    verify_dataset_v1_sources,
)
from ..profiles.ingest import (
    IngestV1BundleComputed,
    IngestV1ReceiptComputed,
    verify_ingest_v1_bundle,
    verify_ingest_v1_pair,
    verify_ingest_v1_sources,
)
from ..profiles.source_v1_helpers import (
    SourceV1File,
    SourceV1Limits,
)

_HEX_512 = re.compile(r"^[a-f0-9]{128}$", re.IGNORECASE | re.ASCII)
_EXPECTED_KEY = re.compile(r"^[a-z][a-z0-9_]{0,63}$", re.ASCII)
_MAX_EXPECTATIONS = 32
_MAX_SAFE_INTEGER = (1 << 53) - 1
_MISSING = object()

_ECMASCRIPT_TRIM = (
    "\u0009\u000b\u000c\u0020\u00a0\u1680"
    "\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a"
    "\u2028\u2029\u202f\u205f\u3000\ufeff\u000a\u000d"
)

type Profile = str
type BundleComputed = DatasetV1BundleComputed | IngestV1BundleComputed
type ReceiptComputed = DatasetV1ReceiptComputed | IngestV1ReceiptComputed


def _js_length(value: str) -> int:
    return len(value.encode("utf-16-le", "surrogatepass")) // 2


def _trim(value: str) -> str:
    return value.strip(_ECMASCRIPT_TRIM)


def _safe_integer(value: object) -> bool:
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


def _checked_intent(value: object) -> VerificationIntent:
    if not isinstance(value, Mapping):
        raise TypeError("Verification intent must have a subject")

    raw_subject = value.get("subject")
    if not isinstance(raw_subject, Mapping):
        raise TypeError("Verification intent must have a subject")

    subject_id = raw_subject.get("id")
    if (
        not isinstance(subject_id, str)
        or not subject_id
        or _js_length(subject_id) > 256
        or _trim(subject_id) != subject_id
    ):
        raise TypeError(
            "Verification subject must have a bounded, canonical ID"
        )

    if "hedera_network" in raw_subject:
        network = raw_subject.get("hedera_network")
        if network not in ("testnet", "mainnet"):
            raise TypeError("Invalid expected Hedera network")

    raw_expected = value.get("expected")
    if (
        type(raw_expected) is not list
        or len(raw_expected) > _MAX_EXPECTATIONS
    ):
        raise TypeError(
            "Verification expectations must be a bounded array"
        )

    used: set[str] = set()
    expectations: list[dict[str, object]] = []

    for raw_commitment in cast(list[object], raw_expected):
        if not isinstance(raw_commitment, Mapping):
            raise TypeError("Invalid commitment expectation key")

        key = raw_commitment.get("key")
        if (
            not isinstance(key, str)
            or _EXPECTED_KEY.fullmatch(key) is None
        ):
            raise TypeError("Invalid commitment expectation key")

        if key in used:
            raise TypeError("Duplicate commitment expectation key")
        used.add(key)

        kind = raw_commitment.get("kind")

        if kind not in ("digest", "merkle-root"):
            raise TypeError("Unsupported commitment expectation kind")

        if kind == "digest":
            digest = raw_commitment.get("digest")
            if (
                not isinstance(digest, str)
                or _HEX_512.fullmatch(digest) is None
            ):
                raise TypeError(
                    "Expected digest must be a SHA3-512 hex commitment"
                )

        else:
            root_hash = raw_commitment.get("root_hash")
            leaf_count = raw_commitment.get("leaf_count")

            if (
                not isinstance(root_hash, str)
                or _HEX_512.fullmatch(root_hash) is None
                or not _safe_integer(leaf_count)
                or cast(int | float, leaf_count) < 1
            ):
                raise TypeError(
                    "Invalid expected Merkle root or leaf count"
                )

        expectations.append(dict(raw_commitment))

    subject = dict(raw_subject)

    return cast(
        VerificationIntent,
        {
            "subject": subject,
            "expected": expectations,
        },
    )


def _fact(
    key: str,
    value: str | int | bool | None,
) -> VerificationFact:
    return VerificationFact(
        key=key,
        state="available",
        value=value,
    )


def _observation(
    observation_id: str,
    subject: VerificationSubject,
    source: VerificationObservationSource,
    facts: list[VerificationFact],
) -> VerificationObservation:
    return VerificationObservation(
        id=observation_id,
        subject=cast(VerificationSubject, dict(subject)),
        source=source,
        facts=tuple(facts),
    )


def _finding(
    check_id: str,
    outcome: VerificationOutcome,
    reason_code: str | None,
    observation_ids: tuple[str, ...] = (),
) -> VerificationFinding:
    return VerificationFinding(
        check_id=check_id,
        outcome=outcome,
        reason_code=reason_code,
        observation_ids=observation_ids,
    )


def _commitment_claim(
    profile: Profile,
    key: str,
    bundle: BundleComputed,
) -> tuple[str, str] | None:
    if key == "bundle_digest":
        return (
            bundle.bundle_digest,
            f"va:{profile}:bundle:v1",
        )

    if key == "idempotency_key":
        return (
            bundle.idempotency_key,
            f"va:{profile}:idem:v1",
        )

    if (
        profile == "dataset"
        and key == "dataset_fingerprint"
        and isinstance(bundle, DatasetV1BundleComputed)
    ):
        return (
            bundle.dataset_fingerprint,
            "va:dataset:fingerprint:v1",
        )

    if (
        profile == "ingest"
        and key == "fingerprint"
        and isinstance(bundle, IngestV1BundleComputed)
    ):
        return (
            bundle.fingerprint,
            "va:ingest:fingerprint:v1",
        )

    return None


def _compare_expected(
    expected: Mapping[str, object],
    *,
    profile: Profile,
    bundle: BundleComputed,
    source_root: str | None,
    source_count: int,
    source_valid: bool,
    bundle_valid: bool,
    observation_ids: tuple[str, ...],
) -> VerificationFinding:
    key = cast(str, expected["key"])
    check_id = f"intent.commitment.{key}"

    if expected["kind"] == "merkle-root":
        algorithm = (
            "hf-dataset-v1"
            if profile == "dataset"
            else "hf-ingest-v1"
        )

        if (
            key != "merkle_root"
            or expected.get("tree_alg") != algorithm
        ):
            return _finding(
                check_id,
                "unsupported",
                "COMMITMENT_CONTRACT_UNSUPPORTED",
            )

        if (
            source_root is None
            or not source_valid
            or not bundle_valid
        ):
            return _finding(
                check_id,
                "indeterminate",
                "SOURCE_BINDING_NOT_ESTABLISHED",
                observation_ids,
            )

        root_hash = cast(str, expected["root_hash"])
        leaf_count = cast(int | float, expected["leaf_count"])
        matches = (
            root_hash.lower() == source_root
            and leaf_count == source_count
        )

        return _finding(
            check_id,
            "pass" if matches else "fail",
            None if matches else "EXPECTED_MERKLE_MISMATCH",
            observation_ids,
        )

    claim = _commitment_claim(profile, key, bundle)

    if (
        claim is None
        or expected.get("contract") != "hf-contract-v1"
        or expected.get("material") != "json"
        or expected.get("domain") != claim[1]
    ):
        return _finding(
            check_id,
            "unsupported",
            "COMMITMENT_CONTRACT_UNSUPPORTED",
        )

    if not source_valid or not bundle_valid:
        return _finding(
            check_id,
            "indeterminate",
            "SOURCE_BINDING_NOT_ESTABLISHED",
            observation_ids,
        )

    digest = cast(str, expected["digest"])
    matches = digest.lower() == claim[0]

    return _finding(
        check_id,
        "pass" if matches else "fail",
        None if matches else "EXPECTED_DIGEST_MISMATCH",
        observation_ids,
    )


def _report(
    intent_value: object,
    *,
    profile: Profile,
    subject: VerificationSubject,
    bundle: BundleComputed,
    receipt: ReceiptComputed | None,
    source_root: str | None,
    source_count: int,
    source_bytes: int,
    source_valid: bool,
    bundle_valid: bool,
    receipt_binding_valid: bool | None,
) -> VerificationReport:
    intent = _checked_intent(intent_value)

    source_id = f"{profile}.source"
    bundle_id = f"{profile}.bundle"
    receipt_id = f"{profile}.receipt"

    source_facts = [
        _fact("source_file_or_item_count", source_count),
        _fact("source_total_bytes", source_bytes),
    ]

    if source_root is not None:
        source_facts.append(
            _fact("source_merkle_root", source_root)
        )

    if isinstance(bundle, DatasetV1BundleComputed):
        count = bundle.file_count
        fingerprint_key = "dataset_fingerprint"
        fingerprint = bundle.dataset_fingerprint
    else:
        count = bundle.item_count
        fingerprint_key = "fingerprint"
        fingerprint = bundle.fingerprint

    bundle_facts = [
        _fact("bundle_digest", bundle.bundle_digest),
        _fact("idempotency_key", bundle.idempotency_key),
        _fact("declared_file_or_item_count", count),
        _fact("declared_total_bytes", bundle.total_bytes),
        _fact(fingerprint_key, fingerprint),
    ]

    content_subject = cast(
        VerificationSubject,
        {
            "kind": subject["kind"],
            "id": subject["id"],
        },
    )

    observations = [
        _observation(
            source_id,
            content_subject,
            "local_computation",
            source_facts,
        ),
        _observation(
            bundle_id,
            content_subject,
            "local_computation",
            bundle_facts,
        ),
    ]

    if receipt is not None:
        observations.append(
            _observation(
                receipt_id,
                subject,
                "provided_evidence",
                [
                    _fact(
                        "receipt_id_recomputed",
                        receipt.receipt_id,
                    ),
                    _fact(
                        "receipt_declared_network",
                        receipt.hedera_network,
                    ),
                ],
            )
        )

    findings = [
        _finding(
            f"{profile}.source_binding",
            "pass" if source_valid else "fail",
            None if source_valid else "SOURCE_MISMATCH",
            (source_id, bundle_id),
        ),
        _finding(
            f"{profile}.bundle_consistency",
            "pass" if bundle_valid else "fail",
            None if bundle_valid else "BUNDLE_MISMATCH",
            (bundle_id,),
        ),
        _finding(
            f"{profile}.receipt_binding",
            (
                "indeterminate"
                if receipt_binding_valid is None
                else "pass"
                if receipt_binding_valid
                else "fail"
            ),
            (
                "RECEIPT_NOT_SUPPLIED"
                if receipt_binding_valid is None
                else None
                if receipt_binding_valid
                else "RECEIPT_OR_BINDING_MISMATCH"
            ),
            (
                (bundle_id, receipt_id)
                if receipt is not None
                else ()
            ),
        ),
    ]

    intended_subject = cast(
        Mapping[str, object],
        intent["subject"],
    )

    subject_match = (
        intended_subject.get("kind") == subject["kind"]
        and intended_subject.get("id") == subject["id"]
    )

    if not subject_match:
        findings.append(
            _finding(
                "intent.subject",
                "fail",
                "SUBJECT_MISMATCH",
                (source_id, bundle_id),
            )
        )
    elif source_valid and bundle_valid:
        findings.append(
            _finding(
                "intent.subject",
                "pass",
                None,
                (source_id, bundle_id),
            )
        )
    else:
        findings.append(
            _finding(
                "intent.subject",
                "indeterminate",
                "SOURCE_BINDING_NOT_ESTABLISHED",
                (source_id, bundle_id),
            )
        )

    if "hedera_network" in intended_subject:
        expected_network = intended_subject["hedera_network"]
        claimed_network = (
            None
            if receipt is None
            else receipt.hedera_network
        )

        if claimed_network is None:
            findings.append(
                _finding(
                    "intent.declared_network",
                    "indeterminate",
                    "NETWORK_EVIDENCE_UNAVAILABLE",
                    (receipt_id,) if receipt is not None else (),
                )
            )
        elif claimed_network != expected_network:
            findings.append(
                _finding(
                    "intent.declared_network",
                    "fail",
                    "NETWORK_MISMATCH",
                    (receipt_id,),
                )
            )
        elif not receipt_binding_valid:
            findings.append(
                _finding(
                    "intent.declared_network",
                    "indeterminate",
                    "RECEIPT_BINDING_NOT_ESTABLISHED",
                    (receipt_id,),
                )
            )
        else:
            findings.append(
                _finding(
                    "intent.declared_network",
                    "pass",
                    None,
                    (receipt_id,),
                )
            )

    for expectation in intent["expected"]:
        findings.append(
            _compare_expected(
                cast(Mapping[str, object], expectation),
                profile=profile,
                bundle=bundle,
                source_root=source_root,
                source_count=source_count,
                source_valid=source_valid,
                bundle_valid=bundle_valid,
                observation_ids=(source_id, bundle_id),
            )
        )

    return VerificationReport(
        intent=intent,
        findings=tuple(findings),
        observations=tuple(observations),
    )


async def verify_dataset_v1_with_intent(
    *,
    bundle: object,
    files: list[SourceV1File],
    intent: object,
    receipt: object = _MISSING,
    limits: SourceV1Limits | None = None,
) -> VerificationReport:
    _checked_intent(intent)

    if receipt is _MISSING:
        source = await verify_dataset_v1_sources(
            bundle=bundle,
            files=files,
            limits=limits,
        )
    else:
        source = await verify_dataset_v1_sources(
            bundle=bundle,
            files=files,
            receipt=receipt,
            limits=limits,
        )

    bundle_result = verify_dataset_v1_bundle(bundle)

    receipt_result = (
        None
        if receipt is _MISSING
        else verify_dataset_v1_receipt(receipt)
    )

    source_valid = not any(
        not mismatch.field.startswith("bundle.")
        and not mismatch.field.startswith("receipt.")
        and not mismatch.field.startswith("binding.")
        and mismatch.field != "sources.receipt_merkle_root"
        for mismatch in source.mismatches
    )

    receipt_binding_valid: bool | None

    if receipt_result is None:
        receipt_binding_valid = None
    else:
        receipt_binding_valid = (
            receipt_result.ok
            and bundle_result.ok
            and not any(
                mismatch.field.startswith("binding.")
                or mismatch.field == "sources.receipt_merkle_root"
                for mismatch in source.mismatches
            )
        )

    actual = bundle_result.computed

    subject: VerificationSubject = {
        "kind": "dataset",
        "id": actual.dataset_key,
    }

    if receipt_result is not None:
        network = receipt_result.computed.hedera_network

        if network in ("mainnet", "testnet"):
            subject["hedera_network"] = cast(
                HederaNetwork,
                network,
            )

    return _report(
        intent,
        profile="dataset",
        subject=subject,
        bundle=actual,
        receipt=(
            None
            if receipt_result is None
            else receipt_result.computed
        ),
        source_root=source.computed.source_merkle_root,
        source_count=source.computed.source_file_count,
        source_bytes=source.computed.source_total_bytes,
        source_valid=source_valid,
        bundle_valid=bundle_result.ok,
        receipt_binding_valid=receipt_binding_valid,
    )


async def verify_ingest_v1_with_intent(
    *,
    bundle: object,
    material: object,
    intent: object,
    receipt: object = _MISSING,
    limits: SourceV1Limits | None = None,
) -> VerificationReport:
    _checked_intent(intent)

    if receipt is _MISSING:
        source = await verify_ingest_v1_sources(
            bundle=bundle,
            material=material,
            limits=limits,
        )
    else:
        source = await verify_ingest_v1_sources(
            bundle=bundle,
            material=material,
            receipt=receipt,
            limits=limits,
        )

    bundle_result = verify_ingest_v1_bundle(bundle)

    pair_result = (
        None
        if receipt is _MISSING
        else verify_ingest_v1_pair(
            bundle=bundle,
            receipt=receipt,
        )
    )

    receipt_value = (
        None
        if pair_result is None
        else pair_result.computed.receipt
    )

    if receipt is _MISSING:
        source_mismatches = source.mismatches[
            len(bundle_result.mismatches) :
        ]
    else:
        source_mismatches = tuple(
            mismatch
            for mismatch in source.mismatches
            if not mismatch.field.startswith("bundle.")
            and not mismatch.field.startswith("receipt.")
            and not mismatch.field.startswith("binding.")
            and mismatch.field != "sources.receipt_merkle_root"
        )

    source_valid = not source_mismatches

    receipt_binding_valid = (
        None
        if pair_result is None
        else (
            pair_result.ok
            and not any(
                mismatch.field == "sources.receipt_merkle_root"
                for mismatch in source.mismatches
            )
        )
    )

    actual = bundle_result.computed

    subject: VerificationSubject = {
        "kind": "ingest",
        "id": actual.object_key,
    }

    if receipt_value is not None:
        network = receipt_value.hedera_network

        if network in ("mainnet", "testnet"):
            subject["hedera_network"] = network

    return _report(
        intent,
        profile="ingest",
        subject=subject,
        bundle=actual,
        receipt=receipt_value,
        source_root=source.computed.source_merkle_root,
        source_count=source.computed.source_item_count,
        source_bytes=source.computed.source_total_bytes,
        source_valid=source_valid,
        bundle_valid=bundle_result.ok,
        receipt_binding_valid=receipt_binding_valid,
    )