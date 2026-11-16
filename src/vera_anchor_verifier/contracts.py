"""Shared structural contracts for read-only verification."""

from dataclasses import dataclass
from typing import Literal, NotRequired, TypedDict

type HederaNetwork = Literal["mainnet", "testnet"]
type VerificationOutcome = Literal[
    "pass",
    "fail",
    "indeterminate",
    "unsupported",
    "skipped",
]
type EvidenceConsistency = Literal["consistent", "conflict", "incomplete"]

type VerificationSubjectKind = Literal[
    "artifact",
    "dataset",
    "ingest",
    "evidence_package",
    "merkle_anchor",
    "merkle_root",
    "merkle_leaf",
    "execution",
    "result",
]


class VerificationSubject(TypedDict):
    kind: VerificationSubjectKind
    id: str
    hedera_network: NotRequired[HederaNetwork]


class RawExpectedDigestCommitment(TypedDict):
    key: str
    kind: Literal["digest"]
    contract: Literal["raw-sha3-512", "core-canonical-json"]
    digest: str


class HfV1ExpectedDigestCommitment(TypedDict):
    key: str
    kind: Literal["digest"]
    contract: Literal["hf-contract-v1"]
    material: Literal["json", "utf8", "raw"]
    domain: str
    digest: str


class ExpectedMerkleRootCommitment(TypedDict):
    key: str
    kind: Literal["merkle-root"]
    tree_alg: Literal[
        "binary-sorted",
        "binary-sorted-v2",
        "hf-dataset-v1",
        "hf-ingest-v1",
    ]
    root_hash: str
    leaf_count: int


type ExpectedCommitment = (
    RawExpectedDigestCommitment
    | HfV1ExpectedDigestCommitment
    | ExpectedMerkleRootCommitment
)


class VerificationIntent(TypedDict):
    subject: VerificationSubject
    expected: list[ExpectedCommitment]


type VerificationFactValue = str | int | float | bool | None
type VerificationFactState = Literal[
    "available",
    "unavailable",
    "not_applicable",
]
type VerificationObservationSource = Literal[
    "provided_evidence",
    "public_record",
    "authorized_service",
    "hedera_mirror",
    "local_computation",
]


@dataclass(frozen=True, slots=True)
class VerificationFact:
    key: str
    state: VerificationFactState
    value: VerificationFactValue = None
    reason_code: str | None = None


@dataclass(frozen=True, slots=True)
class VerificationObservation:
    id: str
    subject: VerificationSubject
    source: VerificationObservationSource
    facts: tuple[VerificationFact, ...]
    resolver_id: str | None = None
    observed_at: str | None = None


@dataclass(frozen=True, slots=True)
class VerificationFinding:
    check_id: str
    outcome: VerificationOutcome
    reason_code: str | None
    observation_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class VerificationReport:
    intent: VerificationIntent
    findings: tuple[VerificationFinding, ...]
    observations: tuple[VerificationObservation, ...]