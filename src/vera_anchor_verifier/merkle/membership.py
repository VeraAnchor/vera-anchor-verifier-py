"""Merkle membership verification for supported verifier tree contracts."""

from collections.abc import Mapping
from dataclasses import dataclass
from hashlib import sha3_512 as _sha3_512
from typing import Literal, TypedDict, TypeGuard, cast

from ..crypto.sha3 import normalize_sha3_512_digest

MAX_MERKLE_PROOF_STEPS = 64
_MAX_SAFE_INTEGER = (1 << 53) - 1


class MerkleProofStep(TypedDict):
    position: Literal["left", "right"]
    hash: str


class ExpectedMerkleRoot(TypedDict):
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


class MerkleMembershipProof(TypedDict):
    leaf_hash: str
    leaf_index: int
    path: list[MerkleProofStep]


class MerkleMembershipInput(TypedDict):
    expected: ExpectedMerkleRoot
    proof: MerkleMembershipProof


@dataclass(frozen=True, slots=True)
class MerkleMembershipResult:
    outcome: Literal["pass", "fail", "unsupported"]
    reason_code: str | None
    expected_root: str
    computed_root: str | None


def _is_safe_integer(value: object) -> TypeGuard[int]:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 0 <= value <= _MAX_SAFE_INTEGER
    )


def _sha3(*parts: bytes) -> str:
    digest = _sha3_512()
    for part in parts:
        digest.update(part)
    return digest.hexdigest()


def _leaf_node(digest: str, is_v2: bool) -> str:
    return _sha3(b"\x00", bytes.fromhex(digest)) if is_v2 else digest


def _parent_node(left: str, right: str, is_v2: bool) -> str:
    if is_v2:
        return _sha3(b"\x01", bytes.fromhex(left), bytes.fromhex(right))
    pair = f'{{"left":"{left}","right":"{right}"}}'.encode()
    return _sha3(pair)


def _parse_proof(
    value: object, count: int
) -> tuple[str, int, tuple[MerkleProofStep, ...]]:
    if not isinstance(value, Mapping):
        raise TypeError("Merkle proof must be an object")
    leaf = normalize_sha3_512_digest(value.get("leaf_hash"))
    index = value.get("leaf_index")
    if not _is_safe_integer(index) or index >= count:
        raise TypeError("Merkle leaf_index must be within the expected leaf_count")
    path = value.get("path")
    if not isinstance(path, list) or len(path) > MAX_MERKLE_PROOF_STEPS:
        raise TypeError("Merkle path must be a bounded array")

    width = count
    depth = 0
    while width > 1:
        width = (width + 1) // 2
        depth += 1
    if len(path) != depth:
        raise TypeError("Merkle path depth does not match expected leaf_count")

    normalized: list[MerkleProofStep] = []
    for i, step in enumerate(path):
        if not isinstance(step, Mapping):
            raise TypeError(f"Merkle path step {i} must be an object")
        if any(key not in {"position", "hash"} for key in step):
            raise TypeError(f"Merkle path step {i} contains unexpected fields")
        position = step.get("position")
        if position not in ("left", "right"):
            raise TypeError(f"Merkle path step {i} has invalid position")
        normalized.append(
            MerkleProofStep(
                position=cast(Literal["left", "right"], position),
                hash=normalize_sha3_512_digest(step.get("hash")),
            )
        )
    return leaf, index, tuple(normalized)


def verify_merkle_membership(input: object) -> MerkleMembershipResult:
    expected = input.get("expected") if isinstance(input, Mapping) else None
    if not isinstance(expected, Mapping) or expected.get("kind") != "merkle-root":
        raise TypeError("Expected a Merkle root commitment")

    expected_root = normalize_sha3_512_digest(expected.get("root_hash"))
    count = expected.get("leaf_count")
    if not _is_safe_integer(count) or count < 1:
        raise TypeError("Expected Merkle leaf_count must be a positive safe integer")

    tree_alg = expected.get("tree_alg")
    if tree_alg not in ("binary-sorted", "binary-sorted-v2"):
        return MerkleMembershipResult(
            outcome="unsupported",
            reason_code="MERKLE_ALGORITHM_UNSUPPORTED",
            expected_root=expected_root,
            computed_root=None,
        )

    is_v2 = tree_alg == "binary-sorted-v2"
    proof = input.get("proof") if isinstance(input, Mapping) else None
    leaf, index, path = _parse_proof(proof, count)
    current = _leaf_node(leaf, is_v2)
    width = count
    position = index

    for sibling in path:
        is_right = position % 2 == 1
        if sibling["position"] != ("left" if is_right else "right"):
            return MerkleMembershipResult(
                outcome="fail",
                reason_code="MERKLE_PATH_POSITION_MISMATCH",
                expected_root=expected_root,
                computed_root=None,
            )
        if not is_right and position + 1 == width and sibling["hash"] != current:
            return MerkleMembershipResult(
                outcome="fail",
                reason_code="MERKLE_ODD_SIBLING_MISMATCH",
                expected_root=expected_root,
                computed_root=None,
            )
        left = sibling["hash"] if is_right else current
        right = current if is_right else sibling["hash"]
        current = _parent_node(left, right, is_v2)
        position //= 2
        width = (width + 1) // 2

    matches = current == expected_root
    return MerkleMembershipResult(
        outcome="pass" if matches else "fail",
        reason_code=None if matches else "MERKLE_ROOT_MISMATCH",
        expected_root=expected_root,
        computed_root=current,
    )