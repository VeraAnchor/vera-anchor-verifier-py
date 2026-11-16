import json
from hashlib import sha3_512

import pytest

from vera_anchor_verifier import MAX_MERKLE_PROOF_STEPS, verify_merkle_membership


def digest(data: bytes) -> str:
    return sha3_512(data).hexdigest()


def v1_parent(left: str, right: str) -> str:
    payload = json.dumps(
        {"left": left, "right": right},
        separators=(",", ":"),
    ).encode()
    return digest(payload)


def v2_leaf(value: str) -> str:
    return digest(b"\x00" + bytes.fromhex(value))


def v2_parent(left: str, right: str) -> str:
    return digest(b"\x01" + bytes.fromhex(left) + bytes.fromhex(right))


def membership(
    tree_alg: str,
    root_hash: str,
    leaf_count: int,
    leaf_hash: str,
    leaf_index: int,
    path: list[dict[str, str]],
) -> dict[str, object]:
    return {
        "expected": {
            "key": "root",
            "kind": "merkle-root",
            "tree_alg": tree_alg,
            "root_hash": root_hash,
            "leaf_count": leaf_count,
        },
        "proof": {
            "leaf_hash": leaf_hash,
            "leaf_index": leaf_index,
            "path": path,
        },
    }


def test_binary_sorted_membership_passes() -> None:
    left, right = digest(b"a"), digest(b"b")
    root = v1_parent(left, right)
    result = verify_merkle_membership(
        membership(
            "binary-sorted",
            root,
            2,
            left,
            0,
            [{"position": "right", "hash": right}],
        )
    )
    assert (result.outcome, result.reason_code, result.computed_root) == (
        "pass",
        None,
        root,
    )


def test_binary_sorted_v2_membership_passes() -> None:
    left, right = digest(b"a"), digest(b"b")
    left_node, right_node = v2_leaf(left), v2_leaf(right)
    root = v2_parent(left_node, right_node)
    result = verify_merkle_membership(
        membership(
            "binary-sorted-v2",
            root,
            2,
            left,
            0,
            [{"position": "right", "hash": right_node}],
        )
    )
    assert (result.outcome, result.reason_code, result.computed_root) == (
        "pass",
        None,
        root,
    )


def test_single_leaf_tree_passes_for_both_algorithms() -> None:
    leaf = digest(b"only")
    v1 = verify_merkle_membership(
        membership("binary-sorted", leaf, 1, leaf, 0, [])
    )
    v2_root = v2_leaf(leaf)
    v2 = verify_merkle_membership(
        membership("binary-sorted-v2", v2_root, 1, leaf, 0, [])
    )
    assert v1.outcome == "pass"
    assert v2.outcome == "pass"


def test_unsupported_algorithm_does_not_parse_proof() -> None:
    root = digest(b"root")
    result = verify_merkle_membership(
        {
            "expected": {
                "key": "root",
                "kind": "merkle-root",
                "tree_alg": "hf-dataset-v1",
                "root_hash": root,
                "leaf_count": 1,
            }
        }
    )
    assert (result.outcome, result.reason_code, result.computed_root) == (
        "unsupported",
        "MERKLE_ALGORITHM_UNSUPPORTED",
        None,
    )


def test_position_and_root_mismatches_are_distinct() -> None:
    left, right = digest(b"a"), digest(b"b")
    root = v1_parent(left, right)
    position = verify_merkle_membership(
        membership(
            "binary-sorted",
            root,
            2,
            left,
            0,
            [{"position": "left", "hash": right}],
        )
    )
    assert (position.reason_code, position.computed_root) == (
        "MERKLE_PATH_POSITION_MISMATCH",
        None,
    )

    wrong_root = digest(b"wrong")
    root_result = verify_merkle_membership(
        membership(
            "binary-sorted",
            wrong_root,
            2,
            left,
            0,
            [{"position": "right", "hash": right}],
        )
    )
    assert root_result.reason_code == "MERKLE_ROOT_MISMATCH"
    assert root_result.computed_root == root


def test_odd_leaf_requires_self_sibling() -> None:
    a, b, c = digest(b"a"), digest(b"b"), digest(b"c")
    ab = v1_parent(a, b)
    root = v1_parent(ab, v1_parent(c, c))
    passed = verify_merkle_membership(
        membership(
            "binary-sorted",
            root,
            3,
            c,
            2,
            [
                {"position": "right", "hash": c},
                {"position": "left", "hash": ab},
            ],
        )
    )
    assert passed.outcome == "pass"

    failed = verify_merkle_membership(
        membership(
            "binary-sorted",
            root,
            3,
            c,
            2,
            [
                {"position": "right", "hash": a},
                {"position": "left", "hash": ab},
            ],
        )
    )
    assert (failed.reason_code, failed.computed_root) == (
        "MERKLE_ODD_SIBLING_MISMATCH",
        None,
    )


def test_merkle_structure_validation_is_fail_closed() -> None:
    leaf = digest(b"a")
    invalid = [
        (
            {"expected": {"kind": "digest"}},
            "Expected a Merkle root commitment",
        ),
        (
            membership("binary-sorted", leaf, 0, leaf, 0, []),
            "positive safe integer",
        ),
        (
            membership("binary-sorted", leaf, 1, leaf, 1, []),
            "leaf_index must be within",
        ),
        (
            membership("binary-sorted", leaf, 2, leaf, 0, []),
            "path depth does not match",
        ),
        (
            membership(
                "binary-sorted",
                leaf,
                2,
                leaf,
                0,
                [{"position": "right", "hash": leaf, "extra": "x"}],
            ),
            "unexpected fields",
        ),
    ]
    for value, message in invalid:
        with pytest.raises(TypeError, match=message):
            verify_merkle_membership(value)


def test_merkle_rejects_unbounded_path_and_unsafe_integers() -> None:
    leaf = digest(b"a")
    oversized_path = [{"position": "right", "hash": leaf}] * (
        MAX_MERKLE_PROOF_STEPS + 1
    )
    with pytest.raises(TypeError, match="bounded array"):
        verify_merkle_membership(
            membership("binary-sorted", leaf, 2, leaf, 0, oversized_path)
        )

    for count in (True, 1 << 53):
        with pytest.raises(TypeError, match="positive safe integer"):
            verify_merkle_membership(
                membership("binary-sorted", leaf, count, leaf, 0, [])
            )