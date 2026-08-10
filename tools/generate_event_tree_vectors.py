#!/usr/bin/env python3
"""Generate deterministic XCIM 0.1 cumulative event-tree vectors."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from generate_valid_receipt_vector import ROOT, b64url, build_vector as build_receipt_vector, canonicalize


OUTPUT = ROOT / "test-vectors" / "event-tree.json"
EMPTY_PREFIX = b"XCIM-EVENT-EMPTY-0.1\0"
LEAF_PREFIX = b"XCIM-EVENT-LEAF-0.1\0"
NODE_PREFIX = b"XCIM-MERKLE-NODE-0.1\0"


def digest(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def leaf_hash(event: dict[str, Any]) -> bytes:
    return digest(LEAF_PREFIX + canonicalize(event))


def node_hash(left: bytes, right: bytes) -> bytes:
    return digest(NODE_PREFIX + left + right)


def split(size: int) -> int:
    return 1 << ((size - 1).bit_length() - 1)


def root(leaves: list[bytes]) -> bytes:
    if not leaves:
        return digest(EMPTY_PREFIX)
    if len(leaves) == 1:
        return leaves[0]
    k = split(len(leaves))
    return node_hash(root(leaves[:k]), root(leaves[k:]))


def append_frontier(frontier: list[bytes | None], leaf: bytes) -> None:
    height = 0
    carry = leaf
    while height < len(frontier) and frontier[height] is not None:
        carry = node_hash(frontier[height], carry)
        frontier[height] = None
        height += 1
    if height == len(frontier):
        frontier.append(carry)
    else:
        frontier[height] = carry


def frontier_root(frontier: list[bytes | None]) -> bytes:
    accumulator = None
    for subtree in reversed(frontier):
        if subtree is not None:
            accumulator = subtree if accumulator is None else node_hash(accumulator, subtree)
    return digest(EMPTY_PREFIX) if accumulator is None else accumulator


def inclusion_path(leaves: list[bytes], index: int) -> list[bytes]:
    if not 0 <= index < len(leaves):
        raise IndexError(index)
    if len(leaves) == 1:
        return []
    k = split(len(leaves))
    if index < k:
        return inclusion_path(leaves[:k], index) + [root(leaves[k:])]
    return inclusion_path(leaves[k:], index - k) + [root(leaves[:k])]


def consistency_subproof(leaves: list[bytes], old_size: int, complete: bool) -> list[bytes]:
    size = len(leaves)
    if old_size == size:
        return [] if complete else [root(leaves)]
    k = split(size)
    if old_size <= k:
        return consistency_subproof(leaves[:k], old_size, complete) + [root(leaves[k:])]
    return consistency_subproof(leaves[k:], old_size - k, False) + [root(leaves[:k])]


def consistency_path(leaves: list[bytes], old_size: int) -> list[bytes]:
    if not 0 <= old_size <= len(leaves):
        raise ValueError(old_size)
    if old_size in (0, len(leaves)):
        return []
    return consistency_subproof(leaves, old_size, True)


def event(sequence: int) -> dict[str, Any]:
    types = ["protocol_genesis", "issuer_key_registered", "app_registered", "app_key_registered",
             "oauth_binding_created", "domain_epoch_started", "manifest_published", "receipt_issued",
             "permission_revoked"]
    object_commitment = b64url(bytes([sequence]) * 32)
    if sequence == 8:
        object_commitment = b64url(digest(b"XCIM-RECEIPT-0.1\0" + canonicalize(build_receipt_vector()["payload"])))
    return {
        "created_at": f"2026-08-05T12:{sequence - 1:02d}:00Z",
        "event_id": f"urn:xcim:event:test-{sequence:02d}",
        "event_type": types[sequence - 1],
        "issuer_id": "urn:xcim:issuer:emabled.com",
        "object_commitment": object_commitment,
        "object_type": "transparency_event",
        "sequence_number": sequence,
        "xcim_version": "0.1",
    }


def build_vector() -> dict[str, Any]:
    events = [event(i) for i in range(1, 10)]
    leaves = [leaf_hash(item) for item in events]
    sizes = [0, 1, 2, 3, 4, 5, 7, 8, 9]
    inclusion_cases = [(3, 0), (3, 1), (3, 2), (5, 2), (9, 0), (9, 4), (9, 7), (9, 8)]
    consistency_cases = [(0, 1), (1, 2), (2, 3), (3, 4), (4, 5), (5, 8), (7, 8), (8, 9)]
    frontier: list[bytes | None] = []
    incremental = [{"frontier": [], "root": b64url(frontier_root(frontier)), "tree_size": 0}]
    for size, leaf in enumerate(leaves, 1):
        append_frontier(frontier, leaf)
        incremental.append({
            "frontier": [None if item is None else b64url(item) for item in frontier],
            "root": b64url(frontier_root(frontier)),
            "tree_size": size,
        })

    return {
        "consistency_proofs": [
            {
                "new_root": b64url(root(leaves[:new])),
                "new_tree_size": new,
                "old_root": b64url(root(leaves[:old])),
                "old_tree_size": old,
                "path": [b64url(item) for item in consistency_path(leaves[:new], old)],
            }
            for old, new in consistency_cases
        ],
        "description": "XCIM 0.1 RFC6962-shaped cumulative event tree using XCIM domain separators.",
        "events": events,
        "inclusion_proofs": [
            {
                "batch_sequence": size,
                "event_root": b64url(root(leaves[:size])),
                "leaf_index": index,
                "path": [b64url(item) for item in inclusion_path(leaves[:size], index)],
                "tree_size": size,
            }
            for size, index in inclusion_cases
        ],
        "incremental_roots": incremental,
        "leaf_hashes": [b64url(item) for item in leaves],
        "negative_tests": [
            {"base_inclusion_case": 0, "mutation": "flip_first_sibling_bit", "expected": False},
            {"base_inclusion_case": 0, "mutation": "increment_tree_size", "expected": False},
            {"base_inclusion_case": 0, "mutation": "leaf_index_out_of_range", "expected": False},
            {"base_consistency_case": 4, "mutation": "replace_old_root", "expected": False},
        ],
        "roots": [{"root": b64url(root(leaves[:size])), "tree_size": size} for size in sizes],
        "vector_id": "xcim-0.1-event-tree-01",
    }


def main() -> None:
    vector = build_vector()
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(vector, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(OUTPUT)


if __name__ == "__main__":
    main()
