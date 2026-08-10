#!/usr/bin/env python3
"""Generate deterministic XCIM 0.1 sparse-Merkle state-tree vectors."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from generate_valid_receipt_vector import ROOT, b64url, canonicalize


OUTPUT = ROOT / "test-vectors" / "state-tree.json"
KEY_PREFIX = b"XCIM-STATE-KEY-0.1\0"
VALUE_PREFIX = b"XCIM-STATE-VALUE-0.1\0"
LEAF_PREFIX = b"XCIM-STATE-LEAF-0.1\0"
NODE_PREFIX = b"XCIM-STATE-NODE-0.1\0"
EMPTY_LEAF_PREFIX = b"XCIM-STATE-EMPTY-LEAF-0.1\0"


def digest(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return digest(NODE_PREFIX + left + right)


EMPTY = [b""] * 257
EMPTY[256] = digest(EMPTY_LEAF_PREFIX)
for depth in range(255, -1, -1):
    EMPTY[depth] = node_hash(EMPTY[depth + 1], EMPTY[depth + 1])


def state_key(object_type: str, object_id: str) -> bytes:
    return digest(KEY_PREFIX + object_type.encode() + b"\0" + object_id.encode())


def value_hash(value: dict[str, Any]) -> bytes:
    return digest(VALUE_PREFIX + canonicalize(value))


def leaf_hash(key: bytes, value: dict[str, Any]) -> bytes:
    return digest(LEAF_PREFIX + key + value_hash(value))


def bit(key: bytes, depth: int) -> int:
    return (key[depth // 8] >> (7 - depth % 8)) & 1


Entry = tuple[bytes, dict[str, Any]]


def subtree(entries: list[Entry], depth: int = 0) -> bytes:
    if not entries:
        return EMPTY[depth]
    if depth == 256:
        if len(entries) != 1:
            raise ValueError("Duplicate state key")
        return leaf_hash(*entries[0])
    left = [entry for entry in entries if bit(entry[0], depth) == 0]
    right = [entry for entry in entries if bit(entry[0], depth) == 1]
    return node_hash(subtree(left, depth + 1), subtree(right, depth + 1))


def make_proof(entries: list[Entry], key: bytes, value: dict[str, Any] | None, batch: int) -> dict[str, Any]:
    siblings: list[tuple[int, bytes]] = []
    current = entries
    for depth in range(256):
        left = [entry for entry in current if bit(entry[0], depth) == 0]
        right = [entry for entry in current if bit(entry[0], depth) == 1]
        sibling_entries = right if bit(key, depth) == 0 else left
        sibling = subtree(sibling_entries, depth + 1)
        if sibling != EMPTY[depth + 1]:
            siblings.append((depth, sibling))
        current = left if bit(key, depth) == 0 else right
    bitmap = bytearray(32)
    for depth, _ in siblings:
        bitmap[depth // 8] |= 0x80 >> (depth % 8)
    return {
        "anchor_reference": f"urn:xcim:test-anchor:{batch}",
        "batch_sequence": batch,
        "next_update": "2026-08-06T12:00:00Z",
        "non_empty_siblings": [b64url(item) for _, item in siblings],
        "presence": value is not None,
        "sibling_bitmap": b64url(bytes(bitmap)),
        "state_key": b64url(key),
        "state_root": b64url(subtree(entries)),
        "state_value": value,
        "state_value_jcs_base64url": None if value is None else b64url(canonicalize(value)),
        "this_update": "2026-08-05T12:00:00Z",
        "tree_depth": 256,
    }


def find_shared_prefix_ids() -> list[str]:
    buckets: dict[int, list[str]] = {}
    for number in range(1, 5000):
        object_id = f"urn:xcim:permission:test-{number:04d}"
        first_byte = state_key("permission", object_id)[0]
        buckets.setdefault(first_byte, []).append(object_id)
        if len(buckets[first_byte]) == 3:
            return buckets[first_byte]
    raise RuntimeError("Could not find deterministic shared-prefix keys")


def value(object_id: str, status: str, epoch: int, marker: int) -> dict[str, Any]:
    return {
        "effective_at": f"2026-08-05T12:{marker:02d}:00Z",
        "latest_event_commitment": b64url(bytes([marker]) * 32),
        "object_id": object_id,
        "status": status,
        "status_epoch": epoch,
    }


def build_vector() -> dict[str, Any]:
    ids = find_shared_prefix_ids()
    initial_values = [value(ids[i], "active", 1, i + 1) for i in range(3)]
    keys = [state_key("permission", object_id) for object_id in ids]
    one = [(keys[0], initial_values[0])]
    three = list(zip(keys, initial_values))
    revoked = value(ids[0], "revoked", 2, 4)
    updated = [(keys[0], revoked), *three[1:]]
    absent_id = "urn:xcim:permission:never-registered"
    absent_key = state_key("permission", absent_id)

    return {
        "description": "XCIM 0.1 256-level sparse Merkle state tree with MSB-first compressed-proof bitmap.",
        "empty_hashes": [b64url(item) for item in EMPTY],
        "keys": [{"object_id": ids[i], "state_key": b64url(keys[i])} for i in range(3)],
        "negative_tests": [
            {"base_proof": "presence_after_insert", "mutation": "bitmap_extra_bit", "expected": False},
            {"base_proof": "presence_after_insert", "mutation": "remove_sibling", "expected": False},
            {"base_proof": "presence_after_insert", "mutation": "alter_sibling", "expected": False},
            {"base_proof": "presence_after_insert", "mutation": "replace_state_key", "expected": False},
            {"base_proof": "presence_after_insert", "mutation": "noncanonical_state_value", "expected": False},
        ],
        "proofs": {
            "absence_empty": make_proof([], absent_key, None, 0),
            "absence_after_neighbor_insert": make_proof(three, absent_key, None, 2),
            "presence_after_insert": make_proof(three, keys[0], initial_values[0], 2),
            "presence_after_update": make_proof(updated, keys[0], revoked, 3),
        },
        "roots": {
            "empty": b64url(EMPTY[0]),
            "one_entry": b64url(subtree(one)),
            "three_entries": b64url(subtree(three)),
            "three_entries_rebuilt_from_zero": b64url(subtree(three)),
            "updated": b64url(subtree(updated)),
        },
        "vector_id": "xcim-0.1-state-tree-01",
    }


def main() -> None:
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(build_vector(), ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(OUTPUT)


if __name__ == "__main__":
    main()
