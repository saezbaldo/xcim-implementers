#!/usr/bin/env python3
"""Generate a coherent XCIM 0.1 full proof-bundle vector."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from generate_state_tree_vectors import make_proof, state_key
from generate_valid_receipt_vector import ROOT, b64url, build_vector as build_receipt, canonicalize


OUTPUT = ROOT / "test-vectors" / "proof-bundle.json"


def digest(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def sign(payload: dict[str, Any], typ: str) -> dict[str, str]:
    protected = {"alg": "EdDSA", "kid": "emabled-test-ed25519-01", "typ": typ}
    protected_segment = b64url(canonicalize(protected))
    payload_segment = b64url(canonicalize(payload))
    signing_input = f"{protected_segment}.{payload_segment}".encode("ascii")
    return {"protected": protected_segment, "payload": payload_segment, "signature": b64url(Ed25519PrivateKey.from_private_bytes(bytes(range(32))).sign(signing_input))}


def build_vector() -> dict[str, Any]:
    receipt_vector = build_receipt()
    event_vector = json.loads((ROOT / "test-vectors" / "event-tree.json").read_text(encoding="utf-8"))
    receipt = receipt_vector["payload"]
    receipt_commitment = b64url(digest(b"XCIM-RECEIPT-0.1\0" + canonicalize(receipt)))
    receipt_event = event_vector["events"][7]
    inclusion = next(item for item in event_vector["inclusion_proofs"] if item["tree_size"] == 9 and item["leaf_index"] == 7)

    permission_id = receipt["permissions"][0]["permission_id"]
    status_value = {
        "effective_at": "2026-08-05T12:08:00Z",
        "latest_event_commitment": receipt_commitment,
        "object_id": permission_id,
        "status": "active",
        "status_epoch": 1,
    }
    key = state_key("permission", permission_id)
    status_proof = make_proof([(key, status_value)], key, status_value, 9)
    protocol_status_proof = dict(status_proof)
    protocol_status_proof.pop("state_value_jcs_base64url")
    protocol_status_proof["anchor_reference"] = "urn:xcim:test-anchor:9"

    roots = {item["tree_size"]: item["root"] for item in event_vector["roots"]}
    manifest = {
        "batch_event_count": 1,
        "batch_sequence": 9,
        "created_at": "2026-08-05T12:09:00Z",
        "event_root": roots[9],
        "first_sequence": 9,
        "issuer_id": "urn:xcim:issuer:emabled.com",
        "last_sequence": 9,
        "object_type": "batch_manifest",
        "previous_anchor_hash": b64url(bytes([0x81]) * 32),
        "previous_event_root": roots[8],
        "previous_tree_size": 8,
        "proof_bundle_set_hash": b64url(bytes([0x82]) * 32),
        "state_root": protocol_status_proof["state_root"],
        "tree_size": 9,
        "xcim_version": "0.1",
    }
    manifest_hash = digest(b"XCIM-BATCH-MANIFEST-0.1\0" + canonicalize(manifest))
    anchor = {
        "batch_manifest_hash": b64url(manifest_hash),
        "batch_sequence": 9,
        "block_hash": "0x" + "93" * 32,
        "block_number": 12345678,
        "confirmations": 128,
        "contract": "0x1111111111111111111111111111111111111111",
        "network": "eip155:137",
        "status": "finalized",
        "transaction_hash": "0x" + "92" * 32,
    }
    bundle = {
        "anchors": [anchor],
        "batch_manifests": [{"batch_sequence": 9, "manifest": sign(manifest, "application/xcim-batch-manifest+jcs")}],
        "bundle_id": "urn:xcim:proof-bundle:test-01",
        "current_status_proof": protocol_status_proof,
        "event_inclusion_proof": inclusion,
        "generated_at": "2026-08-05T12:10:00Z",
        "object_type": "xcim_proof_bundle",
        "receipt": receipt_vector["envelope"],
        "receipt_commitment": receipt_commitment,
        "receipt_event": receipt_event,
        "xcim_version": "0.1",
    }
    return {
        "batch_manifest_hash_evm_hex": "0x" + manifest_hash.hex(),
        "bundle": bundle,
        "expected_result": "XCIM_PASS",
        "issuer_public_key_raw_base64url": receipt_vector["public_key_raw_base64url"],
        "vector_id": "xcim-0.1-full-proof-bundle-01",
    }


def main() -> None:
    OUTPUT.write_text(json.dumps(build_vector(), ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(OUTPUT)


if __name__ == "__main__":
    main()
