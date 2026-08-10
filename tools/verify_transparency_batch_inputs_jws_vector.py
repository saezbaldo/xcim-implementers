#!/usr/bin/env python3
"""Verify the candidate signed transparency-input vector independently."""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


ROOT = Path(__file__).resolve().parents[1]
VECTOR = ROOT / "test-vectors" / "transparency-batch-inputs-jws.json"
JWS_TYPE = "application/xcim-transparency-batch-inputs+jcs"


def decode(value: str) -> bytes:
    if not isinstance(value, str) or not value or "=" in value or any(
        char not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for char in value
    ):
        raise AssertionError("invalid unpadded base64url")
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def canonicalize(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


vector = json.loads(VECTOR.read_text(encoding="utf-8"))
envelope = vector["envelope"]
header_bytes = decode(envelope["protected"])
payload_bytes = decode(envelope["payload"])
header = json.loads(header_bytes)
payload = json.loads(payload_bytes)
assert header == vector["protected_header"] and canonicalize(header) == header_bytes
assert payload == vector["payload"] and canonicalize(payload) == payload_bytes
assert header["typ"] == JWS_TYPE and header["alg"] == "EdDSA"
public_key = decode(vector["public_key_raw_base64url"])
signature = decode(envelope["signature"])
assert len(public_key) == 32 and len(signature) == 64
Ed25519PublicKey.from_public_bytes(public_key).verify(
    signature, (envelope["protected"] + "." + envelope["payload"]).encode("ascii")
)
assert payload["object_type"] == "transparency_batch_inputs"
assert payload["issuer_id"] == "urn:xcim:issuer:emabled.com"
assert payload["batch_sequence"] == 7
print("Verified signed transparency-input vector independently in Python.")
