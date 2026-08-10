#!/usr/bin/env python3
"""Generate the deterministic XCIM 0.1 D-034 permission-revocation vector.

The embedded private seed is public test material and MUST NOT be used outside
protocol fixtures.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path
from typing import Any

import jsonschema
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIR = ROOT / "schemas" / "xcim" / "0.1"
DEFAULT_OUTPUT = ROOT / "test-vectors" / "permission-revocation-jws.json"
DOMAIN_SEPARATOR = b"XCIM-PERMISSION-REVOCATION-0.1\0"


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def canonicalize(value: Any) -> bytes:
    def validate(node: Any) -> None:
        if isinstance(node, float):
            raise ValueError("Floating-point values are not allowed in this vector profile")
        if isinstance(node, int) and not isinstance(node, bool) and abs(node) > 9_007_199_254_740_991:
            raise ValueError("Integer exceeds interoperable exact range")
        if isinstance(node, dict):
            for key, child in node.items():
                if not isinstance(key, str):
                    raise ValueError("JSON object keys must be strings")
                validate(child)
        elif isinstance(node, list):
            for child in node:
                validate(child)

    validate(value)
    return json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


def build_vector() -> dict[str, Any]:
    protected_header = {
        "alg": "EdDSA",
        "kid": "emabled-revocation-test-ed25519-01",
        "typ": "application/xcim-permission-revocation+jcs",
    }
    payload = {
        "effective_at": "2026-08-06T15:00:00.000000Z",
        "issuer": "https://id.emabled.com/",
        "method": "vendor_preference_center",
        "object_type": "permission_revocation",
        "permission_id": "urn:xcim:permission:test-permission-01",
        "purpose_id": "marketing.newsletter",
        "reason_code": "recipient_unsubscribe",
        "receipt_id": "urn:xcim:receipt:test-receipt-01",
        "requested_at": "2026-08-06T15:00:00.000000Z",
        "revocation_id": "xrv_3M3EyT9cSUlyPSUL-xfhKQJq3oTI9lDlvLXjj1tKMtg",
        "scope": "permission",
        "status_epoch": 2,
        "xcim_version": "0.1",
    }
    jsonschema.Draft202012Validator(
        json.loads((SCHEMA_DIR / "permission-revocation.schema.json").read_text(encoding="utf-8")),
        format_checker=jsonschema.FormatChecker(),
    ).validate(payload)

    protected_bytes = canonicalize(protected_header)
    payload_bytes = canonicalize(payload)
    protected_segment = b64url(protected_bytes)
    payload_segment = b64url(payload_bytes)
    signing_input = f"{protected_segment}.{payload_segment}".encode("ascii")
    commitment = hashlib.sha256(DOMAIN_SEPARATOR + payload_bytes).digest()

    private_seed = bytes(range(32, 64))
    private_key = Ed25519PrivateKey.from_private_bytes(private_seed)
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    signature = private_key.sign(signing_input)
    private_key.public_key().verify(signature, signing_input)
    envelope = {"payload": payload_segment, "protected": protected_segment, "signature": b64url(signature)}
    jsonschema.Draft202012Validator(
        json.loads((SCHEMA_DIR / "jws-envelope.schema.json").read_text(encoding="utf-8"))
    ).validate(envelope)

    return {
        "commitment_base64url": b64url(commitment),
        "description": "Valid XCIM 0.1 D-034 permission revocation using JWS Flattened JSON Serialization.",
        "envelope": envelope,
        "private_seed_hex_TEST_ONLY": private_seed.hex(),
        "protected_header": protected_header,
        "protected_jcs_utf8_hex": protected_bytes.hex(),
        "public_key_raw_base64url": b64url(public_key),
        "payload": payload,
        "payload_jcs_utf8_hex": payload_bytes.hex(),
        "signing_input_ascii": signing_input.decode("ascii"),
        "vector_id": "xcim-0.1-permission-revocation-jws-01",
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(build_vector(), ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(args.output)


if __name__ == "__main__":
    main()
