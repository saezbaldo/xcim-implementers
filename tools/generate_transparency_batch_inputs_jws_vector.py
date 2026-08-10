#!/usr/bin/env python3
"""Generate the deterministic candidate signed transparency-input handoff.

The embedded private seed is public test material and MUST NOT be used as a
trust root or signing credential outside protocol fixtures.
"""

from __future__ import annotations

import argparse
import base64
import json
from pathlib import Path
from typing import Any

import jsonschema
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIR = ROOT / "schemas" / "xcim" / "0.1"
DEFAULT_OUTPUT = ROOT / "test-vectors" / "transparency-batch-inputs-jws.json"
JWS_TYPE = "application/xcim-transparency-batch-inputs+jcs"
MEDIA_TYPE = "application/xcim-transparency-batch-inputs+jws+json"


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
        "kid": "xcim-hub-inputs-test-ed25519-01",
        "typ": JWS_TYPE,
    }
    payload = {
        "batch_sequence": 7,
        "consistency_proof_uri": "https://mirror.xcim.org/proofs/7.json",
        "issuer_id": "urn:xcim:issuer:emabled.com",
        "object_type": "transparency_batch_inputs",
        "previous_anchor_hash": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
        "proof_bundle_set_hash": "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI",
        "valid_until": "2026-08-09T16:00:00Z",
        "xcim_version": "0.1",
    }
    jsonschema.Draft202012Validator(
        json.loads((SCHEMA_DIR / "transparency-batch-inputs.schema.json").read_text(encoding="utf-8")),
        format_checker=jsonschema.FormatChecker(),
    ).validate(payload)

    protected_bytes = canonicalize(protected_header)
    payload_bytes = canonicalize(payload)
    protected_segment = b64url(protected_bytes)
    payload_segment = b64url(payload_bytes)
    signing_input = f"{protected_segment}.{payload_segment}".encode("ascii")
    private_seed = bytes(range(64, 96))
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
        "description": "Candidate signed XCIM 0.1 transparency-input handoff; test-only key, not a trust bootstrap.",
        "envelope": envelope,
        "media_type": MEDIA_TYPE,
        "private_seed_hex_TEST_ONLY": private_seed.hex(),
        "protected_header": protected_header,
        "protected_jcs_utf8_hex": protected_bytes.hex(),
        "public_key_raw_base64url": b64url(public_key),
        "payload": payload,
        "payload_jcs_utf8_hex": payload_bytes.hex(),
        "signing_input_ascii": signing_input.decode("ascii"),
        "vector_id": "xcim-0.1-transparency-batch-inputs-jws-01",
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
