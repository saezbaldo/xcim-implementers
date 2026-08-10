#!/usr/bin/env python3
"""Generate the deterministic XCIM 0.1 valid-receipt JWS test vector.

The embedded private seed is public test material and MUST NOT be used outside
protocol fixtures.
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
DEFAULT_OUTPUT = ROOT / "test-vectors" / "valid-receipt-jws.json"


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def canonicalize(value: Any) -> bytes:
    """Canonicalize the fixture's RFC-8785-compatible JSON subset.

    Protocol fixtures initially prohibit floats and integers outside the
    interoperable IEEE-754 exact range. The production canonicalizer must
    implement all RFC 8785 requirements and pass the published vectors.
    """

    def validate(node: Any) -> None:
        if isinstance(node, float):
            raise ValueError("Floating-point values are not allowed in this vector profile")
        if isinstance(node, int) and not isinstance(node, bool):
            if abs(node) > 9_007_199_254_740_991:
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
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def hash_value(byte: int) -> str:
    return b64url(bytes([byte]) * 32)


def build_vector() -> dict[str, Any]:
    protected_header = {
        "alg": "EdDSA",
        "kid": "emabled-test-ed25519-01",
        "typ": "application/xcim-receipt+jcs",
    }
    payload = {
        "application": {
            "app_epoch": 1,
            "app_id": "urn:xcim:app:test-app-01",
            "app_key_id": "test-app-key-01",
            "client_id_commitment": hash_value(0x11),
            "oauth_binding_id": "xob_test_01",
            "provider_issuer": "https://accounts.google.com",
        },
        "declared_sender_domains": ["mail.example.com"],
        "expires_at": None,
        "identity_evidence": {
            "adapter_version": "google-oidc-0.1",
            "address_authority_class": "provider_authoritative",
            "authenticated_at": "2026-08-05T12:00:00Z",
            "comparison_rule_id": "google-case-insensitive-0.1",
            "evidence_type": "oidc_id_token",
            "nonce_commitment": hash_value(0x22),
            "oauth_client_id_commitment": hash_value(0x11),
            "provider_policy_version": "google-2026-08-01",
            "provider_subject_commitment": hash_value(0x33),
        },
        "issued_at": "2026-08-05T12:01:00Z",
        "issuance_profile": "oidc_hosted_consent",
        "issuer": "https://issuer.emabled.com",
        "issuer_independence": "independent",
        "not_before": "2026-08-05T12:01:00Z",
        "object_type": "xcim_receipt",
        "permissions": [
            {
                "authorization_kind": "explicit_consent",
                "decision": "active",
                "expires_at": None,
                "granted_at": "2026-08-05T12:00:59Z",
                "permission_id": "urn:xcim:permission:test-permission-01",
                "purpose_id": "marketing.newsletter",
                "required": False,
            }
        ],
        "presentation": {
            "accepted_at": "2026-08-05T12:00:59Z",
            "locale": "en",
            "manifest_hash": hash_value(0x44),
            "manifest_id": "urn:xcim:manifest:test-manifest-01",
            "mode": "issuer_hosted_top_level",
            "origin": "https://consent.emabled.com",
            "rendering_template_version": "hosted-consent-v0.4",
        },
        "receipt_id": "urn:xcim:receipt:test-receipt-01",
        "recipient": {
            "identity_assurance": "oidc_provider_authenticated",
            "pairwise_id": hash_value(0x55),
        },
        "xcim_version": "0.1",
    }

    receipt_schema = json.loads((SCHEMA_DIR / "receipt.schema.json").read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(receipt_schema, format_checker=jsonschema.FormatChecker()).validate(payload)

    protected_bytes = canonicalize(protected_header)
    payload_bytes = canonicalize(payload)
    protected_segment = b64url(protected_bytes)
    payload_segment = b64url(payload_bytes)
    signing_input = f"{protected_segment}.{payload_segment}".encode("ascii")

    private_seed = bytes(range(32))
    private_key = Ed25519PrivateKey.from_private_bytes(private_seed)
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    signature = private_key.sign(signing_input)
    private_key.public_key().verify(signature, signing_input)

    envelope = {
        "payload": payload_segment,
        "protected": protected_segment,
        "signature": b64url(signature),
    }
    envelope_schema = json.loads((SCHEMA_DIR / "jws-envelope.schema.json").read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(envelope_schema).validate(envelope)

    return {
        "description": "Valid XCIM 0.1 independent Google/Gmail receipt using JWS Flattened JSON Serialization.",
        "envelope": envelope,
        "expected_result": "XCIM_PASS_ANCHOR_PENDING",
        "private_seed_hex_TEST_ONLY": private_seed.hex(),
        "protected_header": protected_header,
        "protected_jcs_utf8_hex": protected_bytes.hex(),
        "public_key_raw_base64url": b64url(public_key),
        "payload": payload,
        "payload_jcs_utf8_hex": payload_bytes.hex(),
        "signing_input_ascii": signing_input.decode("ascii"),
        "vector_id": "xcim-0.1-valid-receipt-jws-01",
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    vector = build_vector()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(vector, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(args.output)


if __name__ == "__main__":
    main()
