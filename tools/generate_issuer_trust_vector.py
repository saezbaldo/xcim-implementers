#!/usr/bin/env python3
"""Generate the XCIM 0.1 registry-to-issuer trust-chain vector."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from generate_valid_receipt_vector import ROOT, b64url, canonicalize


OUTPUT = ROOT / "test-vectors" / "issuer-trust-chain.json"


def sign(payload: dict[str, Any], typ: str, kid: str, seed: bytes) -> tuple[dict[str, str], str]:
    protected = {"alg": "EdDSA", "kid": kid, "typ": typ}
    protected_segment = b64url(canonicalize(protected))
    payload_segment = b64url(canonicalize(payload))
    signing_input = f"{protected_segment}.{payload_segment}".encode("ascii")
    key = Ed25519PrivateKey.from_private_bytes(seed)
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return {
        "payload": payload_segment,
        "protected": protected_segment,
        "signature": b64url(key.sign(signing_input)),
    }, b64url(public)


def build_vector() -> dict[str, Any]:
    issuer_key_commitment = b64url(bytes([0x71]) * 32)
    accreditation = {
        "accreditation_epoch": 1,
        "accreditation_id": "urn:xcim:accreditation:emabled-01",
        "assurance_level": "organization_and_controllers_reviewed",
        "issuer_id": "urn:xcim:issuer:emabled.com",
        "issuer_key_commitments": [issuer_key_commitment],
        "object_type": "issuer_accreditation",
        "policy_version": "xcim-issuer-policy-0.1",
        "previous_entry_commitment": None,
        "registry": "https://registry.xcim.net",
        "review_evidence_commitment": b64url(bytes([0x72]) * 32),
        "reviewed_at": "2026-08-05T14:00:00Z",
        "status": "active",
        "valid_from": "2026-08-05T14:00:00Z",
        "valid_until": "2027-08-05T14:00:00Z",
        "xcim_version": "0.1",
    }
    metadata = {
        "accreditation_reference": {
            "accreditation_epoch": 1,
            "accreditation_id": "urn:xcim:accreditation:emabled-01",
            "entry_uri": "https://registry.xcim.net/v1/issuers/emabled.com/accreditations/1",
            "registry": "https://registry.xcim.net",
        },
        "anchor_networks": [{"contract": "0x1111111111111111111111111111111111111111", "network": "eip155:137"}],
        "batch_mirrors": ["https://mirror.emabled.com/"],
        "consent_endpoint": "https://consent.emabled.com/authorize",
        "issued_at": "2026-08-05T14:01:00Z",
        "issuer": "https://issuer.emabled.com",
        "issuer_id": "urn:xcim:issuer:emabled.com",
        "issuance_profiles_supported": ["oidc_hosted_consent"],
        "jwks_uri": "https://issuer.emabled.com/.well-known/xcim-keys.json",
        "metadata_epoch": 1,
        "object_type": "issuer_metadata",
        "policy_uri": "https://issuer.emabled.com/issuance-policy",
        "revocation_endpoint": "https://revoke.emabled.com/",
        "security_contact": "mailto:security@emabled.com",
        "status_endpoint": "https://issuer.emabled.com/v1/xcim/status",
        "supported_identity_assurance": ["oidc_provider_authenticated"],
        "transparency_log": "https://log.emabled.com/",
        "valid_from": "2026-08-05T14:01:00Z",
        "valid_until": "2027-08-05T14:00:00Z",
        "xcim_version": "0.1",
        "xcim_versions": ["0.1"],
    }
    accreditation_jws, registry_public = sign(accreditation, "application/xcim-issuer-accreditation+jcs", "xcim-registry-test-01", bytes(range(32, 64)))
    metadata_jws, issuer_public = sign(metadata, "application/xcim-issuer-metadata+jcs", "emabled-issuer-test-01", bytes(range(64, 96)))
    return {
        "accreditation": accreditation,
        "accreditation_jws": accreditation_jws,
        "expected_result": "XCIM_PASS_ANCHOR_PENDING",
        "issuer_metadata": metadata,
        "issuer_metadata_jws": metadata_jws,
        "issuer_public_key_raw_base64url": issuer_public,
        "registry_public_key_raw_base64url": registry_public,
        "vector_id": "xcim-0.1-issuer-trust-chain-01",
    }


def main() -> None:
    OUTPUT.write_text(json.dumps(build_vector(), ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(OUTPUT)


if __name__ == "__main__":
    main()
