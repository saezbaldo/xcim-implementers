#!/usr/bin/env python3
"""Generate deterministic negative XCIM 0.1 receipt JWS vectors."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from generate_valid_receipt_vector import ROOT, b64url, build_vector, canonicalize


OUTPUT_DIR = ROOT / "test-vectors" / "negative"
PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))


def envelope(protected: dict[str, Any], payload_bytes: bytes) -> dict[str, str]:
    protected_segment = b64url(canonicalize(protected))
    payload_segment = b64url(payload_bytes)
    signing_input = f"{protected_segment}.{payload_segment}".encode("ascii")
    return {
        "payload": payload_segment,
        "protected": protected_segment,
        "signature": b64url(PRIVATE_KEY.sign(signing_input)),
    }


def fixture(vector_id: str, description: str, env: dict[str, str], expected: str) -> dict[str, Any]:
    return {
        "description": description,
        "envelope": env,
        "expected_result": expected,
        "public_key_raw_base64url": build_vector()["public_key_raw_base64url"],
        "vector_id": vector_id,
    }


def build_vectors() -> list[dict[str, Any]]:
    valid = build_vector()
    protected = valid["protected_header"]
    payload = valid["payload"]

    bad_signature = copy.deepcopy(valid["envelope"])
    signature = bytearray(__import__("base64").urlsafe_b64decode(bad_signature["signature"] + "=="))
    signature[-1] ^= 1
    bad_signature["signature"] = b64url(bytes(signature))

    wrong_typ = copy.deepcopy(protected)
    wrong_typ["typ"] = "application/xcim-event+jcs"

    noncanonical_payload = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=False).encode("utf-8")

    inconsistent_payload = copy.deepcopy(payload)
    permission = inconsistent_payload["permissions"][0]
    permission["decision"] = "declined"
    # Intentionally retains granted_at, which violates the receipt schema.

    return [
        fixture(
            "xcim-0.1-invalid-receipt-bad-signature-01",
            "A one-bit mutation of an otherwise valid Ed25519 signature.",
            bad_signature,
            "XCIM_SIGNATURE_FAIL",
        ),
        fixture(
            "xcim-0.1-invalid-receipt-wrong-typ-01",
            "A correctly signed receipt whose protected typ identifies an event.",
            envelope(wrong_typ, canonicalize(payload)),
            "XCIM_MALFORMED",
        ),
        fixture(
            "xcim-0.1-invalid-receipt-noncanonical-payload-01",
            "A correctly signed, parseable receipt payload that is not JCS canonical.",
            envelope(protected, noncanonical_payload),
            "XCIM_MALFORMED",
        ),
        fixture(
            "xcim-0.1-invalid-receipt-declined-with-granted-at-01",
            "A correctly signed canonical receipt with a declined permission retaining granted_at.",
            envelope(protected, canonicalize(inconsistent_payload)),
            "XCIM_MALFORMED",
        ),
    ]


def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    for vector in build_vectors():
        path = OUTPUT_DIR / f'{vector["vector_id"]}.json'
        path.write_text(json.dumps(vector, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(path)


if __name__ == "__main__":
    main()
