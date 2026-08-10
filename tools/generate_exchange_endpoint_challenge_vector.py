#!/usr/bin/env python3
import base64
import hashlib
import json
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "test-vectors" / "exchange-endpoint-challenge.json"
REQUEST_TYPE = "application/xcim-exchange-challenge+jcs"
RESPONSE_TYPE = "application/xcim-exchange-challenge-response+jcs"
ISSUER_KID = "iss_emabled_01#exchange-1"
VENDOR_KID = "urn:xcim:app:deploytoagents-01#exchange-1"

def b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")

def canonical(value) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")

def sign(payload: dict, media_type: str, kid: str, key: Ed25519PrivateKey) -> dict:
    protected = b64(canonical({"alg": "EdDSA", "kid": kid, "typ": media_type}))
    payload_segment = b64(canonical(payload))
    signature = key.sign(f"{protected}.{payload_segment}".encode("ascii"))
    return {"payload": payload_segment, "protected": protected, "signature": b64(signature)}

issuer = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
vendor = Ed25519PrivateKey.from_private_bytes(bytes(range(32, 64)))
token = b64(bytes(range(64, 96)))
request = {
    "xcim_version": "0.1",
    "object_type": "exchange_endpoint_challenge",
    "challenge_id": "xec_deploytoagents_01",
    "endpoint_id": "oxe_deploytoagents_01",
    "application_id": "urn:xcim:app:deploytoagents-01",
    "application_epoch": 1,
    "endpoint_uri": "https://deploytoagents.com/xcim/exchange",
    "audience": "urn:xcim:app:deploytoagents-01",
    "token": token,
    "issued_at": "2026-08-05T15:00:00Z",
    "expires_at": "2026-08-05T15:05:00Z",
}
challenge_input = "\0".join((request["challenge_id"], request["endpoint_id"], request["endpoint_uri"], token)).encode()
response = {
    "xcim_version": "0.1",
    "object_type": "exchange_endpoint_challenge_response",
    "challenge_id": request["challenge_id"],
    "endpoint_id": request["endpoint_id"],
    "application_id": request["application_id"],
    "application_epoch": request["application_epoch"],
    "endpoint_uri": request["endpoint_uri"],
    "request_commitment": b64(hashlib.sha256(canonical(request)).digest()),
    "challenge_commitment": b64(hashlib.sha256(b"EMABLED-EXCHANGE-ENDPOINT-CHALLENGE-0.1\0" + challenge_input).digest()),
    "responded_at": "2026-08-05T15:00:02Z",
}
wrong_audience = {**request, "audience": "urn:xcim:app:attacker"}
noncanonical_time = {**request, "issued_at": "2026-08-05T15:00:00+00:00"}
wrong_endpoint = {**response, "endpoint_uri": "https://deploytoagents.com/xcim/other"}
valid_response_jws = sign(response, RESPONSE_TYPE, VENDOR_KID, vendor)
bad_signature = dict(valid_response_jws)
bad_signature["signature"] = ("A" if bad_signature["signature"][0] != "A" else "B") + bad_signature["signature"][1:]

document = {
    "vector_id": "xcim-0.1-exchange-endpoint-challenge-01",
    "issuer_key_id": ISSUER_KID,
    "issuer_public_key_raw_base64url": b64(issuer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)),
    "vendor_key_id": VENDOR_KID,
    "vendor_public_key_raw_base64url": b64(vendor.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)),
    "request": request,
    "request_jws": sign(request, REQUEST_TYPE, ISSUER_KID, issuer),
    "response": response,
    "response_jws": valid_response_jws,
    "negative": {
        "request_wrong_audience_jws": sign(wrong_audience, REQUEST_TYPE, ISSUER_KID, issuer),
        "request_non_z_timestamp_jws": sign(noncanonical_time, REQUEST_TYPE, ISSUER_KID, issuer),
        "response_wrong_endpoint_jws": sign(wrong_endpoint, RESPONSE_TYPE, VENDOR_KID, vendor),
        "response_bad_signature_jws": bad_signature,
    },
}
OUTPUT.write_text(json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
print(f"Generated {document['vector_id']} at {OUTPUT.relative_to(ROOT)}")
