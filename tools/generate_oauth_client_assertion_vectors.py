#!/usr/bin/env python3
import base64
import json
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "test-vectors" / "oauth-client-assertions.json"
NOW = 1785967200
AUDIENCE = "https://api.emabled.com/oauth/token"
CLIENT = "urn:xcim:app:vendor-1"
KID = "app-key-test-01"

def b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")

private_key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
public_key = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
header = {"alg": "EdDSA", "kid": KID, "typ": "JWT"}

def signed(name: str, claims: dict) -> dict:
    protected = b64(json.dumps(header, separators=(",", ":"), sort_keys=True).encode())
    payload = b64(json.dumps(claims, separators=(",", ":"), sort_keys=True).encode())
    signing_input = f"{protected}.{payload}".encode("ascii")
    return {"name": name, "jwt": f"{protected}.{payload}.{b64(private_key.sign(signing_input))}"}

base = {"iss": CLIENT, "sub": CLIENT, "aud": AUDIENCE, "iat": NOW, "exp": NOW + 180, "jti": "jti-valid-00000001"}
vectors = [
    signed("valid", base),
    signed("valid-http", {**base, "jti": "jti-valid-http-0001"}),
    signed("valid-invalid-scope", {**base, "jti": "jti-valid-scope-001"}),
    signed("wrong-audience", {**base, "aud": "https://attacker.example/token", "jti": "jti-wrongaud-00001"}),
    signed("expired", {**base, "iat": NOW - 600, "exp": NOW - 300, "jti": "jti-expired-000001"}),
    signed("excessive-lifetime", {**base, "exp": NOW + 600, "jti": "jti-longlife-00001"}),
    signed("issuer-subject-mismatch", {**base, "sub": "app_attacker", "jti": "jti-mismatch-000001"}),
]
OUTPUT.write_text(json.dumps({
    "now": NOW,
    "audience": AUDIENCE,
    "public_key_raw_base64url": b64(public_key),
    "vectors": vectors,
}, indent=2) + "\n", encoding="utf-8")
print(f"Generated {len(vectors)} OAuth client assertion vectors at {OUTPUT.relative_to(ROOT)}")
