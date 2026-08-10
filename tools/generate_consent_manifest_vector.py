#!/usr/bin/env python3
import base64
import hashlib
import json
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "test-vectors" / "consent-manifest.json"
PREFIX = b"XCIM-CONSENT-MANIFEST-SIGNATURE-0.1\0"

def b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")

def canonical(value: dict) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")

private_key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
public_key = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
manifest = {
    "xcim_version": "0.1",
    "object_type": "consent_manifest",
    "manifest_id": "urn:xcim:manifest:vendor-1-newsletter-v1",
    "app_id": "urn:xcim:app:vendor-1",
    "app_epoch": 1,
    "version": "2026-08-v1",
    "display_name": "Integration Vendor",
    "legal_operator": {"name": "Integration Vendor Inc.", "verification": "not_verified"},
    "purposes": [
        {
            "purpose_id": "order.transactional",
            "authorization_kind": "transaction_relationship",
            "required": True,
            "title": "Order updates",
            "description": "Receipts, payment status, shipment and delivery notices.",
            "expected_frequency": "event_driven",
        },
        {
            "purpose_id": "marketing.newsletter",
            "authorization_kind": "explicit_consent",
            "required": False,
            "title": "Newsletter",
            "description": "Product news and selected offers.",
            "expected_frequency": "up_to_4_per_month",
        },
    ],
    "declared_sender_domains": ["mail.vendor.example"],
    "privacy_policy": "https://vendor.example/privacy",
    "terms": "https://vendor.example/terms",
    "locales": {"en": {}, "es": {}},
    "effective_from": "2026-08-05T18:00:00Z",
    "vendor_app_key_id": "app-key-test-01",
}
manifest["vendor_signature"] = b64(private_key.sign(PREFIX + canonical(manifest)))
canonical_full = canonical(manifest)
replacement = json.loads(json.dumps(manifest))
replacement["display_name"] = "Integration Vendor Updated Draft"
replacement.pop("vendor_signature")
replacement["vendor_signature"] = b64(private_key.sign(PREFIX + canonical(replacement)))
session_manifest = json.loads(json.dumps(manifest))
session_manifest["manifest_id"] = "urn:xcim:manifest:vendor-1-session-v1"
session_manifest["version"] = "2026-08-session-v1"
session_manifest.pop("vendor_signature")
session_manifest["vendor_signature"] = b64(private_key.sign(PREFIX + canonical(session_manifest)))
localized_manifest = {
    "xcim_version": "0.1",
    "object_type": "consent_manifest",
    "manifest_id": "urn:xcim:manifest:vendor-1-newsletter-v3",
    "app_id": "urn:xcim:app:vendor-1",
    "app_epoch": 1,
    "version": "2026-08-v3",
    "display_name": "Integration Vendor",
    "localization_profile": "xcim-locales-0.1",
    "default_locale": "en",
    "legal_operator": {"name": "Integration Vendor Inc.", "verification": "not_verified"},
    "purposes": [
        {
            "purpose_id": "order.transactional",
            "authorization_kind": "transaction_relationship",
            "required": True,
            "title": "Order updates",
            "description": "Receipts, payment status, shipment and delivery notices.",
            "expected_frequency": {"kind": "event_driven"},
        },
        {
            "purpose_id": "marketing.newsletter",
            "authorization_kind": "explicit_consent",
            "required": False,
            "title": "Newsletter",
            "description": "Product news and selected offers.",
            "expected_frequency": {"kind": "up_to_per_period", "maximum": 4, "period": "month"},
        },
    ],
    "declared_sender_domains": ["mail.vendor.example"],
    "privacy_policy": "https://vendor.example/privacy",
    "terms": "https://vendor.example/terms",
    "locales": {
        "en": {
            "display_name": "Integration Vendor",
            "purposes": {
                "order.transactional": {
                    "title": "Order updates",
                    "description": "Receipts, payment status, shipment and delivery notices.",
                    "expected_frequency_label": "When order events occur",
                },
                "marketing.newsletter": {
                    "title": "Newsletter",
                    "description": "Product news and selected offers.",
                    "expected_frequency_label": "Up to 4 emails per month",
                },
            },
        },
        "es": {
            "display_name": "Proveedor de integración",
            "purposes": {
                "order.transactional": {
                    "title": "Actualizaciones del pedido",
                    "description": "Recibos, estado del pago, envío y avisos de entrega.",
                    "expected_frequency_label": "Cuando ocurran eventos del pedido",
                },
                "marketing.newsletter": {
                    "title": "Boletín",
                    "description": "Noticias del producto y ofertas seleccionadas.",
                    "expected_frequency_label": "Hasta 4 correos por mes",
                },
            },
        },
    },
    "effective_from": "2026-08-05T18:00:00Z",
    "vendor_app_key_id": "app-key-test-01",
}
localized_manifest["vendor_signature"] = b64(private_key.sign(PREFIX + canonical(localized_manifest)))
OUTPUT.write_text(json.dumps({
    "description": "Valid signed XCIM 0.1 consent manifest",
    "public_key_raw_base64url": b64(public_key),
    "canonical_hash_base64url": b64(hashlib.sha256(canonical_full).digest()),
    "manifest": manifest,
    "replacement_manifest": replacement,
    "session_manifest": session_manifest,
    "localized_manifest": localized_manifest,
}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
print(f"Generated signed consent manifest vector at {OUTPUT.relative_to(ROOT)}")
