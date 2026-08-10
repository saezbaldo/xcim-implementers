#!/usr/bin/env python3
"""Validate XCIM schemas and fixtures entirely offline."""

from __future__ import annotations

import copy
import base64
import json
from pathlib import Path

import jsonschema
from referencing import Registry, Resource


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIR = ROOT / "schemas" / "xcim" / "0.1"


def load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def decode_payload(envelope: dict):
    segment = envelope["payload"]
    return json.loads(base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)))


def main() -> None:
    schemas = [load(path) for path in sorted(SCHEMA_DIR.glob("*.schema.json"))]
    for schema in schemas:
        jsonschema.Draft202012Validator.check_schema(schema)
    registry = Registry().with_resources(
        [(schema["$id"], Resource.from_contents(schema)) for schema in schemas]
    )
    by_title = {schema["title"]: schema for schema in schemas}
    format_checker = jsonschema.FormatChecker()

    vector = load(ROOT / "test-vectors" / "state-tree.json")
    state_validator = jsonschema.Draft202012Validator(
        by_title["XCIM 0.1 Current-State Value"], registry=registry, format_checker=format_checker
    )
    proof_validator = jsonschema.Draft202012Validator(
        by_title["XCIM 0.1 Compressed Sparse-Merkle Status Proof"], registry=registry, format_checker=format_checker
    )
    for proof in vector["proofs"].values():
        if proof["state_value"] is not None:
            state_validator.validate(proof["state_value"])
        protocol_proof = copy.deepcopy(proof)
        protocol_proof.pop("state_value_jcs_base64url")
        proof_validator.validate(protocol_proof)

    event_vector = load(ROOT / "test-vectors" / "event-tree.json")
    event_validator = jsonschema.Draft202012Validator(
        by_title["XCIM 0.1 Transparency Event"], registry=registry, format_checker=format_checker
    )
    for event in event_vector["events"]:
        event_validator.validate(event)
    inclusion_validator = jsonschema.Draft202012Validator(
        by_title["XCIM 0.1 Event Inclusion Proof"], registry=registry, format_checker=format_checker
    )
    consistency_validator = jsonschema.Draft202012Validator(
        by_title["XCIM 0.1 Event Consistency Proof"], registry=registry, format_checker=format_checker
    )
    for proof in event_vector["inclusion_proofs"]:
        inclusion_validator.validate(proof)
    for proof in event_vector["consistency_proofs"]:
        consistency_validator.validate(proof)

    registry_validator = jsonschema.Draft202012Validator(
        by_title["XCIM 0.1 Machine-Readable Registry"], registry=registry, format_checker=format_checker
    )
    registry_documents = [
        load(ROOT / "registries" / "xcim" / "0.1" / "result-codes.json"),
        load(ROOT / "registries" / "xcim" / "0.1" / "media-types.json"),
    ]
    for document in registry_documents:
        registry_validator.validate(document)
    codes = [item["code"] for item in registry_documents[0]["codes"]]
    media_types = [item["media_type"] for item in registry_documents[1]["types"]]
    if len(codes) != len(set(codes)) or len(media_types) != len(set(media_types)):
        raise ValueError("Registry entries must be unique")

    trust_vector = load(ROOT / "test-vectors" / "issuer-trust-chain.json")
    jsonschema.Draft202012Validator(
        by_title["XCIM 0.1 Issuer Metadata Payload"], registry=registry, format_checker=format_checker
    ).validate(trust_vector["issuer_metadata"])
    jsonschema.Draft202012Validator(
        by_title["XCIM 0.1 Issuer Accreditation Payload"], registry=registry, format_checker=format_checker
    ).validate(trust_vector["accreditation"])

    bundle_vector = load(ROOT / "test-vectors" / "proof-bundle.json")
    jsonschema.Draft202012Validator(
        by_title["XCIM 0.1 Full Proof Bundle"], registry=registry, format_checker=format_checker
    ).validate(bundle_vector["bundle"])
    jws_validator = jsonschema.Draft202012Validator(
        by_title["XCIM 0.1 JWS Flattened Envelope"], registry=registry, format_checker=format_checker
    )
    receipt_validator = jsonschema.Draft202012Validator(
        by_title["XCIM 0.1 Receipt Core Payload"], registry=registry, format_checker=format_checker
    )
    manifest_payload_validator = jsonschema.Draft202012Validator(
        by_title["XCIM 0.1 Batch Manifest Payload"], registry=registry, format_checker=format_checker
    )
    anchor_validator = jsonschema.Draft202012Validator(
        by_title["XCIM 0.1 Chain Anchor Reference"], registry=registry, format_checker=format_checker
    )
    valid_receipt = load(ROOT / "test-vectors" / "valid-receipt-jws.json")
    receipt_validator.validate(valid_receipt["payload"])
    revocation_vector = load(ROOT / "test-vectors" / "permission-revocation-jws.json")
    revocation_validator = jsonschema.Draft202012Validator(
        by_title["XCIM Permission Revocation Payload 0.1"], registry=registry, format_checker=format_checker
    )
    revocation_validator.validate(revocation_vector["payload"])
    for field, value in (
        ("method", "email_reply"),
        ("scope", "receipt"),
        ("effective_at", "2026-08-06T15:00:00+00:00"),
        ("issuer_signature", "prohibited"),
    ):
        invalid_revocation = copy.deepcopy(revocation_vector["payload"])
        invalid_revocation[field] = value
        if not list(revocation_validator.iter_errors(invalid_revocation)):
            raise ValueError(f"Permission revocation schema accepted invalid {field}")
    positive_envelopes = [valid_receipt["envelope"], revocation_vector["envelope"], bundle_vector["bundle"]["receipt"],
                          trust_vector["issuer_metadata_jws"], trust_vector["accreditation_jws"]]
    positive_envelopes.extend(item["manifest"] for item in bundle_vector["bundle"]["batch_manifests"])
    for envelope in positive_envelopes:
        jws_validator.validate(envelope)
    for item in bundle_vector["bundle"]["batch_manifests"]:
        manifest_payload_validator.validate(decode_payload(item["manifest"]))
    for anchor in bundle_vector["bundle"]["anchors"]:
        anchor_validator.validate(anchor)

    batch_inputs_vector = load(ROOT / "test-vectors" / "transparency-batch-inputs.json")
    batch_inputs_validator = jsonschema.Draft202012Validator(
        by_title["XCIM 0.1 Transparency Batch Inputs"], registry=registry, format_checker=format_checker
    )
    batch_inputs_validator.validate(batch_inputs_vector["valid"])
    for invalid in batch_inputs_vector["invalid"]:
        if not list(batch_inputs_validator.iter_errors(invalid["value"])):
            raise ValueError(f"Transparency batch inputs schema accepted invalid {invalid['name']}")
    signed_batch_inputs_vector = load(ROOT / "test-vectors" / "transparency-batch-inputs-jws.json")
    batch_inputs_validator.validate(signed_batch_inputs_vector["payload"])
    jws_validator.validate(signed_batch_inputs_vector["envelope"])
    if signed_batch_inputs_vector["protected_header"]["typ"] != "application/xcim-transparency-batch-inputs+jcs" or \
            signed_batch_inputs_vector["media_type"] != "application/xcim-transparency-batch-inputs+jws+json":
        raise ValueError("Signed transparency batch input vector has an unexpected media/type binding")

    manifest_vector = load(ROOT / "test-vectors" / "consent-manifest.json")
    manifest_validator = jsonschema.Draft202012Validator(
        by_title["XCIM 0.1 Consent Manifest Payload"], registry=registry, format_checker=format_checker
    )
    for name in ("manifest", "replacement_manifest", "session_manifest", "localized_manifest"):
        manifest_validator.validate(manifest_vector[name])

    exchange_vector = load(ROOT / "test-vectors" / "exchange-endpoint-challenge.json")
    exchange_request_validator = jsonschema.Draft202012Validator(
        by_title["XCIM 0.1 Exchange Endpoint Challenge Payload"], registry=registry, format_checker=format_checker
    )
    exchange_request_validator.validate(exchange_vector["request"])
    jsonschema.Draft202012Validator(
        by_title["XCIM 0.1 Exchange Endpoint Challenge Response Payload"], registry=registry, format_checker=format_checker
    ).validate(exchange_vector["response"])
    jws_validator.validate(exchange_vector["request_jws"])
    jws_validator.validate(exchange_vector["response_jws"])
    invalid_exchange_time = copy.deepcopy(exchange_vector["request"])
    invalid_exchange_time["issued_at"] = "2026-08-05T15:00:00+00:00"
    if not list(exchange_request_validator.iter_errors(invalid_exchange_time)):
        raise ValueError("Exchange challenge schema accepted a non-Z timestamp")

    print(
        f"Validated {len(schemas)} schemas, {len(vector['proofs'])} state proofs, "
        f"{len(event_vector['events'])} events, 4 consent manifests, 1 exchange challenge pair, {len(event_vector['inclusion_proofs'])} inclusion proofs, "
        f"{len(event_vector['consistency_proofs'])} consistency proofs, 2 issuer trust objects, 1 full proof bundle, "
        f"1 signed revocation, 1 transparency batch input handoff, 1 signed transparency input handoff, {len(codes)} result codes and {len(media_types)} media types offline"
    )


if __name__ == "__main__":
    main()
