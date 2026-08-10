# XCIM protocol vectors

## Valid receipt JWS 01

`valid-receipt-jws.json` contains:

- a fixed public test-only Ed25519 seed;
- protected header and receipt payload;
- canonical UTF-8 bytes in hexadecimal;
- unpadded base64url JWS segments;
- exact signing input;
- raw public key and signature;
- expected resolver result.

Regenerate and verify:

```powershell
python tools/generate_valid_receipt_vector.py
node tools/verify_valid_receipt_vector.mjs
```

The embedded private seed is intentionally public and MUST NOT be used for production, development credentials, or any receipt outside these fixtures.

## Permission revocation JWS 01

`permission-revocation-jws.json` fixes the D-034 payload, protected header, canonical UTF-8 bytes, Ed25519 signature and domain-separated commitment. Python generates the object, while Node.js and C# independently reproduce JCS, signature and commitment; negative checks reject payload mutation, wrong `typ`, removed email-reply method, invalid scope/timestamp and embedded `issuer_signature`.

```powershell
python tools/generate_permission_revocation_vector.py
node tools/verify_permission_revocation_vector.mjs
python tools/validate_protocol_schemas.py
Run the C# conformance runner from the full Emabled workspace (the Python and Node runners in this repository cover these fixtures).
```

Its private seed is public test material and MUST NOT be reused.

## Negative receipt JWS vectors

`negative/` contains correctly classified signature, protected-header, canonicalization and receipt-invariant failures.

```powershell
python tools/generate_negative_vectors.py
node tools/verify_negative_vectors.mjs
```

## Event tree 01

`event-tree.json` contains nine canonical events, roots for sizes 0, 1, 2, 3, 4, 5, 7, 8 and 9, every incremental frontier through size 9, inclusion proofs, RFC6962-shaped consistency proofs and negative mutations. Inclusion verification binds the claimed `(tree_size, event_root)` to the trusted root published by a signed manifest.

```powershell
python tools/generate_event_tree_vectors.py
node tools/verify_event_tree_vectors.mjs
```

## State tree 01

`state-tree.json` contains all 257 deterministic empty hashes, three permission keys sharing the first eight key bits, empty and populated absence proofs, presence proofs before and after an update, and five invalid mutations. Its 32-byte sibling bitmap uses the normative MSB-first depth encoding.

```powershell
python tools/generate_state_tree_vectors.py
node tools/verify_state_tree_vectors.mjs
python tools/validate_protocol_schemas.py
```

## Full proof bundle 01

`proof-bundle.json` composes a signed receipt, its domain-separated commitment, the matching transparency event, an inclusion proof, current permission status, a signed batch manifest and a finalized Polygon anchor. It also publishes the exact base64url-to-EVM-`bytes32` representation round trip for the batch manifest commitment.

```powershell
python tools/generate_event_tree_vectors.py
python tools/generate_proof_bundle_vector.py
node tools/verify_proof_bundle_vector.mjs
python tools/validate_protocol_schemas.py
```

The schema validator registers every local `$id` and resolves relative `$ref` values offline; conformance tests do not depend on `xcim.org` being reachable.

## Candidate signed transparency-input handoff 01

`transparency-batch-inputs-jws.json` fixes a candidate JWS/JCS handoff for the
signed-hub option in ADR-0035. It includes a public test-only Ed25519 key,
canonical payload/header bytes, signing input and envelope. The vector proves
the cryptographic binding only; it is not a trust root and must not be used to
activate the production worker.

```powershell
python tools/generate_transparency_batch_inputs_jws_vector.py
python tools/verify_transparency_batch_inputs_jws_vector.py
node tools/verify_transparency_batch_inputs_jws_vector.mjs
python tools/validate_protocol_schemas.py
Run the C# conformance runner from the full Emabled workspace (the Python and Node runners in this repository cover these fixtures).
```

## Consent manifest and OAuth client assertions

`consent-manifest.json` contains three application-key-signed manifest states used to verify draft replacement, publication freeze and session binding. `oauth-client-assertions.json` covers valid, replay, audience, lifetime and issuer/subject cases for private-key JWT client authentication.

```powershell
python tools/generate_consent_manifest_vector.py
python tools/generate_oauth_client_assertion_vectors.py
Run the C# conformance runner from the full Emabled workspace (the Python and Node runners in this repository cover these fixtures).
```

## Signed exchange endpoint challenge 01

`exchange-endpoint-challenge.json` contains deterministic issuer/vendor Ed25519 keys, signed request and response envelopes, exact request/challenge commitments and negative cases for audience, endpoint rebinding, non-`Z` timestamp and signature mutation. Python generates it; Node.js and C# independently verify the same bytes.

```powershell
python tools/generate_exchange_endpoint_challenge_vector.py
node tools/verify_exchange_endpoint_challenge_vector.mjs
python tools/validate_protocol_schemas.py
Run the C# conformance runner from the full Emabled workspace (the Python and Node runners in this repository cover these fixtures).
```

## Issuer trust chain 01

`issuer-trust-chain.json` uses distinct deterministic Ed25519 test keys for `registry.xcim.net` and the Emabled issuer. It proves the chain from a registry-signed active accreditation to issuer-signed metadata and checks their issuer, accreditation and epoch bindings. The C# core, TypeScript SDK and Node verifier consume the same vector independently.

```powershell
python tools/generate_issuer_trust_vector.py
node tools/verify_issuer_trust_vector.mjs
python tools/validate_protocol_schemas.py
```

## Message recipient binding 01

`message-recipient-binding.json` fixes the v0.1 domain-separated SHA-256 digest for a canonical envelope recipient and a 16-byte presentation salt. Python, C# and TypeScript independently reproduce the digest and verify that copying it to another recipient or changing the salt fails.

```powershell
python tools/check_message_recipient_vector.py
Run the C# conformance runner from the full Emabled workspace (the Python and Node runners in this repository cover these fixtures).
Run the TypeScript SDK suite from the full Emabled workspace.
```

## Email normalization 01

`email-normalization.json` fixes the valid and invalid cases for `xcim-email-0.1`, including local-part case preservation and IDNA domain canonicalization. Python and C# consume the same vector; provider-specific comparison keys remain separate policy behavior.

```powershell
python tools/check_email_normalization_vector.py
Run the C# conformance runner from the full Emabled workspace (the Python and Node runners in this repository cover these fixtures).
```
