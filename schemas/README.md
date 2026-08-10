# XCIM JSON Schemas

Machine-readable contracts for protocol version 0.1.

## Initial set

- `xcim/0.1/jws-envelope.schema.json`
- `xcim/0.1/consent-manifest.schema.json`
- `xcim/0.1/receipt.schema.json`
- `xcim/0.1/transparency-event.schema.json`
- `xcim/0.1/batch-manifest.schema.json`
- `xcim/0.1/state-value.schema.json`
- `xcim/0.1/status-proof.schema.json`

Schemas use JSON Schema Draft 2020-12 and reject unknown properties in signed core objects. Extensions that change security semantics require an explicit schema/version and critical-extension handling; they cannot be smuggled in as arbitrary members.

Semantic requirements that JSON Schema cannot prove—JCS canonical bytes, cryptographic verification, key validity, nonce replay, provider policy and Merkle proofs—remain mandatory verifier checks.

Validation command:

```powershell
python -c "import json,pathlib,jsonschema; fs=sorted(pathlib.Path('schemas').rglob('*.json')); [jsonschema.Draft202012Validator.check_schema(json.loads(p.read_text(encoding='utf-8'))) for p in fs]"
```
