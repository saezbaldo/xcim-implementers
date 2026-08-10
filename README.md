# XCIM Implementers Source Drop

This repository contains the public XCIM implementer materials for draft v0.1.
The schemas and deterministic fixtures are usable for development and review;
they do not create a production trust root or a certification mark.

## Layout

```text
schemas/                 # JSON Schema Draft 2020-12 contracts
test-vectors/            # valid, invalid, replay and stale-state fixtures
examples/                # sanitized .eml and integration examples
implementation-reports/ # dated reports from independent implementers
tools/                   # local generators, validators and verifiers
registries/              # result-code and media-type registries
docs/adr/                # foundational protocol decisions
```

## Current state

- The Emabled reference issuer sandbox is operational.
- Canonical schemas and byte-level fixture definitions are published for draft review.
- Python and Node generators/validators/verifiers are published, with a unified
  `xcim_check.py` command for local and CI runs.
- No independent implementation has a public interoperability result.

The authoritative public program status is
[xcim.org/tools](https://xcim.org/tools/). This source drop is a versioned draft
with corresponding ADRs; production deployment and independent certification
remain out of scope.

## Verify locally

```powershell
python -m pip install -r tools/requirements-ci.txt
python tools/validate_protocol_schemas.py
Get-ChildItem tools -Filter 'verify*.mjs' | ForEach-Object { node $_.FullName }
# Or run the complete check from the repository root:
python tools/xcim_check.py
```

The fixtures use public test-only keys. Never reuse them for real issuers,
vendors or production credentials.
