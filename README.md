# XCIM Implementers Source Drop

This directory is the initial source layout for the public XCIM implementers
repository. It is intentionally a scaffold until the v0.1 byte-level decisions
are closed. Do not use it to claim conformance or production trust.

## Planned layout

```text
spec/                    # versioned protocol drafts and change notes
schemas/                 # canonical JSON schemas after D-003 through D-009
test-vectors/            # valid, invalid, replay and stale-state fixtures
examples/                # sanitized .eml and integration examples
implementation-reports/ # dated reports from independent implementers
tools/                   # local verifier, fixture runner and CI adapters
```

## Current state

- The Emabled reference issuer sandbox is operational.
- Canonical schemas and byte serialization are not published.
- Test vectors and a conformance CLI are not published.
- No independent implementation has a public interoperability result.

The source layout should be moved to the public repository only after a remote
owner, license policy and contribution workflow are approved. Until then, the
authoritative status is [xcim.org/tools](https://xcim.org/tools/).
