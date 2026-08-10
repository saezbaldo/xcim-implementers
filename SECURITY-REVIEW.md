# XCIM public source-drop security review

**Scope:** public draft v0.1 schemas, vectors, generators, verifiers, examples,
documentation and CI in this repository.

This document is a release checklist and evidence record. It is not an
independent cryptographic audit, penetration test or certification.

## Automated controls

- `python tools/check_public_artifacts.py` scans UTF-8 source artifacts for
  private-key blocks and credential-like assignments. Public fixture seeds are
  allowed only when explicitly named `*_TEST_ONLY`.
- `python tools/xcim_check.py` runs the artifact scan, shadow-mode adapter tests,
  JSON Schema validation and deterministic Python/Node vector verifiers.
- GitHub Actions runs the same command on every push and pull request.
- The shadow-mode adapter has no network calls, does not establish issuer trust,
  and does not change delivery policy.

## Threat boundaries

| Threat | Draft control | Remaining work |
|---|---|---|
| Header injection or ambiguous duplicates | Reject CRLF, controls, oversized values and duplicate D-001 headers | Review integration behavior in real MTAs/gateways |
| Test material mistaken for production keys | Explicit `*_TEST_ONLY` markers and public README warnings | Independent implementer key-management review |
| Proof copied to another recipient | Cryptographic recipient-binding vectors and verifier checks | Paired sender/receiver interoperability test |
| Stale or untrusted issuer state | Fail-closed vectors, trust-root contract and freshness result codes | External security review and live trust-source operations |
| PII leakage in public artifacts | Sanitized `.invalid` example and no customer data in vectors | Privacy review of any future implementation report |

## Release decision

The source drop is suitable for draft implementation and review. It must not be
described as a production trust root, certification suite or independent
interoperability result until the remaining external review and paired tests are
complete.
