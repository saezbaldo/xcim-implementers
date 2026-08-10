# Implementer tools

The public draft includes an offline schema/fixture validator, deterministic
Node vector verifiers, a policy-neutral shadow-mode header adapter and a single
entry point for local or CI use:

```powershell
python -m pip install -r tools/requirements-ci.txt
python tools/xcim_check.py
```

The command runs the Python validator and every `verify*.mjs` runner from the
repository root. Use `--python-only`, `--node-only` or `--list` to narrow or
inspect the checks. A green run proves that the published draft artifacts are
self-consistent; it does not prove interoperability with an independent
sender, receiver or production trust network.

To exercise sender/receiver wiring without changing delivery policy:

```powershell
python tools/shadow_mode_adapter.py examples/xcim-shadow-mode.eml
python -m unittest tools.test_shadow_mode_adapter
```

The adapter only validates the D-001 header pair and reports a shadow
observation. It does not fetch references, establish issuer trust or verify a
proof bundle.

The same command runs `check_public_artifacts.py`, which fails on private-key
blocks or credential-like assignments before a public source drop can pass CI.
See [`../SECURITY-REVIEW.md`](../SECURITY-REVIEW.md) for the boundary and the
manual review items that remain open.
