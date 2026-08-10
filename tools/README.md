# Implementer tools

The public draft includes an offline schema/fixture validator, deterministic
Node vector verifiers and a single entry point for local or CI use:

```powershell
python -m pip install -r tools/requirements-ci.txt
python tools/xcim_check.py
```

The command runs the Python validator and every `verify*.mjs` runner from the
repository root. Use `--python-only`, `--node-only` or `--list` to narrow or
inspect the checks. A green run proves that the published draft artifacts are
self-consistent; it does not prove interoperability with an independent
sender, receiver or production trust network.
