# Examples

`xcim-shadow-mode.eml` is a sanitized, non-deliverable message showing where an
ESP or gateway can carry `XCIM-Reference` and `XCIM-Proof` while an ISP or
mailbox provider evaluates the signal in shadow mode. Its URI and proof are
placeholders; it is not a valid conformance vector.

For byte-valid material, use the versioned files in
[`../test-vectors/`](../test-vectors/) and run `python tools/xcim_check.py`.
Do not add recipient addresses, OAuth material, private keys or predictable
email hashes to this directory.
