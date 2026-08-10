from __future__ import annotations

import unittest
from pathlib import Path

from tools.shadow_mode_adapter import (
    HeaderError,
    build_xcim_headers,
    observe_message,
    render_xcim_headers,
)


EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "xcim-shadow-mode.eml"


class ShadowModeAdapterTests(unittest.TestCase):
    def test_sender_builds_only_d001_headers(self) -> None:
        headers = build_xcim_headers("https://issuer.example.invalid/r/1", "proof-placeholder")
        self.assertEqual(set(headers), {"XCIM-Reference", "XCIM-Proof"})
        self.assertIn(
            "XCIM-Reference: https://issuer.example.invalid/r/1\r\n",
            render_xcim_headers(headers["XCIM-Reference"], headers["XCIM-Proof"]),
        )

    def test_example_is_a_shadow_candidate(self) -> None:
        observation = observe_message(EXAMPLE.read_bytes())
        self.assertEqual(observation.status, "candidate")
        self.assertEqual(observation.reference, "https://issuer.example.invalid/xcim/receipts/receipt-test-01")

    def test_missing_pair_is_malformed(self) -> None:
        observation = observe_message(b"From: sender@example.invalid\nXCIM-Reference: https://issuer.example.invalid/r\n\nbody")
        self.assertEqual(observation.status, "malformed")
        self.assertIn("incomplete_header_pair", observation.reasons)

    def test_duplicate_header_is_malformed(self) -> None:
        message = (
            b"XCIM-Reference: https://issuer.example.invalid/r\n"
            b"XCIM-Reference: https://issuer.example.invalid/r2\n"
            b"XCIM-Proof: proof\n\nbody"
        )
        self.assertEqual(observe_message(message).status, "malformed")

    def test_sender_rejects_injection_and_cleartext_reference(self) -> None:
        with self.assertRaises(HeaderError):
            build_xcim_headers("http://issuer.example.invalid/r", "proof")
        with self.assertRaises(HeaderError):
            build_xcim_headers("https://issuer.example.invalid/r\r\nBcc: leaked@example.invalid", "proof")


if __name__ == "__main__":
    unittest.main()
