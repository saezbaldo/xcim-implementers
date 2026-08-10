#!/usr/bin/env python3
"""Small, policy-neutral XCIM header adapter for sender/receiver shadow mode.

This module deliberately stops at transport observation. It does not decide
trust, fetch a reference, verify a proof or change delivery policy.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass
from email import policy
from email.parser import BytesParser
from pathlib import Path
from typing import Any


REFERENCE_HEADER = "XCIM-Reference"
PROOF_HEADER = "XCIM-Proof"
MAX_HEADER_BYTES = 8192


class HeaderError(ValueError):
    """Raised when an XCIM header cannot be safely transported."""


@dataclass(frozen=True)
class ShadowObservation:
    """What a receiver can record without making a delivery decision."""

    status: str
    reference: str | None = None
    proof: str | None = None
    reasons: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["reasons"] = list(self.reasons)
        return result


def _safe_value(name: str, value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise HeaderError(f"{name} must be a non-empty string")
    if "\r" in value or "\n" in value or "\x00" in value:
        raise HeaderError(f"{name} contains a forbidden control sequence")
    encoded = value.strip().encode("utf-8")
    if len(encoded) > MAX_HEADER_BYTES:
        raise HeaderError(f"{name} exceeds {MAX_HEADER_BYTES} UTF-8 bytes")
    if any(ord(char) < 32 and char not in "\t" for char in value):
        raise HeaderError(f"{name} contains a forbidden control character")
    return value.strip()


def build_xcim_headers(reference: str, proof: str) -> dict[str, str]:
    """Return the two D-001 headers for a sender adapter.

    Cryptographic validity and issuer trust remain verifier responsibilities.
    The reference is required to use HTTPS so a caller cannot accidentally
    emit a local-file or clear-text transport URI.
    """

    safe_reference = _safe_value(REFERENCE_HEADER, reference)
    if not safe_reference.lower().startswith("https://"):
        raise HeaderError(f"{REFERENCE_HEADER} must use https")
    return {
        REFERENCE_HEADER: safe_reference,
        PROOF_HEADER: _safe_value(PROOF_HEADER, proof),
    }


def render_xcim_headers(reference: str, proof: str) -> str:
    """Render sender headers without a trailing message body."""

    headers = build_xcim_headers(reference, proof)
    return "\r\n".join(f"{name}: {value}" for name, value in headers.items()) + "\r\n"


def _message_bytes(message: bytes | str) -> bytes:
    if isinstance(message, str):
        return message.encode("utf-8")
    if isinstance(message, bytes):
        return message
    raise TypeError("message must be bytes or str")


def observe_message(message: bytes | str) -> ShadowObservation:
    """Parse an RFC 5322 message and observe XCIM headers in shadow mode."""

    try:
        parsed = BytesParser(policy=policy.default).parsebytes(_message_bytes(message))
    except Exception as exc:  # pragma: no cover - parser-specific exception types
        return ShadowObservation("malformed", reasons=(f"message_parse_failed:{type(exc).__name__}",))

    values: dict[str, str] = {}
    reasons: list[str] = []
    for name in (REFERENCE_HEADER, PROOF_HEADER):
        headers = parsed.get_all(name, failobj=[]) or []
        if len(headers) > 1:
            reasons.append(f"duplicate_header:{name}")
            continue
        if not headers:
            continue
        try:
            values[name] = _safe_value(name, str(headers[0]))
        except HeaderError as exc:
            reasons.append(str(exc))

    if reasons:
        return ShadowObservation("malformed", values.get(REFERENCE_HEADER), values.get(PROOF_HEADER), tuple(reasons))
    if not values:
        return ShadowObservation("absent")
    if REFERENCE_HEADER not in values or PROOF_HEADER not in values:
        return ShadowObservation("malformed", values.get(REFERENCE_HEADER), values.get(PROOF_HEADER), ("incomplete_header_pair",))
    return ShadowObservation("candidate", values[REFERENCE_HEADER], values[PROOF_HEADER])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Observe XCIM headers without changing delivery policy")
    parser.add_argument("message", type=Path, help="RFC 5322 message to inspect")
    args = parser.parse_args(argv)
    observation = observe_message(args.message.read_bytes())
    print(json.dumps(observation.as_dict(), indent=2, sort_keys=True))
    return 0 if observation.status in {"absent", "candidate"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
