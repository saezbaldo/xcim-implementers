#!/usr/bin/env node

import { readFileSync } from "node:fs";
import { createPublicKey, verify } from "node:crypto";

const path = process.argv[2] ?? "test-vectors/valid-receipt-jws.json";
const vector = JSON.parse(readFileSync(path, "utf8"));

const fromBase64Url = (value) => Buffer.from(value, "base64url");

const canonicalize = (value) => {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) throw new Error("Vector profile permits safe integers only");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  if (typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(",")}}`;
  }
  throw new Error(`Unsupported JSON value: ${typeof value}`);
};

const protectedBytes = Buffer.from(canonicalize(vector.protected_header), "utf8");
const payloadBytes = Buffer.from(canonicalize(vector.payload), "utf8");
if (!protectedBytes.equals(fromBase64Url(vector.envelope.protected))) throw new Error("Protected JCS mismatch");
if (!payloadBytes.equals(fromBase64Url(vector.envelope.payload))) throw new Error("Payload JCS mismatch");

const signingInput = Buffer.from(`${vector.envelope.protected}.${vector.envelope.payload}`, "ascii");
if (signingInput.toString("ascii") !== vector.signing_input_ascii) throw new Error("Signing input mismatch");

const publicKey = createPublicKey({
  key: { kty: "OKP", crv: "Ed25519", x: vector.public_key_raw_base64url },
  format: "jwk",
});
if (!verify(null, signingInput, publicKey, fromBase64Url(vector.envelope.signature))) {
  throw new Error("Ed25519 signature verification failed");
}

console.log(`Verified ${vector.vector_id}: ${vector.expected_result}`);
