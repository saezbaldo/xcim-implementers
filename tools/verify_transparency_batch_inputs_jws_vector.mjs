#!/usr/bin/env node

import { createPublicKey, verify } from "node:crypto";
import { readFileSync } from "node:fs";

const path = process.argv[2] ?? "test-vectors/transparency-batch-inputs-jws.json";
const vector = JSON.parse(readFileSync(path, "utf8"));
const fromBase64Url = (value) => Buffer.from(value, "base64url");

const canonicalize = (value) => {
  if (value === null || typeof value === "boolean" || typeof value === "string") return JSON.stringify(value);
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
if (vector.protected_header.typ !== "application/xcim-transparency-batch-inputs+jcs") throw new Error("JWS typ mismatch");
if (vector.media_type !== "application/xcim-transparency-batch-inputs+jws+json") throw new Error("Media type mismatch");
if (vector.payload.object_type !== "transparency_batch_inputs" || vector.payload.batch_sequence !== 7 ||
    vector.payload.issuer_id !== "urn:xcim:issuer:emabled.com") throw new Error("Payload binding mismatch");

const signingInput = Buffer.from(`${vector.envelope.protected}.${vector.envelope.payload}`, "ascii");
if (signingInput.toString("ascii") !== vector.signing_input_ascii) throw new Error("Signing input mismatch");
const publicKey = createPublicKey({
  key: { kty: "OKP", crv: "Ed25519", x: vector.public_key_raw_base64url },
  format: "jwk",
});
if (!verify(null, signingInput, publicKey, fromBase64Url(vector.envelope.signature))) {
  throw new Error("Ed25519 signature verification failed");
}

const tamperedPayload = { ...vector.payload, batch_sequence: 8 };
const tamperedInput = Buffer.from(`${vector.envelope.protected}.${Buffer.from(canonicalize(tamperedPayload)).toString("base64url")}`, "ascii");
if (verify(null, tamperedInput, publicKey, fromBase64Url(vector.envelope.signature))) {
  throw new Error("Payload mutation preserved signature validity");
}

console.log(`Verified ${vector.vector_id}: JWS, JCS and sequence mutation rejection`);
