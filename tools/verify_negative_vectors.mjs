#!/usr/bin/env node

import { readFileSync, readdirSync } from "node:fs";
import { createPublicKey, verify } from "node:crypto";
import { join } from "node:path";

const directory = process.argv[2] ?? "test-vectors/negative";
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

const classify = (vector) => {
  const { envelope } = vector;
  const signingInput = Buffer.from(`${envelope.protected}.${envelope.payload}`, "ascii");
  const publicKey = createPublicKey({
    key: { kty: "OKP", crv: "Ed25519", x: vector.public_key_raw_base64url },
    format: "jwk",
  });
  if (!verify(null, signingInput, publicKey, fromBase64Url(envelope.signature))) return "XCIM_SIGNATURE_FAIL";

  let protectedHeader;
  let payload;
  try {
    protectedHeader = JSON.parse(fromBase64Url(envelope.protected).toString("utf8"));
    payload = JSON.parse(fromBase64Url(envelope.payload).toString("utf8"));
  } catch {
    return "XCIM_MALFORMED";
  }

  if (!Buffer.from(canonicalize(protectedHeader)).equals(fromBase64Url(envelope.protected))) return "XCIM_MALFORMED";
  if (!Buffer.from(canonicalize(payload)).equals(fromBase64Url(envelope.payload))) return "XCIM_MALFORMED";
  if (protectedHeader.alg !== "EdDSA" || protectedHeader.typ !== "application/xcim-receipt+jcs") return "XCIM_MALFORMED";
  if (payload.permissions?.some((permission) => permission.decision === "declined" && permission.granted_at !== null)) {
    return "XCIM_MALFORMED";
  }
  return "UNEXPECTED_PASS";
};

const paths = readdirSync(directory)
  .filter((name) => name.endsWith(".json"))
  .sort()
  .map((name) => join(directory, name));

if (paths.length === 0) throw new Error(`No JSON vectors found in ${directory}`);

for (const path of paths) {
  const vector = JSON.parse(readFileSync(path, "utf8"));
  const actual = classify(vector);
  if (actual !== vector.expected_result) {
    throw new Error(`${vector.vector_id}: expected ${vector.expected_result}, got ${actual}`);
  }
  console.log(`Rejected ${vector.vector_id}: ${actual}`);
}
