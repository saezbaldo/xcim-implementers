#!/usr/bin/env node

import { createPublicKey, verify } from "node:crypto";
import { readFileSync } from "node:fs";

const path = process.argv[2] ?? "test-vectors/issuer-trust-chain.json";
const vector = JSON.parse(readFileSync(path, "utf8"));
const decode = (value) => Buffer.from(value, "base64url");
const canonicalize = (value) => {
  if (value === null || typeof value === "boolean" || typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number") { if (!Number.isSafeInteger(value)) throw new Error("Safe integers only"); return JSON.stringify(value); }
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(",")}}`;
};
const verifyJws = (payload, envelope, publicRaw, expectedTyp) => {
  const header = JSON.parse(decode(envelope.protected));
  if (header.alg !== "EdDSA" || header.typ !== expectedTyp) return false;
  if (!decode(envelope.payload).equals(Buffer.from(canonicalize(payload)))) return false;
  const key = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: publicRaw }, format: "jwk" });
  return verify(null, Buffer.from(`${envelope.protected}.${envelope.payload}`), key, decode(envelope.signature));
};

if (!verifyJws(vector.accreditation, vector.accreditation_jws, vector.registry_public_key_raw_base64url, "application/xcim-issuer-accreditation+jcs")) throw new Error("Registry accreditation signature failed");
if (!verifyJws(vector.issuer_metadata, vector.issuer_metadata_jws, vector.issuer_public_key_raw_base64url, "application/xcim-issuer-metadata+jcs")) throw new Error("Issuer metadata signature failed");
const ref = vector.issuer_metadata.accreditation_reference;
if (vector.accreditation.status !== "active" || ref.accreditation_id !== vector.accreditation.accreditation_id || ref.accreditation_epoch !== vector.accreditation.accreditation_epoch || vector.accreditation.issuer_id !== vector.issuer_metadata.issuer_id) throw new Error("Accreditation/metadata binding failed");
console.log(`Verified ${vector.vector_id}: registry accreditation -> issuer metadata -> ${vector.expected_result}`);
