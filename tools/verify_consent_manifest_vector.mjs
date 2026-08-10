#!/usr/bin/env node

import { createHash, createPublicKey, verify } from "node:crypto";
import { readFileSync } from "node:fs";

const path = process.argv[2] ?? "test-vectors/consent-manifest.json";
const vector = JSON.parse(readFileSync(path, "utf8"));
const canonicalize = (value) => {
  if (value === null || typeof value === "boolean" || typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number") { if (!Number.isSafeInteger(value)) throw new Error("Safe integers only"); return JSON.stringify(value); }
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(",")}}`;
};
const publicKey = createPublicKey({
  key: { kty: "OKP", crv: "Ed25519", x: vector.public_key_raw_base64url }, format: "jwk",
});
const verifyManifest = (manifest) => {
  const unsigned = structuredClone(manifest);
  const signature = Buffer.from(unsigned.vendor_signature, "base64url");
  delete unsigned.vendor_signature;
  const input = Buffer.concat([Buffer.from("XCIM-CONSENT-MANIFEST-SIGNATURE-0.1\0"), Buffer.from(canonicalize(unsigned))]);
  if (!verify(null, input, publicKey, signature)) throw new Error(`Manifest signature failed: ${manifest.manifest_id}`);
};

for (const name of ["manifest", "replacement_manifest", "session_manifest", "localized_manifest"]) verifyManifest(vector[name]);
const hash = createHash("sha256").update(canonicalize(vector.manifest)).digest("base64url");
if (hash !== vector.canonical_hash_base64url) throw new Error("Consent manifest canonical hash mismatch");
if (vector.manifest.vendor_signature === vector.replacement_manifest.vendor_signature ||
    vector.manifest.manifest_id === vector.session_manifest.manifest_id)
  throw new Error("Consent manifest replacement/session vectors are not distinct");
console.log("Verified consent manifest signatures, canonical hash and 4 lifecycle/localization fixtures");
