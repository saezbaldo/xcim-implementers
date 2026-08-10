#!/usr/bin/env node

import { createPublicKey, verify } from "node:crypto";
import { readFileSync } from "node:fs";

const path = process.argv[2] ?? "test-vectors/oauth-client-assertions.json";
const vector = JSON.parse(readFileSync(path, "utf8"));
const key = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: vector.public_key_raw_base64url }, format: "jwk" });
const results = new Map();
for (const item of vector.vectors) {
  const segments = item.jwt.split(".");
  if (segments.length !== 3) throw new Error(`${item.name}: JWT shape failed`);
  const header = JSON.parse(Buffer.from(segments[0], "base64url"));
  const claims = JSON.parse(Buffer.from(segments[1], "base64url"));
  if (header.alg !== "EdDSA" || header.typ !== "JWT" || header.kid !== "app-key-test-01" ||
      !verify(null, Buffer.from(`${segments[0]}.${segments[1]}`), key, Buffer.from(segments[2], "base64url")))
    throw new Error(`${item.name}: JWT signature/header failed`);
  const valid = claims.iss === claims.sub && claims.iss === "urn:xcim:app:vendor-1" &&
    claims.aud === vector.audience && claims.iat <= vector.now && claims.exp > vector.now &&
    claims.exp - claims.iat <= 300 && typeof claims.jti === "string" && claims.jti.length >= 16;
  results.set(item.name, valid);
}
for (const name of ["valid", "valid-http", "valid-invalid-scope"])
  if (!results.get(name)) throw new Error(`${name}: valid assertion rejected`);
for (const name of ["wrong-audience", "expired", "excessive-lifetime", "issuer-subject-mismatch"])
  if (results.get(name)) throw new Error(`${name}: invalid assertion accepted`);
if (new Set(vector.vectors.map((item) => JSON.parse(Buffer.from(item.jwt.split(".")[1], "base64url")).jti)).size !== vector.vectors.length)
  throw new Error("OAuth assertion fixture reused a JWT ID");
console.log(`Verified ${vector.vectors.length} OAuth client assertions across valid and claim-failure cases`);
