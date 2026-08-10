#!/usr/bin/env node

import { createHash, createPublicKey, verify } from "node:crypto";
import { readFileSync } from "node:fs";

const path = process.argv[2] ?? "test-vectors/exchange-endpoint-challenge.json";
const vector = JSON.parse(readFileSync(path, "utf8"));
const decode = (value) => Buffer.from(value, "base64url");
const encode = (value) => Buffer.from(value).toString("base64url");
const canonicalize = (value) => {
  if (value === null || typeof value === "boolean" || typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) throw new Error("Safe integers only");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(",")}}`;
};
const sha256 = (value) => createHash("sha256").update(value).digest();
const publicKey = (raw) => createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: raw }, format: "jwk" });
const openJws = (envelope, rawKey, expectedType, expectedKid) => {
  if (Object.keys(envelope).sort().join() !== "payload,protected,signature") throw new Error("JWS envelope shape mismatch");
  const headerBytes = decode(envelope.protected);
  const payloadBytes = decode(envelope.payload);
  const header = JSON.parse(headerBytes);
  const payload = JSON.parse(payloadBytes);
  if (canonicalize(header) !== headerBytes.toString() || canonicalize(payload) !== payloadBytes.toString())
    throw new Error("JWS contains noncanonical JSON");
  if (header.alg !== "EdDSA" || header.typ !== expectedType || header.kid !== expectedKid)
    throw new Error("JWS protected header mismatch");
  if (!verify(null, Buffer.from(`${envelope.protected}.${envelope.payload}`), publicKey(rawKey), decode(envelope.signature)))
    throw new Error("JWS signature failed");
  return payload;
};
const exactKeys = (value, expected) => Object.keys(value).sort().join() === [...expected].sort().join();
const requestKeys = ["xcim_version", "object_type", "challenge_id", "endpoint_id", "application_id", "application_epoch", "endpoint_uri", "audience", "token", "issued_at", "expires_at"];
const responseKeys = ["xcim_version", "object_type", "challenge_id", "endpoint_id", "application_id", "application_epoch", "endpoint_uri", "request_commitment", "challenge_commitment", "responded_at"];

const request = openJws(vector.request_jws, vector.issuer_public_key_raw_base64url,
  "application/xcim-exchange-challenge+jcs", vector.issuer_key_id);
if (!exactKeys(request, requestKeys) || canonicalize(request) !== canonicalize(vector.request) ||
    request.audience !== request.application_id || decode(request.token).length !== 32)
  throw new Error("Request binding failed");

const response = openJws(vector.response_jws, vector.vendor_public_key_raw_base64url,
  "application/xcim-exchange-challenge-response+jcs", vector.vendor_key_id);
const requestCommitment = encode(sha256(Buffer.from(canonicalize(request))));
const challengeCommitment = encode(sha256(Buffer.concat([
  Buffer.from("EMABLED-EXCHANGE-ENDPOINT-CHALLENGE-0.1\0"),
  Buffer.from([request.challenge_id, request.endpoint_id, request.endpoint_uri, request.token].join("\0")),
])));
if (!exactKeys(response, responseKeys) || canonicalize(response) !== canonicalize(vector.response) ||
    response.challenge_id !== request.challenge_id || response.endpoint_id !== request.endpoint_id ||
    response.application_id !== request.application_id || response.application_epoch !== request.application_epoch ||
    response.endpoint_uri !== request.endpoint_uri || response.request_commitment !== requestCommitment ||
    response.challenge_commitment !== challengeCommitment || Object.hasOwn(response, "token"))
  throw new Error("Response binding failed");

const wrongAudience = openJws(vector.negative.request_wrong_audience_jws, vector.issuer_public_key_raw_base64url,
  "application/xcim-exchange-challenge+jcs", vector.issuer_key_id);
if (wrongAudience.audience === wrongAudience.application_id) throw new Error("Wrong-audience negative vector did not fail binding");
const nonZTimestamp = openJws(vector.negative.request_non_z_timestamp_jws, vector.issuer_public_key_raw_base64url,
  "application/xcim-exchange-challenge+jcs", vector.issuer_key_id);
if (nonZTimestamp.issued_at.endsWith("Z")) throw new Error("Non-Z timestamp negative vector did not fail syntax");
const wrongEndpoint = openJws(vector.negative.response_wrong_endpoint_jws, vector.vendor_public_key_raw_base64url,
  "application/xcim-exchange-challenge-response+jcs", vector.vendor_key_id);
if (wrongEndpoint.endpoint_uri === request.endpoint_uri) throw new Error("Wrong-endpoint negative vector did not fail binding");
try {
  openJws(vector.negative.response_bad_signature_jws, vector.vendor_public_key_raw_base64url,
    "application/xcim-exchange-challenge-response+jcs", vector.vendor_key_id);
  throw new Error("Bad-signature negative vector was accepted");
} catch (error) {
  if (error.message !== "JWS signature failed") throw error;
}

console.log(`Verified ${vector.vector_id}: issuer request -> vendor response -> commitment bindings, 4 negative tests`);
