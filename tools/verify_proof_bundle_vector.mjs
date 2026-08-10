#!/usr/bin/env node

import { createHash, createPublicKey, verify } from "node:crypto";
import { readFileSync } from "node:fs";

const path = process.argv[2] ?? "test-vectors/proof-bundle.json";
const vector = JSON.parse(readFileSync(path, "utf8"));
const bundle = vector.bundle;
const dec = (v) => Buffer.from(v, "base64url");
const enc = (v) => Buffer.from(v).toString("base64url");
const hash = (...parts) => createHash("sha256").update(Buffer.concat(parts.map(Buffer.from))).digest();
const canonicalize = (v) => {
  if (v === null || typeof v === "boolean" || typeof v === "string") return JSON.stringify(v);
  if (typeof v === "number") { if (!Number.isSafeInteger(v)) throw new Error("Safe integers only"); return JSON.stringify(v); }
  if (Array.isArray(v)) return `[${v.map(canonicalize).join(",")}]`;
  return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canonicalize(v[k])}`).join(",")}}`;
};
const publicKey = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: vector.issuer_public_key_raw_base64url }, format: "jwk" });
const verifyJws = (jws, typ) => {
  const header = JSON.parse(dec(jws.protected));
  if (header.alg !== "EdDSA" || header.typ !== typ) return false;
  return verify(null, Buffer.from(`${jws.protected}.${jws.payload}`), publicKey, dec(jws.signature));
};

if (!verifyJws(bundle.receipt, "application/xcim-receipt+jcs")) throw new Error("Receipt signature failed");
const receiptPayload = JSON.parse(dec(bundle.receipt.payload));
if (canonicalize(receiptPayload) !== dec(bundle.receipt.payload).toString()) throw new Error("Receipt not canonical");
const receiptCommitment = hash(Buffer.from("XCIM-RECEIPT-0.1\0"), Buffer.from(canonicalize(receiptPayload)));
if (enc(receiptCommitment) !== bundle.receipt_commitment || bundle.receipt_event.object_commitment !== bundle.receipt_commitment) throw new Error("Receipt/event commitment mismatch");

const manifestJws = bundle.batch_manifests[0].manifest;
if (!verifyJws(manifestJws, "application/xcim-batch-manifest+jcs")) throw new Error("Manifest signature failed");
const manifest = JSON.parse(dec(manifestJws.payload));
if (canonicalize(manifest) !== dec(manifestJws.payload).toString()) throw new Error("Manifest not canonical");
const manifestHash = hash(Buffer.from("XCIM-BATCH-MANIFEST-0.1\0"), Buffer.from(canonicalize(manifest)));
if (enc(manifestHash) !== bundle.anchors[0].batch_manifest_hash || `0x${manifestHash.toString("hex")}` !== vector.batch_manifest_hash_evm_hex) throw new Error("Anchor commitment/bytes32 mismatch");

const EVENT_LEAF = Buffer.from("XCIM-EVENT-LEAF-0.1\0");
const EVENT_NODE = Buffer.from("XCIM-MERKLE-NODE-0.1\0");
const eventNode = (left, right) => hash(EVENT_NODE, left, right);
const split = (size) => 2 ** Math.floor(Math.log2(size - 1));
const inclusion = bundle.event_inclusion_proof;
let cursor = 0;
const rebuildInclusion = (leaf, index, size) => {
  if (size === 1) return leaf;
  const k = split(size);
  if (index < k) return eventNode(rebuildInclusion(leaf, index, k), dec(inclusion.path[cursor++]));
  const right = rebuildInclusion(leaf, index - k, size - k);
  return eventNode(dec(inclusion.path[cursor++]), right);
};
const eventLeaf = hash(EVENT_LEAF, Buffer.from(canonicalize(bundle.receipt_event)));
const inclusionRoot = rebuildInclusion(eventLeaf, inclusion.leaf_index, inclusion.tree_size);
if (cursor !== inclusion.path.length || !inclusionRoot.equals(dec(manifest.event_root)) || inclusion.tree_size !== manifest.tree_size || inclusion.batch_sequence !== manifest.batch_sequence) throw new Error("Event inclusion/batch binding failed");

const STATE_VALUE = Buffer.from("XCIM-STATE-VALUE-0.1\0");
const STATE_LEAF = Buffer.from("XCIM-STATE-LEAF-0.1\0");
const STATE_NODE = Buffer.from("XCIM-STATE-NODE-0.1\0");
const stateNode = (left, right) => hash(STATE_NODE, left, right);
const empty = Array(257); empty[256] = hash(Buffer.from("XCIM-STATE-EMPTY-LEAF-0.1\0"));
for (let d = 255; d >= 0; d--) empty[d] = stateNode(empty[d + 1], empty[d + 1]);
const status = bundle.current_status_proof;
const key = dec(status.state_key); const bitmap = dec(status.sibling_bitmap);
let siblingCursor = status.non_empty_siblings.length - 1;
let current = hash(STATE_LEAF, key, hash(STATE_VALUE, Buffer.from(canonicalize(status.state_value))));
for (let d = 255; d >= 0; d--) {
  const present = (bitmap[Math.floor(d / 8)] & (0x80 >> (d % 8))) !== 0;
  const sibling = present ? dec(status.non_empty_siblings[siblingCursor--]) : empty[d + 1];
  const keyBit = (key[Math.floor(d / 8)] >> (7 - d % 8)) & 1;
  current = keyBit === 0 ? stateNode(current, sibling) : stateNode(sibling, current);
}
if (siblingCursor !== -1 || !current.equals(dec(manifest.state_root)) || status.batch_sequence !== manifest.batch_sequence) throw new Error("Current-state/batch binding failed");
if (status.state_value.object_id !== receiptPayload.permissions[0].permission_id || status.state_value.status !== "active") throw new Error("Permission status binding failed");

console.log(`Verified ${vector.vector_id}: receipt -> event -> inclusion -> status -> manifest -> anchor -> ${vector.expected_result}`);
