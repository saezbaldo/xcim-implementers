#!/usr/bin/env node

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

const path = process.argv[2] ?? "test-vectors/state-tree.json";
const vector = JSON.parse(readFileSync(path, "utf8"));
const b64 = (bytes) => Buffer.from(bytes).toString("base64url");
const unb64 = (value) => Buffer.from(value, "base64url");
const hash = (...parts) => createHash("sha256").update(Buffer.concat(parts.map(Buffer.from))).digest();
const KEY = Buffer.from("XCIM-STATE-KEY-0.1\0");
const VALUE = Buffer.from("XCIM-STATE-VALUE-0.1\0");
const LEAF = Buffer.from("XCIM-STATE-LEAF-0.1\0");
const NODE = Buffer.from("XCIM-STATE-NODE-0.1\0");
const EMPTY_LEAF = Buffer.from("XCIM-STATE-EMPTY-LEAF-0.1\0");

const canonicalize = (value) => {
  if (value === null || typeof value === "boolean" || typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) throw new Error("Safe integers only");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(",")}}`;
};
const nodeHash = (left, right) => hash(NODE, left, right);
const empty = Array(257);
empty[256] = hash(EMPTY_LEAF);
for (let depth = 255; depth >= 0; depth--) empty[depth] = nodeHash(empty[depth + 1], empty[depth + 1]);
const keyBit = (key, depth) => (key[Math.floor(depth / 8)] >> (7 - depth % 8)) & 1;
const bitmapBit = (bitmap, depth) => (bitmap[Math.floor(depth / 8)] & (0x80 >> (depth % 8))) !== 0;
const stateKey = (type, id) => hash(KEY, Buffer.from(type), Buffer.from([0]), Buffer.from(id));
const leafHash = (key, value) => hash(LEAF, key, hash(VALUE, Buffer.from(canonicalize(value))));

const verifyProof = (proof) => {
  try {
    if (proof.tree_depth !== 256) return false;
    const key = unb64(proof.state_key);
    const bitmap = unb64(proof.sibling_bitmap);
    if (key.length !== 32 || bitmap.length !== 32) return false;
    const active = [...bitmap].reduce((sum, byte) => sum + byte.toString(2).replaceAll("0", "").length, 0);
    if (active !== proof.non_empty_siblings.length) return false;
    if (proof.presence !== (proof.state_value !== null)) return false;
    let current;
    if (proof.presence) {
      const canonical = Buffer.from(canonicalize(proof.state_value));
      if (!canonical.equals(unb64(proof.state_value_jcs_base64url))) return false;
      current = leafHash(key, proof.state_value);
    } else {
      if (proof.state_value_jcs_base64url !== null) return false;
      current = empty[256];
    }
    let siblingCursor = proof.non_empty_siblings.length - 1;
    for (let depth = 255; depth >= 0; depth--) {
      const sibling = bitmapBit(bitmap, depth) ? unb64(proof.non_empty_siblings[siblingCursor--]) : empty[depth + 1];
      current = keyBit(key, depth) === 0 ? nodeHash(current, sibling) : nodeHash(sibling, current);
    }
    return siblingCursor === -1 && current.equals(unb64(proof.state_root));
  } catch { return false; }
};

vector.empty_hashes.forEach((expected, depth) => { if (b64(empty[depth]) !== expected) throw new Error(`empty[${depth}] mismatch`); });
vector.keys.forEach((item) => { if (b64(stateKey("permission", item.object_id)) !== item.state_key) throw new Error(`Key mismatch: ${item.object_id}`); });
for (const [name, proof] of Object.entries(vector.proofs)) if (!verifyProof(proof)) throw new Error(`Proof failed: ${name}`);
if (vector.roots.three_entries !== vector.roots.three_entries_rebuilt_from_zero) throw new Error("Snapshot/rebuild root mismatch");
if (vector.roots.three_entries === vector.roots.updated) throw new Error("Update did not change root");

for (const test of vector.negative_tests) {
  const proof = structuredClone(vector.proofs[test.base_proof]);
  if (test.mutation === "bitmap_extra_bit") {
    const bitmap = unb64(proof.sibling_bitmap);
    let depth = 0;
    while (bitmapBit(bitmap, depth)) depth++;
    bitmap[Math.floor(depth / 8)] |= 0x80 >> (depth % 8);
    proof.sibling_bitmap = b64(bitmap);
  }
  if (test.mutation === "remove_sibling") proof.non_empty_siblings.pop();
  if (test.mutation === "alter_sibling") {
    const sibling = unb64(proof.non_empty_siblings[0]); sibling[0] ^= 1; proof.non_empty_siblings[0] = b64(sibling);
  }
  if (test.mutation === "replace_state_key") proof.state_key = b64(Buffer.alloc(32, 0xa5));
  if (test.mutation === "noncanonical_state_value") proof.state_value_jcs_base64url = b64(Buffer.from(JSON.stringify(proof.state_value, null, 2)));
  const actual = verifyProof(proof);
  if (actual !== test.expected) throw new Error(`Negative test returned ${actual}: ${test.mutation}`);
}

console.log(`Verified ${vector.vector_id}: 257 empty hashes, ${Object.keys(vector.proofs).length} proofs, ${vector.negative_tests.length} negative tests`);
