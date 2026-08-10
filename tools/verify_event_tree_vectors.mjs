#!/usr/bin/env node

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

const path = process.argv[2] ?? "test-vectors/event-tree.json";
const vector = JSON.parse(readFileSync(path, "utf8"));
const b64 = (bytes) => Buffer.from(bytes).toString("base64url");
const unb64 = (value) => Buffer.from(value, "base64url");
const hash = (...parts) => createHash("sha256").update(Buffer.concat(parts.map((p) => Buffer.from(p)))).digest();
const EMPTY = Buffer.from("XCIM-EVENT-EMPTY-0.1\0");
const LEAF = Buffer.from("XCIM-EVENT-LEAF-0.1\0");
const NODE = Buffer.from("XCIM-MERKLE-NODE-0.1\0");

const canonicalize = (value) => {
  if (value === null || typeof value === "boolean" || typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) throw new Error("Safe integers only");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(",")}}`;
};
const leafHash = (event) => hash(LEAF, Buffer.from(canonicalize(event)));
const nodeHash = (left, right) => hash(NODE, left, right);
const split = (size) => 2 ** Math.floor(Math.log2(size - 1));
const root = (leaves) => {
  if (leaves.length === 0) return hash(EMPTY);
  if (leaves.length === 1) return leaves[0];
  const k = split(leaves.length);
  return nodeHash(root(leaves.slice(0, k)), root(leaves.slice(k)));
};
const appendFrontier = (frontier, leaf) => {
  let height = 0;
  let carry = leaf;
  while (height < frontier.length && frontier[height] !== null) {
    carry = nodeHash(frontier[height], carry);
    frontier[height] = null;
    height++;
  }
  frontier[height] = carry;
};
const frontierRoot = (frontier) => {
  let accumulator = null;
  for (let height = frontier.length - 1; height >= 0; height--) {
    if (frontier[height] !== null) accumulator = accumulator === null ? frontier[height] : nodeHash(accumulator, frontier[height]);
  }
  return accumulator ?? hash(EMPTY);
};

const verifyInclusion = (leaf, proof, trustedRoot) => {
  if (!Number.isSafeInteger(proof.tree_size) || !Number.isSafeInteger(proof.leaf_index) ||
      proof.tree_size < 1 || proof.leaf_index < 0 || proof.leaf_index >= proof.tree_size) return false;
  let cursor = 0;
  const rebuild = (index, size) => {
    if (size === 1) return leaf;
    const k = split(size);
    if (index < k) {
      const left = rebuild(index, k);
      if (cursor >= proof.path.length) throw new Error("short path");
      return nodeHash(left, unb64(proof.path[cursor++]));
    }
    const right = rebuild(index - k, size - k);
    if (cursor >= proof.path.length) throw new Error("short path");
    return nodeHash(unb64(proof.path[cursor++]), right);
  };
  try {
    const candidate = rebuild(proof.leaf_index, proof.tree_size);
    const claimedRoot = unb64(proof.event_root);
    return cursor === proof.path.length && claimedRoot.equals(trustedRoot) && candidate.equals(trustedRoot);
  } catch { return false; }
};

const verifyConsistency = (proof) => {
  const m = proof.old_tree_size;
  const n = proof.new_tree_size;
  const oldRoot = unb64(proof.old_root);
  const newRoot = unb64(proof.new_root);
  if (!Number.isSafeInteger(m) || !Number.isSafeInteger(n) || m < 0 || m > n) return false;
  if (m === 0) return proof.path.length === 0 && oldRoot.equals(hash(EMPTY));
  if (m === n) return proof.path.length === 0 && oldRoot.equals(newRoot);
  let fn = m - 1;
  let sn = n - 1;
  while ((fn & 1) === 1) { fn >>= 1; sn >>= 1; }
  let cursor = 0;
  let first;
  if ((m & (m - 1)) === 0) first = oldRoot;
  else {
    if (cursor >= proof.path.length) return false;
    first = unb64(proof.path[cursor++]);
  }
  let fr = first;
  let sr = first;
  for (; cursor < proof.path.length; cursor++) {
    const sibling = unb64(proof.path[cursor]);
    if (sn === 0) return false;
    if ((fn & 1) === 1 || fn === sn) {
      fr = nodeHash(sibling, fr);
      sr = nodeHash(sibling, sr);
      while (fn !== 0 && (fn & 1) === 0) { fn >>= 1; sn >>= 1; }
    } else {
      sr = nodeHash(sr, sibling);
    }
    fn >>= 1;
    sn >>= 1;
  }
  return sn === 0 && fr.equals(oldRoot) && sr.equals(newRoot);
};

const leaves = vector.events.map(leafHash);
vector.leaf_hashes.forEach((expected, i) => { if (b64(leaves[i]) !== expected) throw new Error(`Leaf ${i} mismatch`); });
vector.roots.forEach(({ tree_size, root: expected }) => { if (b64(root(leaves.slice(0, tree_size))) !== expected) throw new Error(`Root ${tree_size} mismatch`); });
const frontier = [];
vector.incremental_roots.forEach((item, size) => {
  if (size > 0) appendFrontier(frontier, leaves[size - 1]);
  const encoded = frontier.map((node) => node === null ? null : b64(node));
  if (JSON.stringify(encoded) !== JSON.stringify(item.frontier) || b64(frontierRoot(frontier)) !== item.root || item.tree_size !== size) {
    throw new Error(`Incremental frontier ${size} mismatch`);
  }
});
const trustedRoots = new Map(vector.roots.map((item) => [item.tree_size, unb64(item.root)]));
vector.inclusion_proofs.forEach((proof) => {
  if (!verifyInclusion(leaves[proof.leaf_index], proof, trustedRoots.get(proof.tree_size))) throw new Error(`Invalid inclusion ${proof.tree_size}/${proof.leaf_index}`);
});
vector.consistency_proofs.forEach((proof) => { if (!verifyConsistency(proof)) throw new Error(`Invalid consistency ${proof.old_tree_size}/${proof.new_tree_size}`); });

for (const test of vector.negative_tests) {
  let accepted;
  if (test.base_inclusion_case !== undefined) {
    const proof = structuredClone(vector.inclusion_proofs[test.base_inclusion_case]);
    if (test.mutation === "flip_first_sibling_bit") { const x = unb64(proof.path[0]); x[0] ^= 1; proof.path[0] = b64(x); }
    if (test.mutation === "increment_tree_size") proof.tree_size++;
    if (test.mutation === "leaf_index_out_of_range") proof.leaf_index = proof.tree_size;
    accepted = verifyInclusion(leaves[vector.inclusion_proofs[test.base_inclusion_case].leaf_index], proof, trustedRoots.get(proof.tree_size));
  } else {
    const proof = structuredClone(vector.consistency_proofs[test.base_consistency_case]);
    proof.old_root = b64(Buffer.alloc(32, 0xa5));
    accepted = verifyConsistency(proof);
  }
  if (accepted !== test.expected) throw new Error(`Negative test unexpectedly returned ${accepted}: ${test.mutation}`);
}

console.log(`Verified ${vector.vector_id}: ${vector.roots.length} roots, ${vector.inclusion_proofs.length} inclusion proofs, ${vector.consistency_proofs.length} consistency proofs, ${vector.negative_tests.length} negative tests`);
