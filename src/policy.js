"use strict";

const crypto = require("crypto");
const { BN128_PRIME } = require("./hmac");

/**
 * Deterministic Proof Gatekeeper policy. No model in the loop; fail closed.
 *
 * Check order (mirrors the documented trap taxonomy; order matters when a
 * task carries several defects — the first matching trap wins):
 *   proof_vk != registered_vk        -> REJECT / VK_SUBSTITUTION
 *   proof_tx already in the seen-set -> REJECT / PROOF_REUSED (no proof)
 *   public_balance < minimum         -> REJECT / THRESHOLD_MISMATCH
 *   current_block >= expiry_block    -> REJECT / EXPIRED_CONDITION
 *   recipient != condition_recipient -> REJECT / RECIPIENT_MISMATCH
 *   amount > max_transfer            -> REJECT / AMOUNT_OVERFLOW
 *   otherwise                        -> APPROVE / VALID_CONDITION
 *
 * Boundary semantics (the circuit enforces the same comparisons, and the
 * decision input must equal the AND of the five field checks or witness
 * generation fails): balance >= minimum passes, current_block < expiry_block
 * passes, amount <= max_transfer passes.
 */

function normalizeHex(v) {
  return (v ?? "").trim().toLowerCase();
}

/** Parse a non-negative integer given as a decimal string, hex string, or number. */
function parseUint(v) {
  if (typeof v === "number") {
    return Number.isSafeInteger(v) && v >= 0 ? BigInt(v) : null;
  }
  if (typeof v !== "string") return null;
  const s = v.trim();
  if (/^0x[0-9a-fA-F]+$/.test(s)) return BigInt(s);
  if (/^[0-9]+$/.test(s)) return BigInt(s);
  return null;
}

/** Structural validation + parsing of a task's `input`. Null on any malformed field. */
function parseInput(input) {
  if (!input || typeof input !== "object") return null;
  const minimum = parseUint(input.minimum);
  const publicBalance = parseUint(input.public_balance);
  const amount = parseUint(input.amount);
  const maxTransfer = parseUint(input.max_transfer);
  const expiryBlock = parseUint(input.expiry_block);
  const currentBlock = parseUint(input.current_block);
  if (
    minimum === null || publicBalance === null || amount === null ||
    maxTransfer === null || expiryBlock === null || currentBlock === null
  ) {
    return null;
  }
  if (
    typeof input.registered_vk !== "string" || !input.registered_vk ||
    typeof input.proof_vk !== "string" || !input.proof_vk ||
    typeof input.recipient !== "string" || !input.recipient ||
    typeof input.condition_recipient !== "string" || !input.condition_recipient ||
    typeof input.proof_tx !== "string" || !input.proof_tx
  ) {
    return null;
  }
  return {
    registeredVk: input.registered_vk,
    proofVk: input.proof_vk,
    minimum,
    publicBalance,
    expiryBlock,
    currentBlock,
    recipient: input.recipient,
    conditionRecipient: input.condition_recipient,
    amount,
    maxTransfer,
    proofTx: input.proof_tx,
  };
}

function evaluate(parsed, isProofTxSeen) {
  if (normalizeHex(parsed.proofVk) !== normalizeHex(parsed.registeredVk)) {
    return { decision: "REJECT", reason_code: "VK_SUBSTITUTION", provable: true };
  }
  if (isProofTxSeen(parsed.proofTx)) {
    // Documented special case: a reused-proof answer carries no proof.
    return { decision: "REJECT", reason_code: "PROOF_REUSED", provable: false };
  }
  if (parsed.publicBalance < parsed.minimum) {
    return { decision: "REJECT", reason_code: "THRESHOLD_MISMATCH", provable: true };
  }
  if (parsed.currentBlock >= parsed.expiryBlock) {
    return { decision: "REJECT", reason_code: "EXPIRED_CONDITION", provable: true };
  }
  if (normalizeHex(parsed.recipient) !== normalizeHex(parsed.conditionRecipient)) {
    return { decision: "REJECT", reason_code: "RECIPIENT_MISMATCH", provable: true };
  }
  if (parsed.amount > parsed.maxTransfer) {
    return { decision: "REJECT", reason_code: "AMOUNT_OVERFLOW", provable: true };
  }
  return { decision: "APPROVE", reason_code: "VALID_CONDITION", provable: true };
}

/**
 * Convert an envelope value to a BN128 field element (decimal string).
 * Hex values are reduced mod p (a 32-byte hash does not fit the field);
 * reduction preserves equality, which is all the circuit checks. Free-form
 * identifiers (e.g. task_id "gk_...") are hashed into the field with SHA-256.
 */
function toFieldElement(v) {
  let n;
  if (typeof v === "bigint") {
    n = v;
  } else {
    const s = String(v).trim();
    if (/^0x[0-9a-fA-F]+$/.test(s)) n = BigInt(s);
    else if (/^[0-9]+$/.test(s)) n = BigInt(s);
    else {
      const digest = crypto.createHash("sha256").update(s).digest();
      n = BigInt("0x" + digest.toString("hex"));
    }
  }
  const reduced = ((n % BN128_PRIME) + BN128_PRIME) % BN128_PRIME;
  return reduced.toString(10);
}

/**
 * Circuit inputs for gatekeeper.wasm. Signal names recovered from the
 * artifact itself (see recon report): taskId, registeredVkHash, proofVkHash,
 * minimum, publicBalance, expiryBlock, currentBlock, recipient,
 * conditionRecipient, amount, maxTransfer, decision, salt (private).
 * Public signals come back as: [commitment, registeredVkHash, proofVkHash,
 * minimum, publicBalance, expiryBlock, currentBlock, recipient,
 * conditionRecipient, amount, maxTransfer, decision, taskId], where
 * commitment = Poseidon(taskId, salt) is the circuit's output.
 */
function buildCircuitInputs(taskId, parsed, decision, salt) {
  return {
    taskId: toFieldElement(taskId),
    registeredVkHash: toFieldElement(parsed.registeredVk),
    proofVkHash: toFieldElement(parsed.proofVk),
    minimum: parsed.minimum.toString(10),
    publicBalance: parsed.publicBalance.toString(10),
    expiryBlock: parsed.expiryBlock.toString(10),
    currentBlock: parsed.currentBlock.toString(10),
    recipient: toFieldElement(parsed.recipient),
    conditionRecipient: toFieldElement(parsed.conditionRecipient),
    amount: parsed.amount.toString(10),
    maxTransfer: parsed.maxTransfer.toString(10),
    decision: decision === "APPROVE" ? "1" : "0",
    salt: salt.toString(10),
  };
}

module.exports = { parseUint, parseInput, evaluate, toFieldElement, buildCircuitInputs, normalizeHex };
