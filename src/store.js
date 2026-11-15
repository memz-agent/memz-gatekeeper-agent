"use strict";

const fs = require("fs");
const path = require("path");

/**
 * Seen-set for proof_tx references (the PROOF_REUSED trap: "the proof
 * reference has not already been used for another task") plus a
 * task_id -> serialized-response cache so a redelivered task is answered
 * idempotently instead of being misread as proof reuse.
 *
 * In-memory state is authoritative for the life of the process; a JSON file
 * backs it across restarts on a best-effort basis. On serverless hosts the
 * file lives in /tmp and may vanish on cold start — an accepted, documented
 * weakness of the free-tier deployment (a missed reuse detection costs one
 * task; a wrong APPROVE would cost far more, and the policy never approves
 * on uncertainty).
 */
class SeenStore {
  constructor(filePath) {
    this.filePath = filePath;
    this.seenProofTx = new Set();
    this.responseByTaskId = new Map();
    this.load();
  }

  load() {
    try {
      const raw = fs.readFileSync(this.filePath, "utf8");
      const data = JSON.parse(raw);
      for (const tx of data.proofTx ?? []) this.seenProofTx.add(normalizeTx(tx));
      for (const [k, v] of Object.entries(data.responses ?? {})) {
        this.responseByTaskId.set(k, v);
      }
    } catch {
      /* missing/corrupt file -> start empty */
    }
  }

  persist() {
    try {
      fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
      const tmp = `${this.filePath}.tmp`;
      fs.writeFileSync(
        tmp,
        JSON.stringify({
          proofTx: [...this.seenProofTx],
          responses: Object.fromEntries(this.responseByTaskId),
        }),
      );
      fs.renameSync(tmp, this.filePath);
    } catch (err) {
      console.error("[store] persist failed:", err.message);
    }
  }

  hasProofTx(proofTx) {
    return this.seenProofTx.has(normalizeTx(proofTx));
  }

  recordProofTx(proofTx) {
    const key = normalizeTx(proofTx);
    if (!key) return;
    if (!this.seenProofTx.has(key)) {
      this.seenProofTx.add(key);
      this.persist();
    }
  }

  getResponse(taskId) {
    return this.responseByTaskId.get(taskId) ?? null;
  }

  recordResponse(taskId, serializedResponse) {
    if (!this.responseByTaskId.has(taskId)) {
      this.responseByTaskId.set(taskId, serializedResponse);
      this.persist();
    }
  }

  get size() {
    return this.seenProofTx.size;
  }
}

function normalizeTx(tx) {
  return (tx ?? "").trim().toLowerCase();
}

module.exports = { SeenStore, normalizeTx };
