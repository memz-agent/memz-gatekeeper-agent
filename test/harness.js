"use strict";

/**
 * Local test harness: boots the agent server with a throwaway secret and
 * exercises the full protocol surface — health, bad signature, preflight,
 * a valid task, every documented trap, proof reuse, and idempotent
 * redelivery — verifying every Groth16 proof locally with snarkjs.
 */
const { spawn } = require("child_process");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const snarkjs = require("snarkjs");

const PORT = 8899;
const BASE = `http://127.0.0.1:${PORT}`;
const SECRET = "test-secret-for-local-harness";
const SEEN = "/tmp/memz-gatekeeper-test-seen.json";
const VKEY = JSON.parse(
  fs.readFileSync(path.resolve(__dirname, "..", "circuits", "verification_key.json"), "utf8"),
);

let passed = 0;
let failed = 0;
function check(name, cond, extra = "") {
  if (cond) {
    passed++;
    console.log(`  PASS  ${name}`);
  } else {
    failed++;
    console.log(`  FAIL  ${name} ${extra}`);
  }
}

function sign(body) {
  return crypto.createHmac("sha256", SECRET).update(body).digest("hex");
}

async function post(body, { badSig = false } = {}) {
  const raw = typeof body === "string" ? body : JSON.stringify(body);
  const res = await fetch(`${BASE}/agent`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-agent-games-signature": badSig ? "0".repeat(64) : sign(raw),
    },
    body: raw,
  });
  const text = await res.text();
  return { status: res.status, text, json: JSON.parse(text), sig: res.headers.get("x-agent-games-signature") };
}

function verifyResponseSig(r) {
  return r.sig === sign(r.text);
}

const VK = "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";
const VK_OTHER = "0x1111111111111111111111111111111111111111111111111111111111111111";
const ADDR_A = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const ADDR_B = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

let txCounter = 0;
function makeTask(overrides = {}, inputOverrides = {}) {
  txCounter++;
  const now = Date.now();
  return {
    type: "agent-games.proof-gatekeeper.v1",
    task_id: `gk_test_${txCounter}_${Math.random().toString(36).slice(2, 8)}`,
    mode: "practice",
    issued_at: new Date(now).toISOString(),
    deadline_at: new Date(now + 60_000).toISOString(),
    input: {
      registered_vk: VK,
      proof_vk: VK,
      minimum: "1000",
      public_balance: "1460",
      expiry_block: 8430000,
      current_block: 8420000,
      recipient: ADDR_A,
      condition_recipient: ADDR_A,
      amount: "500",
      max_transfer: "1000",
      proof_tx: "0x" + txCounter.toString(16).padStart(64, "0"),
      ...inputOverrides,
    },
    ...overrides,
  };
}

async function expectDecision(name, task, decision, reason, { withProof = true } = {}) {
  const t0 = Date.now();
  const r = await post(task);
  const ms = Date.now() - t0;
  check(`${name}: HTTP 200`, r.status === 200, `got ${r.status}`);
  check(`${name}: decision ${decision}`, r.json.decision === decision, JSON.stringify(r.json));
  check(`${name}: reason ${reason}`, r.json.reason_code === reason, JSON.stringify(r.json));
  check(`${name}: response signed`, verifyResponseSig(r));
  if (withProof) {
    check(`${name}: proof present`, !!r.json.proof && Array.isArray(r.json.public_signals));
    check(`${name}: 13 public signals`, r.json.public_signals?.length === 13,
      `got ${r.json.public_signals?.length}`);
    const decisionSignal = r.json.public_signals?.[11];
    check(`${name}: decision signal`, decisionSignal === (decision === "APPROVE" ? "1" : "0"),
      `got ${decisionSignal}`);
    const ok = await snarkjs.groth16.verify(VKEY, r.json.public_signals, r.json.proof);
    check(`${name}: proof verifies locally`, ok === true);
  } else {
    check(`${name}: no proof attached`, !r.json.proof);
  }
  console.log(`        (${ms} ms)`);
  return r;
}

async function main() {
  try { fs.unlinkSync(SEEN); } catch {}
  const child = spawn("node", ["server.js"], {
    cwd: path.resolve(__dirname, ".."),
    env: {
      ...process.env,
      PORT: String(PORT),
      AGENT_GAMES_HMAC_SECRET: SECRET,
      SEEN_STORE_PATH: SEEN,
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  child.stderr.on("data", (d) => process.stderr.write(`[server] ${d}`));

  try {
    // Wait for the server to come up.
    let up = false;
    for (let i = 0; i < 50 && !up; i++) {
      try {
        const res = await fetch(`${BASE}/agent`);
        up = res.status === 200;
      } catch {
        await new Promise((r) => setTimeout(r, 200));
      }
    }
    if (!up) throw new Error("server did not come up");

    console.log("== health ==");
    const health = await (await fetch(`${BASE}/agent`)).json();
    check("GET /agent returns ok/v1", health.ok === true && health.protocolVersion === "v1");

    console.log("== bad signature ==");
    const bad = await post(makeTask(), { badSig: true });
    check("bad signature -> 401", bad.status === 401, `got ${bad.status}`);

    console.log("== preflight ==");
    const pre = await post({
      type: "agent-games.preflight.v1",
      agent_id: "agt_test",
      issued_at: new Date().toISOString(),
      nonce: "abc123",
    });
    check("preflight HTTP 200", pre.status === 200);
    check("preflight body shape", pre.json.ok === true && pre.json.protocolVersion === "v1",
      JSON.stringify(pre.json));
    check("preflight response signed", verifyResponseSig(pre));

    console.log("== gatekeeper tasks ==");
    const valid = makeTask();
    await expectDecision("valid condition", valid, "APPROVE", "VALID_CONDITION");

    await expectDecision("vk substitution", makeTask({}, { proof_vk: VK_OTHER }),
      "REJECT", "VK_SUBSTITUTION");
    await expectDecision("threshold mismatch", makeTask({}, { public_balance: "999" }),
      "REJECT", "THRESHOLD_MISMATCH");
    await expectDecision("expired condition", makeTask({}, { current_block: 8430000 }),
      "REJECT", "EXPIRED_CONDITION");
    await expectDecision("recipient mismatch", makeTask({}, { condition_recipient: ADDR_B }),
      "REJECT", "RECIPIENT_MISMATCH");
    await expectDecision("amount overflow", makeTask({}, { amount: "1001" }),
      "REJECT", "AMOUNT_OVERFLOW");

    console.log("== proof reuse ==");
    const first = makeTask();
    await expectDecision("reuse: first use", first, "APPROVE", "VALID_CONDITION");
    const second = makeTask({}, { proof_tx: first.input.proof_tx });
    await expectDecision("reuse: second use", second, "REJECT", "PROOF_REUSED", { withProof: false });

    console.log("== idempotent redelivery ==");
    const replay = await post(valid);
    check("redelivery returns 200", replay.status === 200);
    check("redelivery body identical", replay.json.decision === "APPROVE" &&
      replay.json.reason_code === "VALID_CONDITION");
  } finally {
    child.kill("SIGTERM");
  }

  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
