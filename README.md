# memz-gatekeeper-agent

A Proof Gatekeeper agent for the [zkVerify AgentGames](https://agentgames.zkverify.io)
competition, entered by [@njmfdln](https://x.com/njmfdln) (memz.ai).

The agent receives proof-backed payment conditions from the platform,
decides **APPROVE** or **REJECT** deterministically, and backs every decision
with a locally generated Groth16 proof (BN128, via
[snarkjs](https://github.com/iden3/snarkjs)) produced with the official
gatekeeper circuit — the circuit itself asserts that the decision equals the
AND of the five field checks, so a wrong decision is unprovable.

## How it works

```
POST /agent   (HMAC-SHA256 over the raw body, header x-agent-games-signature)
  1. Verify the signature BEFORE parsing the body          -> 401 on mismatch
  2. type = agent-games.preflight.v1                       -> signed { ok: true, protocolVersion: "v1" }
  3. type = agent-games.proof-gatekeeper.v1
       idempotent replay of a redelivered task_id
       deadline sanity check
       deterministic policy (below)
       local Groth16 proof (except PROOF_REUSED)
       signed response
GET /agent    health check { ok: true, protocolVersion: "v1" }
```

### Policy (fail closed — any doubt is a REJECT)

| Check | Failure result |
| --- | --- |
| `proof_vk != registered_vk` | REJECT · `VK_SUBSTITUTION` |
| `proof_tx` already in the seen-set | REJECT · `PROOF_REUSED` (no proof attached, per spec) |
| `public_balance < minimum` | REJECT · `THRESHOLD_MISMATCH` |
| `current_block >= expiry_block` | REJECT · `EXPIRED_CONDITION` |
| `recipient != condition_recipient` | REJECT · `RECIPIENT_MISMATCH` |
| `amount > max_transfer` | REJECT · `AMOUNT_OVERFLOW` |
| all checks pass | APPROVE · `VALID_CONDITION` |

Circuit inputs (signal names recovered from the published WASM):
`taskId, registeredVkHash, proofVkHash, minimum, publicBalance, expiryBlock,
currentBlock, recipient, conditionRecipient, amount, maxTransfer, decision,
salt` — with a deterministic per-task salt derived from the agent secret, so
redeliveries reproduce identical proof inputs.

## Layout

| Path | Purpose |
| --- | --- |
| `api/agent.js` | Vercel serverless entry (`bodyParser: false` → raw body for HMAC) |
| `server.js` | Plain Node HTTP server for local / non-serverless hosting |
| `src/handler.js` | Protocol pipeline: auth → preflight → task → proof → signed reply |
| `src/policy.js` | Deterministic decision logic + circuit input encoding |
| `src/hmac.js` | HMAC-SHA256 sign/verify (hex out; hex/base64 in), salt derivation |
| `src/prover.js` | snarkjs `fullProve` wrapper |
| `src/store.js` | proof_tx seen-set + response cache (in-memory, file-backed) |
| `circuits/` | Official gatekeeper artifacts (`gatekeeper.wasm`, `gatekeeper_final.zkey`, `verification_key.json`) |
| `test/harness.js` | Local end-to-end tests: every trap + proof verification |

## Configuration

| Env var | Required | Notes |
| --- | --- | --- |
| `AGENT_GAMES_HMAC_SECRET` | yes | Platform-generated; dashboard → agent → **Rotate Secret**, shown exactly once. Never commit it. |
| `CIRCUITS_DIR` | no | Defaults to `./circuits` |
| `SEEN_STORE_PATH` | no | Defaults to `data/seen.json`, `/tmp/…` on Vercel |
| `PORT` | no | Plain-server port, default 8787 |

## Run / test / deploy

```bash
npm install
AGENT_GAMES_HMAC_SECRET=<secret> npm start     # plain server on :8787
npm test                                       # boots a test server, runs the full trap suite
```

Deployed on Vercel: `api/agent.js` is the function, `vercel.json` bundles
`circuits/**` into it and raises the duration limit to 60s. Register the
**full handler path** (`https://<host>/agent`, not the root) in the AgentGames
dashboard, rotate the secret into the Vercel env var, redeploy, and let the
platform preflight run.

### Known limitation

The seen-set persists to a JSON file; on serverless it lives in `/tmp` and
can reset on cold start, which could miss a proof-reuse trap in the worst
case. All other checks are stateless and unaffected.
