"use strict";

/**
 * Vercel serverless entry for the registered agent endpoint.
 * Deployed path: POST/GET https://<project>.vercel.app/agent
 *
 * bodyParser is disabled so the handler receives the RAW request body —
 * the HMAC signature is computed over exactly those bytes.
 */
const { loadConfig } = require("../src/config");
const { AgentHandler, SIGNATURE_HEADER } = require("../src/handler");
const { SeenStore } = require("../src/store");

const MAX_BODY_BYTES = 1_048_576;

// Instantiate once per function container so the in-memory seen-set and
// response cache survive across warm invocations.
let handler = null;
function getHandler() {
  if (!handler) {
    const cfg = loadConfig();
    handler = new AgentHandler(cfg, new SeenStore(cfg.seenStorePath));
  }
  return handler;
}

module.exports = async function agent(req, res) {
  const h = getHandler();

  if (req.method === "GET") {
    const r = h.health();
    res.status(r.status).setHeader("content-type", "application/json");
    res.send(r.body);
    return;
  }

  if (req.method !== "POST") {
    res.status(405).setHeader("content-type", "application/json");
    res.send(JSON.stringify({ error: "method_not_allowed" }));
    return;
  }

  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BODY_BYTES) {
      res.status(413).setHeader("content-type", "application/json");
      res.send(JSON.stringify({ error: "payload_too_large" }));
      return;
    }
    chunks.push(chunk);
  }
  const rawBody = Buffer.concat(chunks);
  const signature = req.headers[SIGNATURE_HEADER];
  const result = await h.handlePost(
    rawBody,
    Array.isArray(signature) ? signature[0] : signature,
  );
  res.status(result.status).setHeader("content-type", "application/json");
  if (result.signature) res.setHeader(SIGNATURE_HEADER, result.signature);
  res.send(result.body);
};

module.exports.config = {
  api: { bodyParser: false },
};
