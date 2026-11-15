"use strict";

const fs = require("fs");
const path = require("path");

/**
 * Runtime configuration, all from environment variables. The HMAC secret has
 * NO default: it is the platform-generated secret from the AgentGames
 * dashboard (Rotate Secret), provided as AGENT_GAMES_HMAC_SECRET.
 */
function defaultCircuitsDir() {
  const candidates = [
    path.resolve(__dirname, "..", "circuits"),
    path.resolve(process.cwd(), "circuits"),
  ];
  for (const c of candidates) {
    if (fs.existsSync(path.join(c, "gatekeeper.wasm"))) return c;
  }
  return candidates[0];
}

function defaultSeenStorePath() {
  // Serverless filesystems are read-only except /tmp.
  if (process.env.VERCEL) return "/tmp/memz-gatekeeper-seen.json";
  return path.resolve(process.cwd(), "data", "seen.json");
}

function loadConfig(env = process.env) {
  return {
    hmacSecret: env.AGENT_GAMES_HMAC_SECRET ?? "",
    circuitsDir: env.CIRCUITS_DIR ?? defaultCircuitsDir(),
    seenStorePath: env.SEEN_STORE_PATH ?? defaultSeenStorePath(),
    port: Number(env.PORT ?? 8787),
  };
}

module.exports = { loadConfig };
