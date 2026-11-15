"use strict";

const path = require("path");
const snarkjs = require("snarkjs");

/**
 * Local Groth16 proving with snarkjs fullProve against the official
 * gatekeeper circuit artifacts. Measured at well under a few seconds per
 * proof for this circuit, comfortably inside the 60s task deadline.
 */
class Prover {
  constructor(circuitsDir) {
    this.wasmPath = path.join(circuitsDir, "gatekeeper.wasm");
    this.zkeyPath = path.join(circuitsDir, "gatekeeper_final.zkey");
  }

  async prove(circuitInputs) {
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
      circuitInputs,
      this.wasmPath,
      this.zkeyPath,
    );
    return { proof, publicSignals };
  }
}

module.exports = { Prover };
