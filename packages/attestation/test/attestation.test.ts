import { describe, expect, it } from "vitest";
import { generateNodeKeyPair, toBase64 } from "@satoris/sealed";
import {
  type AttestationPolicy,
  DevInsecureVerifier,
  createDevEvidence,
  newNonce,
  verifyAttestation,
} from "../src/index.js";

const MEASUREMENT = "ab".repeat(48);
const policy: AttestationPolicy = {
  allowedPlatforms: ["dev-insecure"],
  allowedMeasurements: [MEASUREMENT],
  allowedTcbStatus: ["UpToDate"],
  maxAgeMs: 60_000,
  requireGpuAttestation: false,
  allowDebug: false,
};
const verifiers = [new DevInsecureVerifier()];

async function evidence(opts: { gpu?: boolean; measurement?: string; now?: number } = {}) {
  const { publicKey } = await generateNodeKeyPair();
  const nonce = newNonce();
  const ev = await createDevEvidence({ publicKey, nonce, measurement: opts.measurement ?? MEASUREMENT, gpu: opts.gpu, now: opts.now });
  return { ev, nonce };
}

describe("verifyAttestation", () => {
  it("accepts fresh evidence that binds the key and nonce", async () => {
    const { ev, nonce } = await evidence();
    const r = await verifyAttestation(ev, { policy, verifiers, expectedNonce: nonce });
    expect(r).toMatchObject({ ok: true, tier: "tee-cpu" });
    expect(r.evidenceHash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("assigns the GPU tier only with GPU evidence", async () => {
    const { ev } = await evidence({ gpu: true });
    expect((await verifyAttestation(ev, { policy, verifiers })).tier).toBe("tee-gpu");
    const { ev: cpuOnly } = await evidence();
    const r = await verifyAttestation(cpuOnly, { policy: { ...policy, requireGpuAttestation: true }, verifiers });
    expect(r.ok).toBe(false);
  });

  it("rejects a replayed nonce, stale evidence and unknown images", async () => {
    const { ev } = await evidence();
    expect((await verifyAttestation(ev, { policy, verifiers, expectedNonce: newNonce() })).reasons).toContain("nonce mismatch");

    const { ev: old } = await evidence({ now: Date.now() - 120_000 });
    expect((await verifyAttestation(old, { policy, verifiers })).reasons).toContain("evidence is stale");

    const { ev: rogue } = await evidence({ measurement: "cd".repeat(48) });
    expect((await verifyAttestation(rogue, { policy, verifiers })).ok).toBe(false);
  });

  it("rejects a quote whose report_data binds a different key", async () => {
    const { ev } = await evidence();
    const attacker = await generateNodeKeyPair();
    const swapped = { ...ev, publicKey: toBase64(attacker.publicKey) };
    const r = await verifyAttestation(swapped, { policy, verifiers });
    expect(r.ok).toBe(false);
    expect(r.reasons).toContain("report_data does not bind the sealing key and nonce");
  });

  it("ignores dev evidence unless the policy opts in", async () => {
    const { ev } = await evidence();
    const r = await verifyAttestation(ev, { policy: { ...policy, allowedPlatforms: ["intel-tdx"] }, verifiers });
    expect(r.ok).toBe(false);
  });
});
