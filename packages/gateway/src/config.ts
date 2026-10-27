import { readFileSync } from "node:fs";
import { type AttestationPolicy, DEFAULT_POLICY, type TrustTier } from "@satoris/attestation";
import type { PaymentConfig } from "./app.js";
import type { PricingConfig } from "./pricing.js";
import type { NodeConfig } from "./registry.js";

export interface GatewayFileConfig {
  port: number;
  facilitatorUrl: string;
  payment: PaymentConfig;
  pricing: PricingConfig;
  nodes: NodeConfig[];
  policy: Partial<AttestationPolicy> & Pick<AttestationPolicy, "allowedMeasurements">;
  minTier: TrustTier;
  /** How often to re-challenge every node, ms. Must be below policy.maxAgeMs. */
  attestationIntervalMs: number;
}

/** Loads JSON config; `${ENV_VAR}` strings are substituted so secrets stay out of the file. */
export function loadConfig(path: string): GatewayFileConfig & { policy: AttestationPolicy } {
  const raw = readFileSync(path, "utf8").replace(/\$\{([A-Z0-9_]+)\}/g, (_, name: string) => {
    const value = process.env[name];
    if (value === undefined) throw new Error(`config references unset env var ${name}`);
    return value;
  });
  const cfg = JSON.parse(raw) as GatewayFileConfig;
  const policy: AttestationPolicy = { ...DEFAULT_POLICY, ...cfg.policy };
  if (cfg.attestationIntervalMs >= policy.maxAgeMs) {
    throw new Error("attestationIntervalMs must be shorter than policy.maxAgeMs or nodes will flap");
  }
  return { ...cfg, policy };
}
