import { serve } from "@hono/node-server";
import { HTTPFacilitatorClient } from "@x402/core/server";
import { x402ResourceServer } from "@x402/hono";
import { ExactSvmScheme } from "@x402/svm/exact/server";
import { UptoSvmScheme } from "@x402/svm/upto/server";
import { DevInsecureVerifier, type PlatformVerifier } from "@satoris/attestation";
import { MemoryReceiptStore, NodeRegistry, createGateway, loadConfig } from "./index.js";

const cfg = loadConfig(process.env.SATORIS_CONFIG ?? "gateway.config.json");

// Vendor verifiers (Intel DCAP for TDX, AMD KDS for SEV-SNP, NVIDIA NRAS for GPUs)
// plug in here; see docs/ARCHITECTURE.md. Dev verifier only counts if policy allows it.
const verifiers: PlatformVerifier[] = [];
if (cfg.policy.allowedPlatforms.includes("dev-insecure")) {
  console.warn("[gateway] dev-insecure attestation is allowed: never run this config in production");
  verifiers.push(new DevInsecureVerifier());
}

const resourceServer = new x402ResourceServer(new HTTPFacilitatorClient({ url: cfg.facilitatorUrl })).register(
  cfg.payment.network,
  cfg.payment.scheme === "upto" ? new UptoSvmScheme() : new ExactSvmScheme(),
);

const registry = new NodeRegistry(cfg.nodes, cfg.policy, verifiers);
await registry.refreshAll();
setInterval(() => void registry.refreshAll(), cfg.attestationIntervalMs).unref();

const app = createGateway({
  pricing: cfg.pricing,
  registry,
  receipts: new MemoryReceiptStore(),
  payment: cfg.payment,
  resourceServer,
  minTier: cfg.minTier,
});

serve({ fetch: app.fetch, port: cfg.port });
const live = registry.list().filter((n) => registry.isLive(n)).length;
console.log(`[gateway] listening on :${cfg.port}, ${live}/${cfg.nodes.length} nodes attested`);
