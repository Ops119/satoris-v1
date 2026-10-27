import {
  type AttestationEvidence,
  type AttestationPolicy,
  type PlatformVerifier,
  type TrustTier,
  newNonce,
  verifyAttestation,
} from "@satoris/attestation";
import { fromBase64, keyId } from "@satoris/sealed";

export interface NodeConfig {
  id: string;
  url: string;
  models: string[];
  /** Bearer token the node agent expects from this gateway. */
  authToken?: string;
  region?: string;
}

export interface NodeState {
  config: NodeConfig;
  tier: TrustTier;
  healthy: boolean;
  kid?: string;
  publicKey?: string;
  evidence?: AttestationEvidence;
  evidenceHash?: string;
  attestedAt?: number;
  reasons: string[];
  /** Exponentially weighted latency of recent requests, ms. */
  latencyMs: number;
}

export const TIER_RANK: Record<TrustTier, number> = { untrusted: 0, "tee-cpu": 1, "tee-gpu": 2 };

/**
 * Tracks which nodes are currently attested. Each refresh challenges every node
 * with a fresh nonce, so a replayed quote can't keep a compromised node live.
 * (MVP: static node list. Step 3 replaces it with the on-chain registry.)
 */
export class NodeRegistry {
  private readonly nodes = new Map<string, NodeState>();

  constructor(
    configs: NodeConfig[],
    private readonly policy: AttestationPolicy,
    private readonly verifiers: PlatformVerifier[],
    private readonly fetchImpl: typeof fetch = fetch,
  ) {
    for (const config of configs) {
      this.nodes.set(config.id, { config, tier: "untrusted", healthy: false, reasons: ["not yet attested"], latencyMs: 500 });
    }
  }

  list(): NodeState[] {
    return [...this.nodes.values()];
  }

  get(id: string): NodeState | undefined {
    return this.nodes.get(id);
  }

  /** A node is usable only while its last attestation is within the policy's freshness window. */
  isLive(node: NodeState, now = Date.now()): boolean {
    return node.healthy && node.tier !== "untrusted" && node.attestedAt !== undefined && now - node.attestedAt <= this.policy.maxAgeMs;
  }

  async refreshAll(): Promise<void> {
    await Promise.all([...this.nodes.keys()].map((id) => this.refresh(id)));
  }

  async refresh(id: string): Promise<NodeState> {
    const node = this.nodes.get(id);
    if (!node) throw new Error(`unknown node ${id}`);
    const nonce = newNonce();
    try {
      const res = await this.fetchImpl(`${node.config.url}/attestation?nonce=${nonce}`, {
        signal: AbortSignal.timeout(10_000),
      });
      if (!res.ok) throw new Error(`attestation endpoint returned ${res.status}`);
      const evidence = (await res.json()) as AttestationEvidence;
      const result = await verifyAttestation(evidence, {
        policy: this.policy,
        verifiers: this.verifiers,
        expectedNonce: nonce,
      });
      node.tier = result.tier;
      node.healthy = result.ok;
      node.reasons = result.reasons;
      node.evidence = evidence;
      node.evidenceHash = result.evidenceHash;
      node.publicKey = result.ok ? evidence.publicKey : undefined;
      node.kid = result.ok ? await keyId(fromBase64(evidence.publicKey)) : undefined;
      node.attestedAt = result.ok ? Date.now() : undefined;
    } catch (err) {
      node.healthy = false;
      node.tier = "untrusted";
      node.reasons = [(err as Error).message];
      node.attestedAt = undefined;
    }
    return node;
  }

  recordLatency(id: string, ms: number) {
    const node = this.nodes.get(id);
    if (node) node.latencyMs = node.latencyMs * 0.8 + ms * 0.2;
  }

  markUnhealthy(id: string, reason: string) {
    const node = this.nodes.get(id);
    if (node) {
      node.healthy = false;
      node.reasons = [reason];
    }
  }
}

export interface RouteRequest {
  model: string;
  minTier: TrustTier;
  /** Sealed requests are pinned to the node whose key the client encrypted to. */
  pinnedNode?: string;
  pinnedKid?: string;
}

/**
 * Picks a node: must serve the model, be freshly attested at or above the
 * requested tier; among those prefer the higher tier, then the faster node.
 * (Price is a catalog constant in the MVP, so it doesn't factor in yet.)
 */
export function selectNode(registry: NodeRegistry, req: RouteRequest, now = Date.now()): NodeState | undefined {
  const candidates = registry.list().filter((n) => {
    if (!registry.isLive(n, now)) return false;
    if (!n.config.models.includes(req.model)) return false;
    if (TIER_RANK[n.tier] < TIER_RANK[req.minTier]) return false;
    if (req.pinnedNode && n.config.id !== req.pinnedNode) return false;
    if (req.pinnedKid && n.kid !== req.pinnedKid) return false;
    return true;
  });
  candidates.sort((a, b) => TIER_RANK[b.tier] - TIER_RANK[a.tier] || a.latencyMs - b.latencyMs);
  return candidates[0];
}
