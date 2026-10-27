import { type Usage, sha256, toHex } from "@satoris/sealed";
import type { TrustTier } from "@satoris/attestation";

/**
 * A job receipt. It holds hashes and metering only, never prompts or
 * completions. For sealed requests even the hashes are over ciphertext.
 * Receipts are batched into a Merkle tree whose root is anchored on Solana, so
 * a client can later prove "this attested node served this job for this price".
 */
export interface Receipt {
  id: string;
  version: 1;
  createdAt: number;
  nodeId: string;
  model: string;
  tier: TrustTier;
  evidenceHash: string;
  sealed: boolean;
  requestHash: string;
  responseHash: string;
  usage: Usage;
  maxAtomic: string;
  chargedAtomic: string;
  network: string;
  status: "pending" | "settled" | "failed";
  payer?: string;
  transaction?: string;
  settledAtomic?: string;
}

export interface ReceiptStore {
  put(receipt: Receipt): Promise<void>;
  get(id: string): Promise<Receipt | undefined>;
  update(id: string, patch: Partial<Receipt>): Promise<Receipt | undefined>;
  /** Settled receipts not yet included in an anchored batch. */
  listUnanchored(limit: number): Promise<Receipt[]>;
  markAnchored(ids: string[], signature: string): Promise<void>;
}

export class MemoryReceiptStore implements ReceiptStore {
  private readonly receipts = new Map<string, Receipt>();
  private readonly anchored = new Set<string>();

  async put(receipt: Receipt) {
    this.receipts.set(receipt.id, receipt);
  }

  async get(id: string) {
    return this.receipts.get(id);
  }

  async update(id: string, patch: Partial<Receipt>) {
    const current = this.receipts.get(id);
    if (!current) return undefined;
    const next = { ...current, ...patch };
    this.receipts.set(id, next);
    return next;
  }

  async listUnanchored(limit: number) {
    const out: Receipt[] = [];
    for (const r of this.receipts.values()) {
      if (out.length >= limit) break;
      if (r.status === "settled" && !this.anchored.has(r.id)) out.push(r);
    }
    return out;
  }

  async markAnchored(ids: string[]) {
    for (const id of ids) this.anchored.add(id);
  }
}

/** Leaf = sha256 over a fixed-order serialization of the receipt's committed fields. */
export async function receiptLeaf(r: Receipt): Promise<Uint8Array> {
  return sha256(
    JSON.stringify([
      r.version,
      r.id,
      r.createdAt,
      r.nodeId,
      r.model,
      r.evidenceHash,
      r.requestHash,
      r.responseHash,
      r.usage.prompt_tokens,
      r.usage.completion_tokens,
      r.settledAtomic ?? r.chargedAtomic,
      r.network,
      r.payer ?? "",
      r.transaction ?? "",
    ]),
  );
}

/** Binary Merkle root (sha256, odd node promoted). Matches the on-chain verifier's ordering. */
export async function merkleRoot(leaves: Uint8Array[]): Promise<Uint8Array> {
  if (leaves.length === 0) return new Uint8Array(32);
  let level = leaves;
  while (level.length > 1) {
    const next: Uint8Array[] = [];
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i]!;
      const right = level[i + 1];
      if (!right) {
        next.push(left);
        continue;
      }
      const buf = new Uint8Array(64);
      buf.set(left, 0);
      buf.set(right, 32);
      next.push(await sha256(buf));
    }
    level = next;
  }
  return level[0]!;
}

/** Posts a batch root on-chain. Implemented by the Solana client in step 2. */
export interface ReceiptAnchor {
  anchor(batch: { root: string; count: number; firstAt: number; lastAt: number }): Promise<string>;
}

export async function anchorPending(store: ReceiptStore, anchor: ReceiptAnchor, batchSize = 1024) {
  const batch = await store.listUnanchored(batchSize);
  if (batch.length === 0) return undefined;
  const root = toHex(await merkleRoot(await Promise.all(batch.map(receiptLeaf))));
  const signature = await anchor.anchor({
    root,
    count: batch.length,
    firstAt: Math.min(...batch.map((r) => r.createdAt)),
    lastAt: Math.max(...batch.map((r) => r.createdAt)),
  });
  // Only mark after the transaction lands, so a failed anchor is retried next round.
  await store.markAnchored(
    batch.map((r) => r.id),
    signature,
  );
  return { root, count: batch.length, signature };
}
