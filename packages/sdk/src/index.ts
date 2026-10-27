/**
 * Satoris client SDK.
 *
 *   const client = new SatorisClient({ baseUrl, signer, network, budget: "$5" });
 *   const { completion } = await client.sealedChat({ model, messages });
 *
 * - Payments: answers HTTP 402 automatically with a USDC payment from `signer`
 *   (x402 on Solana), bounded by a per-request cap and a session budget, so an
 *   autonomous agent can hold a scoped hot key without risking the main wallet.
 * - Privacy: `sealedChat` verifies the node's attestation itself with its own
 *   nonce (it does not trust the gateway), then encrypts the prompt to the key
 *   bound in that attestation. The gateway only ever relays ciphertext.
 */
import { x402Client } from "@x402/core/client";
import type { Network, PaymentRequirements } from "@x402/core/types";
import { decodePaymentResponseHeader, wrapFetchWithPayment } from "@x402/fetch";
import type { ClientSvmSigner } from "@x402/svm";
import { ExactSvmScheme } from "@x402/svm/exact/client";
import { UptoSvmScheme } from "@x402/svm/upto/client";
import {
  type AttestationEvidence,
  type AttestationPolicy,
  type PlatformVerifier,
  type TrustTier,
  newNonce,
  verifyAttestation,
} from "@satoris/attestation";
import {
  type ChatCompletionRequest,
  type ChatCompletionResponse,
  type SealedChatRequest,
  type SealedChatResponse,
  fromBase64,
  sealJson,
} from "@satoris/sealed";

export interface SatorisClientOptions {
  baseUrl: string;
  /** Solana signer paying for requests. Use a dedicated hot key for agents. */
  signer: ClientSvmSigner;
  network: Network;
  scheme?: "upto" | "exact";
  /** Largest single authorization, in USD (e.g. "$0.50"). Default "$1". */
  maxPerRequest?: `$${string}`;
  /** Total USD this client may authorize over its lifetime (e.g. "$5"). */
  budget?: `$${string}`;
  /** Required to use sealedChat: what the client accepts as a trustworthy node. */
  attestation?: { policy: AttestationPolicy; verifiers: PlatformVerifier[] };
  minTier?: Exclude<TrustTier, "untrusted">;
  fetch?: typeof fetch;
}

export interface ChatResult {
  completion: ChatCompletionResponse;
  receiptId: string | null;
  node: string | null;
  tier: string | null;
  /** Decoded x402 settlement (payer, transaction signature, amount). */
  payment: ReturnType<typeof decodePaymentResponseHeader> | null;
}

export interface NodeInfo {
  id: string;
  models: string[];
  live: boolean;
  tier: TrustTier;
  kid?: string;
  public_key?: string;
}

/**
 * Lifetime budget enforced client-side. Authorizations are reserved at their
 * maximum: with `upto` the actual charge is usually lower, so this errs safe.
 */
export class SessionBudget {
  private spent = 0n;

  constructor(readonly limitAtomic: bigint) {}

  get remainingAtomic(): bigint {
    return this.limitAtomic - this.spent;
  }

  filter = (_v: number, reqs: PaymentRequirements[]) => reqs.filter((r) => BigInt(r.amount) <= this.remainingAtomic);

  commit(amount: string) {
    this.spent += BigInt(amount);
  }
}

export class SatorisError extends Error {
  constructor(
    readonly status: number,
    message: string,
    readonly code?: string,
  ) {
    super(message);
  }
}

export class SatorisClient {
  private readonly baseUrl: string;
  private readonly rawFetch: typeof fetch;
  private readonly paidFetch: typeof fetch;
  readonly budget?: SessionBudget;

  constructor(private readonly opts: SatorisClientOptions) {
    this.baseUrl = opts.baseUrl.replace(/\/$/, "");
    this.rawFetch = opts.fetch ?? fetch;
    const scheme = opts.scheme ?? "upto";
    const client = x402Client.fromConfig({
      schemes: [
        {
          network: opts.network,
          client: scheme === "upto" ? new UptoSvmScheme(opts.signer) : new ExactSvmScheme(opts.signer),
        },
      ],
      spendControls: { maxAmountPerPayment: opts.maxPerRequest ?? "$1" },
    });
    if (opts.budget) {
      const budget = new SessionBudget(usdToAtomic(opts.budget));
      client.registerPolicy(budget.filter);
      client.onAfterPaymentCreation(async (ctx) => budget.commit(ctx.selectedRequirements.amount));
      this.budget = budget;
    }
    this.paidFetch = wrapFetchWithPayment(this.rawFetch, client);
  }

  private headers(): Record<string, string> {
    const h: Record<string, string> = { "content-type": "application/json" };
    if (this.opts.minTier) h["x-satoris-min-trust"] = this.opts.minTier;
    return h;
  }

  async models() {
    return this.getJson<{ data: Array<{ id: string; pricing: Record<string, string>; available_nodes: number }> }>(
      "/v1/models",
    );
  }

  async nodes(): Promise<NodeInfo[]> {
    return (await this.getJson<{ data: NodeInfo[] }>("/v1/nodes")).data;
  }

  async receipt(id: string) {
    return this.getJson<Record<string, unknown>>(`/v1/receipts/${id}`);
  }

  /** Standard path: TLS to the gateway, which forwards plaintext to an attested node. */
  async chat(request: ChatCompletionRequest): Promise<ChatResult> {
    const res = await this.paidFetch(`${this.baseUrl}/v1/chat/completions`, {
      method: "POST",
      headers: this.headers(),
      body: JSON.stringify({ ...request, stream: false }),
    });
    await this.throwIfError(res);
    return { completion: (await res.json()) as ChatCompletionResponse, ...this.meta(res) };
  }

  /**
   * End-to-end path: verify a node, seal the prompt to its attested key, and
   * decrypt the reply locally. The gateway never sees the prompt or completion.
   */
  async sealedChat(request: ChatCompletionRequest, options: { node?: string } = {}): Promise<ChatResult & { evidence: AttestationEvidence }> {
    if (!this.opts.attestation) throw new Error("sealedChat requires the `attestation` option");
    const maxTokens = request.max_completion_tokens ?? request.max_tokens;
    if (maxTokens === undefined) throw new Error("sealedChat requires max_tokens (it is billed in the clear)");

    const candidates = (await this.nodes()).filter(
      (n) => n.live && n.models.includes(request.model) && (!options.node || n.id === options.node),
    );
    if (candidates.length === 0) throw new SatorisError(503, `no live node serves ${request.model}`);

    let lastError: Error | undefined;
    for (const node of candidates) {
      const nonce = newNonce();
      const evidence = await this.getJson<AttestationEvidence>(`/v1/nodes/${node.id}/attestation?nonce=${nonce}`);
      const verdict = await verifyAttestation(evidence, { ...this.opts.attestation, expectedNonce: nonce });
      if (!verdict.ok) {
        lastError = new SatorisError(412, `node ${node.id} failed attestation: ${verdict.reasons.join("; ")}`);
        continue;
      }
      const meta = { model: request.model, max_tokens: maxTokens };
      const inner = { ...request, stream: false, max_tokens: maxTokens };
      const { envelope, reply } = await sealJson(inner, fromBase64(evidence.publicKey), meta);
      const body: SealedChatRequest = { meta, node: node.id, envelope };
      const res = await this.paidFetch(`${this.baseUrl}/v1/sealed/chat/completions`, {
        method: "POST",
        headers: this.headers(),
        body: JSON.stringify(body),
      });
      if (res.status === 409 || res.status === 503) {
        lastError = new SatorisError(res.status, "node rotated its key or went offline");
        continue;
      }
      await this.throwIfError(res);
      const sealed = (await res.json()) as SealedChatResponse;
      const completion = await reply.openJson<ChatCompletionResponse>(sealed.envelope);
      return { completion, evidence, ...this.meta(res) };
    }
    throw lastError ?? new SatorisError(503, "no node accepted the request");
  }

  private meta(res: Response) {
    const paymentHeader = res.headers.get("payment-response") ?? res.headers.get("x-payment-response");
    return {
      receiptId: res.headers.get("x-satoris-receipt-id"),
      node: res.headers.get("x-satoris-node"),
      tier: res.headers.get("x-satoris-trust-tier"),
      payment: paymentHeader ? decodePaymentResponseHeader(paymentHeader) : null,
    };
  }

  private async getJson<T>(path: string): Promise<T> {
    const res = await this.rawFetch(`${this.baseUrl}${path}`);
    await this.throwIfError(res);
    return (await res.json()) as T;
  }

  private async throwIfError(res: Response) {
    if (res.ok) return;
    let message = res.statusText;
    let code: string | undefined;
    try {
      const body = (await res.clone().json()) as { error?: { message?: string; type?: string } | string };
      if (typeof body.error === "string") message = body.error;
      else if (body.error?.message) {
        message = body.error.message;
        code = body.error.type;
      }
    } catch {
      // non-JSON error body
    }
    throw new SatorisError(res.status, message, code);
  }
}

export function usdToAtomic(usd: string): bigint {
  const m = /^\$?(\d+)(?:\.(\d{1,6}))?$/.exec(usd.trim());
  if (!m) throw new Error(`invalid USD amount ${usd}`);
  return BigInt(m[1]!) * 1_000_000n + BigInt((m[2] ?? "").padEnd(6, "0"));
}
