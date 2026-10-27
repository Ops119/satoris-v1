import { Hono, type Context } from "hono";
import { paymentMiddleware, setSettlementOverrides, type x402ResourceServer } from "@x402/hono";
import type { HTTPTransportContext, RoutesConfig } from "@x402/core/http";
import type { Network } from "@x402/core/types";
import { getUsdcAddress } from "@x402/svm";
import type { TrustTier } from "@satoris/attestation";
import {
  type ChatCompletionResponse,
  type SealedChatRequest,
  type SealedChatResponse,
  type Usage,
  sha256,
  toHex,
} from "@satoris/sealed";
import { type PricingConfig, type Quote, QuoteError, costAtomic, quoteChat, quoteSealed } from "./pricing.js";
import { type NodeRegistry, type NodeState, TIER_RANK, selectNode } from "./registry.js";
import type { Receipt, ReceiptStore } from "./receipts.js";

export interface PaymentConfig {
  network: Network;
  /** Treasury / escrow address that receives USDC. */
  payTo: string;
  /**
   * `upto`: client authorizes the max, gateway settles actual usage (preferred).
   * `exact`: client pays the max up front; use only if your facilitator lacks `upto`.
   */
  scheme: "upto" | "exact";
  /** SPL mint; defaults to USDC on the configured network. */
  asset?: string;
  maxTimeoutSeconds?: number;
}

export interface GatewayOptions {
  pricing: PricingConfig;
  registry: NodeRegistry;
  receipts: ReceiptStore;
  payment: PaymentConfig;
  /** x402 resource server with the facilitator client and the SVM scheme registered. */
  resourceServer: x402ResourceServer;
  /** Lowest trust tier the gateway will route to. Clients may raise it, never lower it. */
  minTier: TrustTier;
  syncFacilitatorOnStart?: boolean;
  fetchImpl?: typeof fetch;
  /** Access log sink; receives no payload, IP or wallet data. */
  log?: (line: string) => void;
}

type Vars = {
  quote: Quote;
  node: NodeState;
  rawBody: string;
};

const RECEIPT_HEADER = "x-satoris-receipt-id";
const CHAT_PATH = "/v1/chat/completions";
const SEALED_PATH = "/v1/sealed/chat/completions";

export function createGateway(opts: GatewayOptions) {
  const { pricing, registry, receipts, payment } = opts;
  const fetchImpl = opts.fetchImpl ?? fetch;
  const log = opts.log ?? ((line: string) => console.log(line));
  const asset = payment.asset ?? getUsdcAddress(payment.network);

  // Finalize receipts once the facilitator confirms settlement on-chain.
  opts.resourceServer.onAfterSettle(async (ctx) => {
    const transport = ctx.transportContext as HTTPTransportContext | undefined;
    const id = transport?.responseHeaders?.[RECEIPT_HEADER];
    if (!id) return; // e.g. the escrow deposit phase of `upto`, before the handler ran
    await receipts.update(id, {
      status: ctx.result.success ? "settled" : "failed",
      payer: ctx.result.payer,
      transaction: ctx.result.transaction,
      settledAtomic: ctx.result.amount ?? ctx.requirements.amount,
    });
  });
  opts.resourceServer.onSettleFailure(async (ctx) => {
    const transport = ctx.transportContext as HTTPTransportContext | undefined;
    const id = transport?.responseHeaders?.[RECEIPT_HEADER];
    if (id) await receipts.update(id, { status: "failed" });
  });

  const priced = (quoteFn: (cfg: PricingConfig, body: unknown) => Quote, description: string) => ({
    accepts: {
      scheme: payment.scheme,
      network: payment.network,
      payTo: payment.payTo,
      maxTimeoutSeconds: payment.maxTimeoutSeconds ?? 120,
      price: async (ctx: { adapter: { getBody?: () => unknown } }) => {
        const body = await ctx.adapter.getBody?.();
        return { asset, amount: quoteFn(pricing, body).maxAtomic.toString() };
      },
    },
    description,
    mimeType: "application/json",
  });

  const routes: RoutesConfig = {
    [`POST ${CHAT_PATH}`]: priced(quoteChat, "OpenAI-compatible chat completion on attested TEE GPU nodes"),
    [`POST ${SEALED_PATH}`]: priced(quoteSealed, "End-to-end sealed chat completion; gateway sees ciphertext only"),
  };

  const app = new Hono<{ Variables: Vars }>();

  // Zero-log: method, route and status only. No bodies, headers, IPs or wallets.
  app.use("*", async (c, next) => {
    const start = performance.now();
    await next();
    const path = c.req.path.replace(/^\/v1\/(receipts|nodes)\/[^/]+/, "/v1/$1/:id");
    log(`${c.req.method} ${path} ${c.res.status} ${Math.round(performance.now() - start)}ms`);
  });

  app.onError((err, c) => {
    if (err instanceof QuoteError) return c.json(openaiError(err.message, "invalid_request_error"), err.status);
    log(`error ${err.name}`);
    return c.json(openaiError("internal error", "server_error"), 500);
  });

  // Validate and route *before* asking for payment, so clients never pay for a request we can't serve.
  const preflight = (kind: "chat" | "sealed") =>
    async (c: Context<{ Variables: Vars }>, next: () => Promise<void>) => {
      const rawBody = await c.req.text();
      let body: unknown;
      try {
        body = JSON.parse(rawBody);
      } catch {
        return c.json(openaiError("body must be JSON", "invalid_request_error"), 400);
      }
      const quote = kind === "chat" ? quoteChat(pricing, body) : quoteSealed(pricing, body);
      const sealed = kind === "sealed" ? (body as SealedChatRequest) : undefined;
      const node = selectNode(registry, {
        model: quote.model.id,
        minTier: effectiveTier(opts.minTier, c.req.header("x-satoris-min-trust")),
        pinnedNode: sealed?.node,
        pinnedKid: sealed?.envelope.kid,
      });
      if (!node) {
        const msg = sealed
          ? "the node this request was sealed to is not currently attested; refetch /v1/nodes and reseal"
          : `no attested node is serving ${quote.model.id} right now`;
        return c.json(openaiError(msg, "service_unavailable"), 503);
      }
      c.set("rawBody", rawBody);
      c.set("quote", quote);
      c.set("node", node);
      await next();
    };

  app.post(CHAT_PATH, preflight("chat"));
  app.post(SEALED_PATH, preflight("sealed"));
  app.use(paymentMiddleware(routes, opts.resourceServer, undefined, undefined, opts.syncFacilitatorOnStart ?? true));

  const forward = async (c: Context<{ Variables: Vars }>, path: string, body: unknown) => {
    const node = c.get("node");
    const headers: Record<string, string> = { "content-type": "application/json" };
    if (node.config.authToken) headers.authorization = `Bearer ${node.config.authToken}`;
    const start = performance.now();
    const res = await fetchImpl(`${node.config.url}${path}`, {
      method: "POST",
      headers,
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(300_000),
    });
    registry.recordLatency(node.config.id, performance.now() - start);
    if (res.status >= 500) registry.markUnhealthy(node.config.id, `upstream ${res.status}`);
    return res;
  };

  /** Bill actual usage (capped at the authorization), write the receipt, tag the response. */
  const meter = async (c: Context<{ Variables: Vars }>, usage: Usage, responseText: string, sealed: boolean) => {
    const quote = c.get("quote");
    const node = c.get("node");
    let charged = costAtomic(quote.model, usage, pricing.minChargeAtomic);
    if (charged > quote.maxAtomic) charged = quote.maxAtomic;
    if (payment.scheme === "upto") setSettlementOverrides(c, { amount: charged.toString() });
    const receipt: Receipt = {
      id: crypto.randomUUID(),
      version: 1,
      createdAt: Date.now(),
      nodeId: node.config.id,
      model: quote.model.id,
      tier: node.tier,
      evidenceHash: node.evidenceHash ?? "",
      sealed,
      requestHash: toHex(await sha256(c.get("rawBody"))),
      responseHash: toHex(await sha256(responseText)),
      usage,
      maxAtomic: quote.maxAtomic.toString(),
      chargedAtomic: (payment.scheme === "upto" ? charged : quote.maxAtomic).toString(),
      network: payment.network,
      status: "pending",
    };
    await receipts.put(receipt);
    c.header(RECEIPT_HEADER, receipt.id);
    c.header("x-satoris-node", node.config.id);
    c.header("x-satoris-trust-tier", node.tier);
    c.header("x-satoris-evidence-hash", receipt.evidenceHash);
  };

  app.post(CHAT_PATH, async (c) => {
    const quote = c.get("quote");
    const body = { ...JSON.parse(c.get("rawBody")), stream: false, max_tokens: quote.maxTokens };
    delete body.max_completion_tokens;
    const res = await forward(c, CHAT_PATH, body);
    if (!res.ok) return c.json(openaiError("upstream node failed", "upstream_error"), 502);
    const result = (await res.json()) as ChatCompletionResponse;
    if (!validUsage(result.usage)) return c.json(openaiError("upstream returned no usage", "upstream_error"), 502);
    const text = JSON.stringify(result);
    await meter(c, result.usage, text, false);
    return c.body(text, 200, { "content-type": "application/json" });
  });

  app.post(SEALED_PATH, async (c) => {
    const res = await forward(c, SEALED_PATH, JSON.parse(c.get("rawBody")));
    if (res.status === 409) return c.json(openaiError("node key rotated; reseal", "stale_key"), 409);
    if (!res.ok) return c.json(openaiError("upstream node failed", "upstream_error"), 502);
    const result = (await res.json()) as SealedChatResponse;
    if (!validUsage(result.usage)) return c.json(openaiError("upstream returned no usage", "upstream_error"), 502);
    const text = JSON.stringify(result);
    await meter(c, result.usage, text, true);
    return c.body(text, 200, { "content-type": "application/json" });
  });

  app.get("/healthz", (c) => c.json({ ok: true }));

  app.get("/v1/models", (c) => {
    const live = registry.list().filter((n) => registry.isLive(n));
    return c.json({
      object: "list",
      data: pricing.models.map((m) => ({
        id: m.id,
        object: "model",
        owned_by: "satoris",
        pricing: {
          currency: "USDC",
          input_per_mtok: atomicToUsd(m.inputPerMTok),
          output_per_mtok: atomicToUsd(m.outputPerMTok),
        },
        max_output_tokens: m.maxOutputTokens,
        context_window: m.contextWindow,
        available_nodes: live.filter((n) => n.config.models.includes(m.id)).length,
      })),
    });
  });

  app.get("/v1/nodes", (c) =>
    c.json({
      data: registry.list().map((n) => ({
        id: n.config.id,
        region: n.config.region,
        models: n.config.models,
        live: registry.isLive(n),
        tier: n.tier,
        kid: n.kid,
        public_key: n.publicKey,
        attested_at: n.attestedAt,
        evidence_hash: n.evidenceHash,
        evidence: n.evidence,
        reasons: n.reasons,
      })),
    }),
  );

  // Clients verify nodes themselves with their own nonce; the gateway just relays.
  app.get("/v1/nodes/:id/attestation", async (c) => {
    const node = registry.get(c.req.param("id"));
    if (!node) return c.json(openaiError("unknown node", "not_found"), 404);
    const nonce = c.req.query("nonce") ?? "";
    if (!/^[0-9a-f]{64}$/.test(nonce)) return c.json(openaiError("nonce must be 32 bytes hex", "invalid_request_error"), 400);
    const res = await fetchImpl(`${node.config.url}/attestation?nonce=${nonce}`, { signal: AbortSignal.timeout(10_000) });
    return c.body(await res.text(), res.status as 200, { "content-type": "application/json" });
  });

  app.get("/v1/receipts/:id", async (c) => {
    const receipt = await receipts.get(c.req.param("id"));
    if (!receipt) return c.json(openaiError("unknown receipt", "not_found"), 404);
    return c.json(receipt);
  });

  return app;
}

function effectiveTier(floor: TrustTier, requested: string | undefined): TrustTier {
  if (requested === "tee-gpu" || requested === "tee-cpu") {
    return TIER_RANK[requested] > TIER_RANK[floor] ? requested : floor;
  }
  return floor;
}

function validUsage(u: Usage | undefined): u is Usage {
  return (
    !!u &&
    Number.isInteger(u.prompt_tokens) &&
    Number.isInteger(u.completion_tokens) &&
    u.prompt_tokens >= 0 &&
    u.completion_tokens >= 0
  );
}

function atomicToUsd(atomic: number): string {
  return (atomic / 1_000_000).toFixed(6);
}

function openaiError(message: string, type: string) {
  return { error: { message, type } };
}
