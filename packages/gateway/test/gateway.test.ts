import { beforeEach, describe, expect, it } from "vitest";
import type { FacilitatorClient } from "@x402/core/server";
import { decodePaymentRequiredHeader, encodePaymentSignatureHeader } from "@x402/core/http";
import type { PaymentPayload, PaymentRequirements, SettleResponse, SupportedResponse } from "@x402/core/types";
import { x402ResourceServer } from "@x402/hono";
import { ExactSvmScheme } from "@x402/svm/exact/server";
import { UptoSvmScheme } from "@x402/svm/upto/server";
import { SOLANA_DEVNET_CAIP2, USDC_DEVNET_ADDRESS } from "@x402/svm";
import { type AttestationPolicy, DevInsecureVerifier, newNonce, verifyAttestation } from "@satoris/attestation";
import { DevQuoteProvider, EchoBackend, createNodeAgent } from "@satoris/node-agent";
import { type ChatCompletionResponse, type SealedChatResponse, fromBase64, sealJson } from "@satoris/sealed";
import {
  MemoryReceiptStore,
  NodeRegistry,
  type PricingConfig,
  type Receipt,
  createGateway,
  merkleRoot,
  receiptLeaf,
} from "../src/index.js";

const MEASUREMENT = "11".repeat(48);
const PAY_TO = "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin";
const FEE_PAYER = "EwWqGE4ZFKLofuestmU4LDdK7XM1N4ALgdZccwYugwGd";
const PAYER = "Hc3sdEAsCGQcpgfivywog9uwtk8gUBUZgsxdME1EJy88";

const policy: AttestationPolicy = {
  allowedPlatforms: ["dev-insecure"],
  allowedMeasurements: [MEASUREMENT],
  allowedTcbStatus: ["UpToDate"],
  maxAgeMs: 60_000,
  requireGpuAttestation: false,
  allowDebug: false,
};

const pricing: PricingConfig = {
  defaultMaxTokens: 100,
  minChargeAtomic: 10,
  models: [{ id: "echo-1", inputPerMTok: 1_000_000, outputPerMTok: 2_000_000, maxOutputTokens: 1000, contextWindow: 8192 }],
};

class FakeFacilitator implements FacilitatorClient {
  verified: PaymentPayload[] = [];
  settled: PaymentRequirements[] = [];
  valid = true;

  constructor(private readonly scheme: "exact" | "upto" = "exact") {}

  async verify(payload: PaymentPayload) {
    this.verified.push(payload);
    return this.valid ? { isValid: true, payer: PAYER } : { isValid: false, invalidReason: "insufficient_funds" };
  }

  async settle(_payload: PaymentPayload, req: PaymentRequirements): Promise<SettleResponse> {
    this.settled.push(req);
    return { success: true, transaction: "5igSig", network: req.network, payer: PAYER, amount: req.amount };
  }

  async getSupported(): Promise<SupportedResponse> {
    return {
      kinds: [
        {
          x402Version: 2,
          scheme: this.scheme,
          network: SOLANA_DEVNET_CAIP2,
          extra: { feePayer: FEE_PAYER, receiverAuthorizer: FEE_PAYER },
        },
      ],
      extensions: [],
      signers: {},
    };
  }
}

async function setup(opts: { nodeFails?: boolean; scheme?: "exact" | "upto" } = {}) {
  const scheme = opts.scheme ?? "exact";
  const node = await createNodeAgent({
    nodeId: "n1",
    backend: new EchoBackend(["echo-1"]),
    quotes: new DevQuoteProvider(MEASUREMENT),
    authToken: "node-secret",
  });
  // Everything the gateway sends upstream passes through here, so tests can inspect it.
  const upstream: string[] = [];
  const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const req = new Request(input, init);
    if (req.method === "POST") upstream.push(await req.clone().text());
    if (opts.nodeFails && req.method === "POST") return new Response("boom", { status: 500 });
    return node.app.fetch(req);
  }) as typeof fetch;

  const registry = new NodeRegistry(
    [{ id: "n1", url: "http://node", models: ["echo-1"], authToken: "node-secret" }],
    policy,
    [new DevInsecureVerifier()],
    fetchImpl,
  );
  await registry.refreshAll();

  const facilitator = new FakeFacilitator(scheme);
  const resourceServer = new x402ResourceServer(facilitator).register(
    SOLANA_DEVNET_CAIP2,
    scheme === "upto" ? new UptoSvmScheme() : new ExactSvmScheme(),
  );
  const receipts = new MemoryReceiptStore();
  const app = createGateway({
    pricing,
    registry,
    receipts,
    payment: { network: SOLANA_DEVNET_CAIP2, payTo: PAY_TO, scheme },
    resourceServer,
    minTier: "tee-cpu",
    fetchImpl,
    log: () => {},
  });
  return { app, facilitator, receipts, registry, upstream, node };
}

const chatBody = { model: "echo-1", messages: [{ role: "user", content: "hello there" }], max_tokens: 50 };

function post(app: { request: (path: string, init: RequestInit) => Response | Promise<Response> }, path: string, body: unknown, headers: Record<string, string> = {}) {
  return app.request(path, { method: "POST", headers: { "content-type": "application/json", ...headers }, body: JSON.stringify(body) });
}

/** Pays exactly what the 402 challenge asked for, like a wallet would. */
async function pay(res: Response): Promise<Record<string, string>> {
  const required = decodePaymentRequiredHeader(res.headers.get("payment-required")!);
  const payload: PaymentPayload = {
    x402Version: required.x402Version,
    resource: required.resource,
    accepted: required.accepts[0]!,
    payload: { transaction: "base64-partially-signed-tx" },
  };
  return { "payment-signature": encodePaymentSignatureHeader(payload) };
}

describe("gateway", () => {
  let ctx: Awaited<ReturnType<typeof setup>>;
  beforeEach(async () => {
    ctx = await setup();
  });

  it("lists the catalog and attested nodes for free", async () => {
    const models = await (await ctx.app.request("/v1/models")).json();
    expect(models.data[0]).toMatchObject({ id: "echo-1", available_nodes: 1, pricing: { input_per_mtok: "1.000000" } });
    const nodes = await (await ctx.app.request("/v1/nodes")).json();
    expect(nodes.data[0]).toMatchObject({ id: "n1", live: true, tier: "tee-cpu" });
  });

  it("answers an unpaid request with a 402 priced at the request's upper bound", async () => {
    const res = await post(ctx.app, "/v1/chat/completions", chatBody);
    expect(res.status).toBe(402);
    const required = decodePaymentRequiredHeader(res.headers.get("payment-required")!);
    const accept = required.accepts[0]!;
    expect(accept).toMatchObject({ scheme: "exact", network: SOLANA_DEVNET_CAIP2, payTo: PAY_TO, asset: USDC_DEVNET_ADDRESS });
    // 50 output tokens @ $2/M + prompt bytes @ $1/M, rounded up to atomic units.
    const promptBytes = new TextEncoder().encode(JSON.stringify(chatBody.messages)).length;
    expect(accept.amount).toBe(String(Math.ceil(promptBytes * 1) + 50 * 2));
    expect(ctx.upstream).toHaveLength(0);
  });

  it("rejects bad requests before asking for payment", async () => {
    expect((await post(ctx.app, "/v1/chat/completions", { model: "echo-1" })).status).toBe(400);
    expect((await post(ctx.app, "/v1/chat/completions", { ...chatBody, model: "nope" })).status).toBe(404);
    expect((await post(ctx.app, "/v1/chat/completions", { ...chatBody, max_tokens: 5000 })).status).toBe(400);
    expect((await post(ctx.app, "/v1/chat/completions", { ...chatBody, stream: true })).status).toBe(400);
    // Asking for a GPU tier when only CPU-TEE nodes exist: unavailable, not a payment prompt.
    expect((await post(ctx.app, "/v1/chat/completions", chatBody, { "x-satoris-min-trust": "tee-gpu" })).status).toBe(503);
  });

  it("serves a paid request, settles it and records a receipt", async () => {
    const challenge = await post(ctx.app, "/v1/chat/completions", chatBody);
    const res = await post(ctx.app, "/v1/chat/completions", chatBody, await pay(challenge));
    expect(res.status).toBe(200);
    const completion = (await res.json()) as ChatCompletionResponse;
    expect(completion.choices[0]!.message.content).toBe("echo: hello there");
    expect(res.headers.get("payment-response")).toBeTruthy();
    expect(ctx.facilitator.settled).toHaveLength(1);

    const receipt = (await ctx.receipts.get(res.headers.get("x-satoris-receipt-id")!)) as Receipt;
    expect(receipt).toMatchObject({ status: "settled", payer: PAYER, transaction: "5igSig", nodeId: "n1", sealed: false });
    expect(receipt.usage.completion_tokens).toBe(3);
  });

  it("with upto, authorizes the upper bound but settles only actual usage", async () => {
    const upto = await setup({ scheme: "upto" });
    const challenge = await post(upto.app, "/v1/chat/completions", chatBody);
    const max = BigInt(decodePaymentRequiredHeader(challenge.headers.get("payment-required")!).accepts[0]!.amount);
    const res = await post(upto.app, "/v1/chat/completions", chatBody, await pay(challenge));
    expect(res.status).toBe(200);

    const receipt = (await upto.receipts.get(res.headers.get("x-satoris-receipt-id")!)) as Receipt;
    // Echo used 3 prompt + 3 completion tokens: max(6 atomic, 10 minimum) = 10.
    expect(receipt.chargedAtomic).toBe("10");
    expect(receipt.status).toBe("settled");
    expect(BigInt(receipt.settledAtomic!)).toBe(10n);
    expect(BigInt(receipt.settledAtomic!)).toBeLessThan(max);
  });

  it("does not charge when the node fails", async () => {
    const failing = await setup({ nodeFails: true });
    const challenge = await post(failing.app, "/v1/chat/completions", chatBody);
    const res = await post(failing.app, "/v1/chat/completions", chatBody, await pay(challenge));
    expect(res.status).toBe(502);
    expect(failing.facilitator.settled).toHaveLength(0);
  });

  it("does not run inference when the facilitator rejects the payment", async () => {
    ctx.facilitator.valid = false;
    const challenge = await post(ctx.app, "/v1/chat/completions", chatBody);
    const res = await post(ctx.app, "/v1/chat/completions", chatBody, await pay(challenge));
    expect(res.status).toBe(402);
    expect(ctx.upstream).toHaveLength(0);
  });

  it("relays sealed requests without ever seeing the plaintext", async () => {
    const secret = "my medical history is private";
    // Client verifies the node itself with its own nonce, then seals to the attested key.
    const nonce = newNonce();
    const evidence = await (await ctx.app.request(`/v1/nodes/n1/attestation?nonce=${nonce}`)).json();
    const verdict = await verifyAttestation(evidence, { policy, verifiers: [new DevInsecureVerifier()], expectedNonce: nonce });
    expect(verdict.ok).toBe(true);

    const meta = { model: "echo-1", max_tokens: 50 };
    const { envelope, reply } = await sealJson(
      { model: "echo-1", messages: [{ role: "user", content: secret }], max_tokens: 50 },
      fromBase64(evidence.publicKey),
      meta,
    );
    const body = { meta, node: "n1", envelope };
    const challenge = await post(ctx.app, "/v1/sealed/chat/completions", body);
    expect(challenge.status).toBe(402);
    const res = await post(ctx.app, "/v1/sealed/chat/completions", body, await pay(challenge));
    expect(res.status).toBe(200);

    const sealed = (await res.json()) as SealedChatResponse;
    const completion = await reply.openJson<ChatCompletionResponse>(sealed.envelope);
    expect(completion.choices[0]!.message.content).toBe(`echo: ${secret}`);

    expect(ctx.upstream.join("")).not.toContain("medical");
    expect(JSON.stringify(sealed)).not.toContain("medical");
    const receipt = await ctx.receipts.get(res.headers.get("x-satoris-receipt-id")!);
    expect(receipt).toMatchObject({ sealed: true, status: "settled" });
  });

  it("refuses sealed requests addressed to a node that is not attested", async () => {
    const meta = { model: "echo-1", max_tokens: 50 };
    const { envelope } = await sealJson({ model: "echo-1", messages: [] }, ctx.node.publicKey, meta);
    const res = await post(ctx.app, "/v1/sealed/chat/completions", { meta, node: "ghost", envelope });
    expect(res.status).toBe(503);
  });
});

describe("receipt merkle batching", () => {
  it("is deterministic and order sensitive", async () => {
    const base: Receipt = {
      id: "a", version: 1, createdAt: 1, nodeId: "n1", model: "m", tier: "tee-cpu", evidenceHash: "e", sealed: false,
      requestHash: "q", responseHash: "r", usage: { prompt_tokens: 1, completion_tokens: 2, total_tokens: 3 },
      maxAtomic: "10", chargedAtomic: "5", network: "solana:x", status: "settled",
    };
    const leaves = await Promise.all([base, { ...base, id: "b" }, { ...base, id: "c" }].map(receiptLeaf));
    const root = await merkleRoot(leaves);
    expect(root).toHaveLength(32);
    expect(await merkleRoot(leaves)).toEqual(root);
    expect(await merkleRoot([leaves[1]!, leaves[0]!, leaves[2]!])).not.toEqual(root);
  });
});
