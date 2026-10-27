/**
 * Node agent: the only Satoris process that ever sees plaintext prompts. It runs
 * inside the TEE next to the model server, generates its sealing key in TEE
 * memory at boot, and never writes prompts, completions or keys to disk or logs.
 */
import { Hono } from "hono";
import {
  type ChatCompletionRequest,
  type NodeKeyPair,
  type SealedChatRequest,
  type SealedChatResponse,
  generateNodeKeyPair,
  isSealedEnvelope,
  keyId,
  openJson,
} from "@satoris/sealed";
import type { InferenceBackend } from "./backend.js";
import type { QuoteProvider } from "./quote.js";

export * from "./backend.js";
export * from "./quote.js";

export interface NodeAgentOptions {
  nodeId: string;
  backend: InferenceBackend;
  quotes: QuoteProvider;
  /** Shared secret the gateway presents; omit only for local development. */
  authToken?: string;
  keys?: NodeKeyPair;
}

const NONCE_RE = /^[0-9a-f]{64}$/;

export async function createNodeAgent(opts: NodeAgentOptions) {
  const keys = opts.keys ?? (await generateNodeKeyPair());
  const kid = await keyId(keys.publicKey);
  const app = new Hono();

  app.onError((err, c) => {
    // Never echo request content; errors carry only a coarse reason.
    return c.json({ error: { message: "node error", type: err.name } }, 500);
  });

  app.get("/healthz", (c) => c.json({ ok: true, node: opts.nodeId, kid }));

  app.get("/attestation", async (c) => {
    const nonce = c.req.query("nonce") ?? "";
    if (!NONCE_RE.test(nonce)) return c.json({ error: { message: "nonce must be 32 bytes hex" } }, 400);
    return c.json(await opts.quotes.getEvidence(keys.publicKey, nonce));
  });

  app.use("/v1/*", async (c, next) => {
    if (opts.authToken && c.req.header("authorization") !== `Bearer ${opts.authToken}`) {
      return c.json({ error: { message: "unauthorized" } }, 401);
    }
    await next();
  });

  app.get("/v1/models", async (c) => {
    const ids = await opts.backend.models();
    return c.json({ object: "list", data: ids.map((id) => ({ id, object: "model", owned_by: opts.nodeId })) });
  });

  // Plaintext path: TLS terminates at the gateway, which can see the prompt.
  app.post("/v1/chat/completions", async (c) => {
    const req = (await c.req.json()) as ChatCompletionRequest;
    return c.json(await opts.backend.chat(req));
  });

  // Sealed path: the gateway only ever handles ciphertext.
  app.post("/v1/sealed/chat/completions", async (c) => {
    const body = (await c.req.json()) as SealedChatRequest;
    if (!isSealedEnvelope(body.envelope) || !body.meta) {
      return c.json({ error: { message: "malformed sealed request" } }, 400);
    }
    if (body.envelope.kid !== kid) {
      return c.json({ error: { message: "sealed to a stale or foreign key", code: "stale_key" } }, 409);
    }
    let opened: Awaited<ReturnType<typeof openJson<ChatCompletionRequest>>>;
    try {
      opened = await openJson<ChatCompletionRequest>(body.envelope, keys, body.meta);
    } catch {
      return c.json({ error: { message: "decryption failed", code: "bad_envelope" } }, 400);
    }
    const inner = opened.value;
    const requested = inner.max_completion_tokens ?? inner.max_tokens;
    // The clear meta is what the client was billed for; the inner request can't exceed it.
    if (inner.model !== body.meta.model || (requested !== undefined && requested > body.meta.max_tokens)) {
      return c.json({ error: { message: "sealed request does not match its metadata" } }, 400);
    }
    const result = await opts.backend.chat({
      ...inner,
      stream: false,
      max_tokens: body.meta.max_tokens,
      max_completion_tokens: undefined,
    });
    const response: SealedChatResponse = {
      usage: result.usage,
      envelope: await opened.reply.sealJson(result),
    };
    return c.json(response);
  });

  return { app, publicKey: keys.publicKey, kid };
}
