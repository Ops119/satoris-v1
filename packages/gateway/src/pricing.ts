import { type ChatCompletionRequest, type SealedChatRequest, type Usage, fromBase64 } from "@satoris/sealed";

/** Prices are in atomic USDC (6 decimals) per million tokens, so 150_000 = $0.15 / 1M tokens. */
export interface ModelPrice {
  id: string;
  inputPerMTok: number;
  outputPerMTok: number;
  /** Hard cap on completion tokens for this model. */
  maxOutputTokens: number;
  contextWindow: number;
}

export interface PricingConfig {
  models: ModelPrice[];
  /** Default completion budget when the client doesn't send max_tokens. */
  defaultMaxTokens: number;
  /** Floor per request in atomic units; keeps dust payments above facilitator minimums. */
  minChargeAtomic: number;
}

export interface Quote {
  model: ModelPrice;
  maxTokens: number;
  /** Upper bound on prompt tokens used for the authorization. */
  maxInputTokens: number;
  /** The most this request can cost; what the client authorizes. */
  maxAtomic: bigint;
}

export class QuoteError extends Error {
  constructor(
    message: string,
    readonly status: 400 | 404 = 400,
  ) {
    super(message);
  }
}

function tokenCost(tokens: number, perMTok: number): bigint {
  // ceil(tokens * perMTok / 1e6) without float drift.
  const num = BigInt(tokens) * BigInt(perMTok);
  return (num + 999_999n) / 1_000_000n;
}

export function costAtomic(model: ModelPrice, usage: Pick<Usage, "prompt_tokens" | "completion_tokens">, min: number): bigint {
  const cost = tokenCost(usage.prompt_tokens, model.inputPerMTok) + tokenCost(usage.completion_tokens, model.outputPerMTok);
  return cost < BigInt(min) ? BigInt(min) : cost;
}

/**
 * The gateway has to price a request before it runs, so it authorizes an upper
 * bound and settles actual usage afterwards (`upto` scheme). UTF-8 bytes are a
 * safe ceiling on BPE token count for every mainstream tokenizer, so we bill the
 * prompt at <= its byte length rather than shipping a tokenizer per model.
 */
function boundedQuote(cfg: PricingConfig, modelId: string, requestedMax: number | undefined, inputBytes: number): Quote {
  const model = cfg.models.find((m) => m.id === modelId);
  if (!model) throw new QuoteError(`model ${modelId} is not available`, 404);
  const maxTokens = requestedMax ?? Math.min(cfg.defaultMaxTokens, model.maxOutputTokens);
  if (!Number.isInteger(maxTokens) || maxTokens < 1) throw new QuoteError("max_tokens must be a positive integer");
  if (maxTokens > model.maxOutputTokens) {
    throw new QuoteError(`max_tokens exceeds ${model.maxOutputTokens} for ${model.id}`);
  }
  const maxInputTokens = Math.min(inputBytes, model.contextWindow);
  const maxAtomic = costAtomic(model, { prompt_tokens: maxInputTokens, completion_tokens: maxTokens }, cfg.minChargeAtomic);
  return { model, maxTokens, maxInputTokens, maxAtomic };
}

export function quoteChat(cfg: PricingConfig, body: unknown): Quote {
  const req = body as ChatCompletionRequest | undefined;
  if (!req || typeof req.model !== "string" || !Array.isArray(req.messages) || req.messages.length === 0) {
    throw new QuoteError("body must be a chat completion request with model and messages");
  }
  if (req.stream) throw new QuoteError("stream=true is not supported yet; use stream=false");
  const bytes = new TextEncoder().encode(JSON.stringify(req.messages)).length;
  return boundedQuote(cfg, req.model, req.max_completion_tokens ?? req.max_tokens, bytes);
}

export function quoteSealed(cfg: PricingConfig, body: unknown): Quote {
  const req = body as SealedChatRequest | undefined;
  if (!req?.meta || typeof req.meta.model !== "string" || typeof req.node !== "string" || !req.envelope?.ct) {
    throw new QuoteError("body must be a sealed chat request with meta, node and envelope");
  }
  let bytes: number;
  try {
    // AES-GCM ciphertext is plaintext + 16-byte tag; plaintext JSON bytes bound the prompt tokens.
    bytes = Math.max(0, fromBase64(req.envelope.ct).length - 16);
  } catch {
    throw new QuoteError("envelope ciphertext is not valid base64");
  }
  return boundedQuote(cfg, req.meta.model, req.meta.max_tokens, bytes);
}
