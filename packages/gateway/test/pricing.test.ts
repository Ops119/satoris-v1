import { describe, expect, it } from "vitest";
import { type PricingConfig, QuoteError, costAtomic, quoteChat } from "../src/pricing.js";

const cfg: PricingConfig = {
  defaultMaxTokens: 256,
  minChargeAtomic: 10,
  models: [{ id: "m", inputPerMTok: 600_000, outputPerMTok: 800_000, maxOutputTokens: 4096, contextWindow: 1000 }],
};
const model = cfg.models[0]!;

describe("pricing", () => {
  it("rounds each component up to whole atomic units", () => {
    // 1 token @ $0.60/M = 0.6 atomic -> 1; 1 token @ $0.80/M -> 1
    expect(costAtomic(model, { prompt_tokens: 1, completion_tokens: 1 }, 0)).toBe(2n);
    expect(costAtomic(model, { prompt_tokens: 1_000_000, completion_tokens: 1_000_000 }, 0)).toBe(1_400_000n);
  });

  it("applies the minimum charge", () => {
    expect(costAtomic(model, { prompt_tokens: 0, completion_tokens: 0 }, 10)).toBe(10n);
  });

  it("caps prompt tokens at the context window and defaults max_tokens", () => {
    const q = quoteChat(cfg, { model: "m", messages: [{ role: "user", content: "x".repeat(5000) }] });
    expect(q.maxInputTokens).toBe(1000);
    expect(q.maxTokens).toBe(256);
    expect(q.maxAtomic).toBe(costAtomic(model, { prompt_tokens: 1000, completion_tokens: 256 }, 10));
  });

  it("rejects malformed requests", () => {
    expect(() => quoteChat(cfg, { model: "m", messages: [] })).toThrow(QuoteError);
    expect(() => quoteChat(cfg, { model: "m", messages: [{ role: "user", content: "x" }], max_tokens: 0 })).toThrow(QuoteError);
    expect(() => quoteChat(cfg, { model: "m", messages: [{ role: "user", content: "x" }], max_tokens: 1.5 })).toThrow(QuoteError);
  });
});
