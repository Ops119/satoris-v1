import { serve } from "@hono/node-server";
import {
  ConfigfsTsmQuoteProvider,
  DevQuoteProvider,
  EchoBackend,
  OpenAICompatibleBackend,
  type QuoteProvider,
  createNodeAgent,
} from "./index.js";

const env = process.env;

function quoteProvider(): QuoteProvider {
  const platform = env.TEE_PLATFORM ?? (ConfigfsTsmQuoteProvider.available() ? "intel-tdx" : "dev-insecure");
  if (platform === "intel-tdx" || platform === "amd-sev-snp") return new ConfigfsTsmQuoteProvider(platform);
  if (platform === "dev-insecure") {
    console.warn("[node-agent] using dev-insecure attestation: NOT a TEE, do not send real data");
    return new DevQuoteProvider(env.DEV_MEASUREMENT ?? "00".repeat(48));
  }
  throw new Error(`unknown TEE_PLATFORM ${platform}`);
}

const backend = env.BACKEND_URL
  ? new OpenAICompatibleBackend(env.BACKEND_URL, env.BACKEND_API_KEY)
  : new EchoBackend((env.ECHO_MODELS ?? "echo-1").split(","));

const { app, kid } = await createNodeAgent({
  nodeId: env.NODE_ID ?? "dev-node-1",
  backend,
  quotes: quoteProvider(),
  authToken: env.NODE_AUTH_TOKEN,
});

const port = Number(env.PORT ?? 8787);
serve({ fetch: app.fetch, port });
console.log(`[node-agent] listening on :${port} kid=${kid}`);
