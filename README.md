# satoris-v1

Private AI inference on Solana. Prompts are decrypted only inside attested TEE
GPU nodes, every request is paid with USDC over [x402](https://www.x402.org/),
and GPU providers stake into an on-chain registry that can slash them.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the trust model, how this
maps to the product outline, and what's still to build.

## Layout

| Path | What |
|---|---|
| `packages/sealed` | Client-side encryption to an attested node key (X25519 + HKDF + AES-GCM, WebCrypto) and shared wire types |
| `packages/attestation` | Attestation evidence, policy checks (nonce, freshness, measurement, key binding), trust tiers |
| `packages/node-agent` | Runs in the TEE: serves quotes via configfs-tsm, opens sealed prompts, forwards to vLLM/any OpenAI-compatible server |
| `packages/gateway` | OpenAI-compatible API, x402 payments (`@x402/hono` + `@x402/svm`), attested routing, metering, receipts |
| `packages/sdk` | Client: auto-pays 402s with spend limits, verifies nodes with its own nonce, `sealedChat` end to end |
| `programs/satoris` | Anchor program: node registry and staking, attestation records, receipt Merkle roots, slashing |

## Quick start (local, no TEE)

```bash
pnpm install
pnpm test          # 23 tests: crypto, attestation policy, pricing, full gateway flow
pnpm typecheck
cargo check        # Anchor program

# terminal 1: node agent with an echo model and dev (unsigned!) attestation
NODE_AUTH_TOKEN=devtoken pnpm dev:node

# terminal 2: gateway on Solana devnet via the public x402 facilitator
cp packages/gateway/gateway.config.example.json packages/gateway/gateway.config.json
NODE_AUTH_TOKEN=devtoken SATORIS_TREASURY=<your devnet address> pnpm dev:gateway

curl localhost:8080/v1/models
curl -i localhost:8080/v1/chat/completions -H 'content-type: application/json' \
  -d '{"model":"echo-1","messages":[{"role":"user","content":"hi"}],"max_tokens":20}'
# -> 402 Payment Required with a PAYMENT-REQUIRED challenge for devnet USDC
```

Point `BACKEND_URL` at a vLLM server to serve a real model from the node agent.

## Using the SDK

```ts
import { SatorisClient } from "@satoris/sdk";
import { DevInsecureVerifier } from "@satoris/attestation";

const client = new SatorisClient({
  baseUrl: "http://localhost:8080",
  signer,                                   // @solana/kit TransactionSigner (a scoped hot key for agents)
  network: "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
  scheme: "exact",
  maxPerRequest: "$0.10",
  budget: "$5",
  attestation: { policy, verifiers: [new DevInsecureVerifier()] },
});

// Gateway relays ciphertext only; the reply is decrypted locally.
const { completion, receiptId, payment } = await client.sealedChat({
  model: "echo-1",
  messages: [{ role: "user", content: "something private" }],
  max_tokens: 200,
});
```

## Status

This is MVP step 1 from the outline: an x402-gated inference API over
TEE nodes, plus the on-chain program for steps 2–3. Before handling real
data, you need hardware quote verifiers (TDX/SNP/NVIDIA). Until they're in,
only `dev-insecure` evidence verifies, and it proves nothing. See the
"Suggested next steps" section in the architecture doc.
