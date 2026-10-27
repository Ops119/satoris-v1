# Roadmap

Where the MVP goes next. One rule runs through every phase: **stay light.**
Reuse what's already in the tree, add a dependency only when it replaces
real work, and make every phase shippable on its own with a clear exit test.

Starting point (`feat/mvp-scaffold`): an x402-gated, OpenAI-compatible
gateway, a sealed (end-to-end encrypted) path, an attestation policy layer,
a TEE node agent, a client SDK, and an Anchor program for registry, staking,
receipts and slashing. The big gap: **no real hardware attestation yet.** Only
unsigned dev evidence verifies.

## Principles

1. **Critical path first.** Real attestation is what makes the privacy claim
   true; everything else is polish until it lands.
2. **One of each before many.** One TEE platform, one GPU type, one
   facilitator, one GPU provider. Generalize only after it works end to end.
3. **Small dependency budget.** The whole roadmap adds four runtime
   dependencies (`jose`, `@phala/dcap-qvl-web`, `@solana/kit` which is
   already a transitive dependency, and a Codama-generated program client).
   Storage uses Node's built-in `node:sqlite` until load proves otherwise.
4. **Don't build what you can buy or reuse.** Use hosted facilitators,
   vendor verifiers and existing GPU clouds. No custom token, facilitator
   or tokenizer.
5. **Keep the gateway untrusted.** On the sealed path it never sees data, so
   it can stay simple and, later, anyone can run one.

## Phase overview

| Phase | Goal | Size* | Exit test |
|---|---|---|---|
| 0. Harden | Make the MVP safe to expose on devnet | ~1 wk | Real devnet USDC request end to end; receipts survive restart |
| 1. Real attestation | Privacy claim becomes true on one platform | ~2–3 wk | A real TDX + H100 node attests; dev evidence rejected in prod config |
| 2. On-chain trust loop | Chain becomes the source of truth for nodes and receipts | ~2 wk | User proves a receipt against an on-chain root on devnet |
| 3. Payments polish | Per-token billing and streaming | ~1–2 wk | Streamed, sealed reply settled at actual usage |
| 4. Providers and app | Third-party GPUs and a usable front end | ~3–4 wk | An outside provider onboards with no help from us; web app chats privately |
| 5. Mainnet beta | Audit and launch | ~2 wk + audit lead time | Audited program on mainnet with capped stakes and volumes |

\*One or two engineers, rough. Phases 2 and 3 can run in parallel once Phase 1 is underway.

---

## Phase 0 — Harden what exists (~1 week)

Small fixes that close obvious holes before anything is public.

- **Request limits.** Add Hono's `bodyLimit` (for example 1 MB) to the paid
  routes, plus an in-memory per-IP token bucket on the *unpaid* 402 path.
  Quoting is free, so it's the DoS surface. Neither needs storage or logs.
- **Constant-time auth** for the gateway-to-node bearer token
  (`crypto.timingSafeEqual`).
- **Persistent receipts with `node:sqlite`.** It's built into Node 22, so
  there's no new dependency. Implement `ReceiptStore` against it and keep
  `MemoryReceiptStore` for tests. Postgres waits until there's more than
  one gateway.
- **Containers.** A distroless gateway image and a node-agent image, the
  starting point for Phase 1's measured image.
- **Real devnet run.** A `scripts/devnet-e2e.ts` using the SDK with a funded
  devnet key: 402, then pay, then completion, then receipt. This covers the
  one path the tests fake today.
- **Program tests with LiteSVM** (`litesvm` crate, in-process, no
  validator): register, attest, slash, unbond, withdraw, plus the negative
  cases. Add them to CI.

**Exit:** the devnet script pays real devnet USDC and gets a completion, a
gateway restart keeps receipts, and program tests run in CI.

## Phase 1 — Real attestation on one platform (~2–3 weeks) ★ critical path

Pick the CPU TEE of your first GPU provider. The default suggestion is
**Intel TDX + NVIDIA H100/H200 confidential computing**, because TDX has the
lightest verification story below. Add AMD SEV-SNP in Phase 5, or first if
your provider is SNP-based (some clouds' confidential H100 VMs are).

- **TDX quote verification with `dcap-qvl`.** It's a pure-Rust DCAP verifier
  with a WASM build on npm (`@phala/dcap-qvl-web`). Wrap it as a
  `TdxVerifier implements PlatformVerifier` in `@satoris/attestation`.
  Because it's WASM, **the same code runs in the gateway, in Node agents and
  in the browser SDK**, so clients verify quotes themselves. Fetch
  collateral (TCB info, QE identity, CRLs) from Intel PCS and cache it for
  hours.
- **GPU evidence through NVIDIA NRAS.** The node agent collects GPU evidence
  with NVIDIA's attestation SDK (or `go-nvtrust`) using **the same nonce**
  as the TDX quote, sends it to NRAS, and ships the returned JWT as
  `gpuEvidence`. The verifier checks the ES384 signature against NRAS's
  JWKS with `jose`, then checks `eat_nonce == nonce`,
  `x-nvidia-overall-att-result == true`, debug disabled and an allowed
  driver/VBIOS. A matching nonce is what ties the GPU to that specific
  confidential VM.
- **Reproducible, measured node image.** Build the node agent plus vLLM plus
  pinned model weights into one image (mkosi, or a dstack-style CVM base).
  Publish its measurement (MRTD and RTMR0–2) in the repo. That value goes
  into `allowedMeasurements` and later on-chain. Use RTMR3 for runtime
  events such as the model-weights hash.
- **Prod policy.** `allowedPlatforms: ["intel-tdx"]`,
  `requireGpuAttestation: true`, and dev evidence removed from the prod
  config. The gateway should refuse to start if a prod config lists
  `dev-insecure`.
- **Fallback, not default:** Intel Trust Authority can verify CPU and GPU
  evidence together and return one JWT. It's useful if `dcap-qvl` hits an
  edge case, but it adds a SaaS dependency and an API key to the trust
  path, so keep it optional.

**Exit:** a real TDX + H100 node shows `tee-gpu` in `/v1/nodes`. The SDK
verifies it in the browser and in Node. Tampered quotes, a wrong
measurement, a debug TD and a nonce mismatch all fail in tests built from
recorded real quotes.

## Phase 2 — On-chain trust loop (~2 weeks)

Make the chain the source of truth instead of a gateway config file.

- **Program client.** Generate a TypeScript client from the Anchor IDL with
  Codama, on `@solana/kit` (already pulled in by `@x402/svm`). No
  `@coral-xyz/anchor` or web3.js v1.
- **On-chain measurement allowlist.** Add a small `ImageAllowlist` account
  managed by the admin, and have `record_attestation` require the
  measurement to be in it. That moves "which images are trusted" from
  config into governance.
- **Attestation authority worker.** A small process that re-challenges every
  registered node, verifies it with the Phase 1 verifiers, and calls
  `record_attestation` with a short expiry (for example 15 minutes). Start
  with one key and move it to a Squads multisig or a 2-of-3 set of
  independent verifiers before mainnet.
- **Registry from chain.** The gateway reads `Node` accounts with a filtered
  `getProgramAccounts` call cached for about 30 seconds, and routes only to
  nodes with an unexpired tier. It still re-challenges each node itself. The
  static node list remains for dev.
- **Receipt anchoring and proofs.** Run `anchorPending` every N minutes or
  every 1,024 receipts. Add `GET /v1/receipts/:id/proof` (Merkle path plus
  batch index) and an SDK `verifyReceipt()` that checks the proof against
  the on-chain `ReceiptBatch` root.

**Exit:** on devnet, a node registers and stakes, the worker attests it, the
gateway routes to it from on-chain data, and a client verifies its receipt's
inclusion against the chain.

## Phase 3 — Payments polish (~1–2 weeks)

- **Turn on `upto`.** The public x402.org facilitator only does `exact` on
  Solana devnet, so test PayAI and the Coinbase CDP facilitator through
  their `/supported` endpoints, or self-host the Kora reference
  facilitator. The gateway already refuses to start if the facilitator
  lacks the configured scheme, which makes this a config change.
- **Streaming.** This is the one real design change. Today the x402 Hono
  middleware buffers the whole response before it settles, which breaks
  SSE. Use `x402HTTPResourceServer` directly instead: verify up front,
  stream, then call `processSettlement` with the metered amount when the
  stream ends. On the sealed path, encrypt each chunk with AES-GCM under the
  existing response key, using a counter nonce and a final "end" frame so
  truncation is detectable. Keep usage in the clear for billing.
- **Agent ergonomics.** Make the SDK `budget` per session key, and add a
  small MCP server (one `chat` tool that wraps `sealedChat`) so agent
  frameworks can call Satoris with no custom code.

**Exit:** a streamed, sealed completion arrives chunk by chunk, settles at
actual usage, and the client detects a truncated stream.

## Phase 4 — Providers and app (~3–4 weeks)

- **Provider onboarding.** A `satoris-node` CLI inside the measured image
  generates the sealing key in the TEE, attests, then runs `register_node`
  with stake.
  - **Stake in USDC at first.** The program already takes any stake mint, so
    there's no token to launch.
- **Scheduler v2.** Add per-node price bids, VRAM and region to `Node` and to
  `selectNode`. Keep it a pure function: it's easy to test and has no
  queue infrastructure.
- **Provider payouts v1.** Compute payouts off-chain from anchored receipts
  and pay them weekly from the treasury, with the batch root referenced in
  the transfer memo. Per-job on-chain escrow comes later, only if
  providers ask for it.
- **Reputation and slashing.** Keep a rolling success-rate and latency score
  in the gateway. The authority worker raises a slash for failed
  re-attestation or a measurement change. Output-quality disputes wait;
  they're hard to prove and easy to get wrong.
- **One GPU cloud integration.** Choose whichever DePIN or cloud gives you
  confidential H100s, and integrate by running the node image there, not by
  building API integrations into Render, io.net, Akash and Nosana all at
  once.
- **Web app.** Next.js with the Solana wallet adapter, calling the SDK's
  `sealedChat` in the browser. WebCrypto and the WASM verifier already
  work there. Wallet connect is the only login. React Native comes after the
  web app works.

**Exit:** an outside operator onboards a node from the docs alone, and a
user chats privately from the browser with in-browser attestation checks.

## Phase 5 — Mainnet beta (~2 weeks plus audit lead time)

- **Audit** the program. Have someone else review the sealed-envelope
  construction and the attestation policy.
- **Caps for launch:** max stake per node, max request price, and an admin
  pause instruction.
- **Ops:** an RPC provider (Helius or Triton), key management for the
  receipt, attestation and slash authorities (KMS or a multisig), and
  dashboards built only from the access log and receipts, so the zero-log
  promise still holds.
- **Add AMD SEV-SNP** (VCEK chain from AMD KDS) if Phase 1 started with
  TDX, and Blackwell GPUs if providers have them.

## Deliberately not doing (yet)

| Item | Why not now | Revisit when |
|---|---|---|
| Native token and governance | USDC staking and a multisig are enough; a token adds legal and design load | Providers or users ask for it |
| Running our own facilitator | Hosted ones exist; Kora is the fallback | Fees or uptime become a problem |
| General ZK/MPC inference | Orders of magnitude slower than TEEs for LLMs | A narrow workload (for example embeddings or verifying small models) needs it |
| Postgres, Kubernetes, queues | One gateway plus SQLite covers early load | More than one gateway instance |
| Per-model tokenizers | Byte-length upper bound plus `upto` settlement is accurate enough | Customers complain about authorization size |
| Multi-provider DePIN adapters | Each one is a maintenance burden | One integration is proven and demand is clear |
| Decentralized gateways | The sealed path already makes the gateway untrusted | After mainnet beta |

## Top risks

1. **Attestation verification bugs** undermine the whole product. Test with
   recorded real quotes, including tampered ones, and get it reviewed.
2. **Facilitator support for `upto` on Solana** could change. The gateway
   already fails fast, and `exact` stays as a working fallback.
3. **Supply of confidential GPUs** in DePIN networks may be thin. Start with
   one cloud that offers confidential H100s and add DePIN capacity as it
   appears.
4. **Streaming settlement** means leaving the stock x402 middleware.
   Isolate it in one module and keep it covered by the fake-facilitator
   tests.
