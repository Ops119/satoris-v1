# Satoris architecture

Private AI inference on Solana: prompts are processed only inside attested
TEEs, paid per request with x402 (USDC), on a staked DePIN GPU network.

```
 client / agent                gateway (untrusted for data)            TEE GPU node
 ───────────────               ─────────────────────────────           ──────────────────────
 SDK ── GET /v1/nodes ───────▶ registry of attested nodes
     ── GET attestation?nonce ▶ relays ───────────────────────────────▶ quote(report_data =
     ◀── evidence ─────────────                                          sha256(key‖nonce))
 verify quote locally
 seal(prompt → node key)
     ── POST sealed ─────────▶ 402 ◀─ price = f(model, max_tokens, ct size)
     ── POST + PAYMENT-SIG ──▶ facilitator.verify ─▶ forward ciphertext ▶ open → model → seal
     ◀── sealed reply ───────── meter usage, settle actual (upto) ◀────── reply + clear usage
 open reply locally            receipt(hashes only) ─▶ Merkle root ─▶ Solana program
```

## Trust model

| Party | Sees plaintext? | Trusted for |
|---|---|---|
| Client | yes | itself |
| Gateway | **no** on the sealed path; yes on the plain OpenAI-compatible path | routing, metering, uptime |
| Facilitator | no (payment data only) | settling the USDC transfer |
| Node operator | no; the prompt is decrypted only inside the TEE | providing hardware |
| Node TEE image | yes | measured, so its code is pinned by the measurement allowlist |
| Solana | no (hashes and roots only) | ordering, staking, slashing |

Metering trusts the token counts the node reports. That holds because the
node code is measured and attested. The operator cannot change it without
changing the measurement.

## Mapping to the outline

| Outline item | Where | Status |
|---|---|---|
| 1. Client-side encryption | `packages/sealed` (X25519 → HKDF-SHA256 → AES-256-GCM, WebCrypto) | done |
| 1. Wallet-based auth, no KYC | x402 payment *is* the auth; no accounts or API keys | done |
| 1. Web/mobile app | — | not started; SDK is ready for it |
| 2. Confidential inference + remote attestation | `packages/attestation`, `packages/node-agent` (configfs-tsm quotes for TDX/SEV-SNP) | policy layer done; vendor quote verifiers to plug in |
| 2. ZK / MPC workloads | — | not started |
| 2. Attestation + receipts anchored on-chain | gateway `receipts.ts` + program `record_attestation`/`anchor_receipts` | program done; Solana client for posting is TODO |
| 3. x402 pay-per-request | gateway `app.ts` via `@x402/hono` + `@x402/svm` | done |
| 3. Per-token metering | `upto` scheme: authorize max, settle actual via `Settlement-Overrides` | done; needs a facilitator that supports `upto` |
| 3. Streaming micropayments | — | not started (`stream: true` is rejected for now) |
| 3. Agent session keys + spend limits | SDK `maxPerRequest` + `SessionBudget` | done (client-side) |
| 4. Provider network, staking | program `register_node`/`add_stake`/unbonding | done |
| 4. Scheduler / router | gateway `registry.ts` `selectNode` (model, tier, latency) | MVP; price/VRAM/region later |
| 4. Render / io.net / Akash / Nosana | — | not started |
| 4. Reputation, slashing, uptime proofs | program `slash`; gateway marks nodes unhealthy | slashing done; reputation/uptime later |
| 5. Token-gated tiers / governance | — | optional, not started |
| 6. OpenAI-compatible API, model catalog | `POST /v1/chat/completions`, `GET /v1/models` | done |
| 6. Zero-log policy, audit endpoints | access log is method/path/status only; `GET /v1/receipts/:id` | done |
| 7. RPC, indexer, KMS/HSM | — | not started |

## Payments in detail

- **Pricing.** Catalog prices are in atomic USDC per million tokens. Before a
  request runs, the gateway can't know its cost, so it quotes an upper bound:
  `max_tokens × output price + prompt bytes × input price`. UTF-8 bytes are
  always ≥ BPE tokens, and on the sealed path the gateway sizes the
  ciphertext, so no tokenizer is needed.
- **Validate before 402.** Malformed bodies, unknown models, `max_tokens`
  over the cap and "no attested node" all fail with 4xx/503 *before* the
  client is asked to pay.
- **`upto` vs `exact`.** With `upto` (escrow channel on SVM) the client
  authorizes the max and the gateway settles the metered amount via
  `setSettlementOverrides`. With `exact` the client pays the quoted max. The
  public x402.org facilitator supports only `exact` on Solana devnet (checked
  while building this), so the example config uses `exact`.
- **No charge on failure.** If the node errors, the handler returns ≥ 400 and the
  x402 middleware cancels instead of settling.

## Attestation in detail

`report_data = sha256(sealing_pubkey ‖ nonce) ‖ 0³²`. Verification
(`verifyAttestation`) checks platform allowlist, nonce, freshness, vendor
signature chain (delegated to a `PlatformVerifier`), measurement allowlist,
TCB status, debug mode, GPU CC evidence, and finally that `report_data` binds
the advertised sealing key. Tiers: `tee-gpu` (CPU TEE plus NVIDIA CC
evidence), `tee-cpu`, `untrusted`.

The gateway re-challenges every node on an interval shorter than
`policy.maxAgeMs`. Clients don't rely on that. `sealedChat` fetches evidence
with its **own** nonce and verifies it locally before sealing.

**Still to plug in** (each implements `PlatformVerifier`):
- Intel TDX: DCAP quote verification (PCK chain → TCB info / QE identity from Intel PCS).
- AMD SEV-SNP: VCEK chain from AMD KDS, report signature, TCB.
- NVIDIA H100/H200/B200 CC: NRAS or local GPU verifier; set `gpuAttested`.

Until these land, only `dev-insecure` evidence verifies. It is unsigned and
accepted only when a policy explicitly lists it.

## On-chain program (`programs/satoris`)

PDAs: `config`, `node[owner, node_id]`, `vault[node]` (token account owned by
the node PDA), `batch[index]`.

| Instruction | Signer | Effect |
|---|---|---|
| `initialize` | admin | set stake mint, treasury, authorities, min stake, unbonding period |
| `register_node` | owner | lock stake, record sealing key + measurement; tier = untrusted |
| `add_stake`, `update_node`, `begin_unbonding`, `withdraw_stake` | owner | stake lifecycle; `update_node` resets trust |
| `record_attestation` | attestation authority | must match registered key and measurement; sets tier + expiry |
| `anchor_receipts` | receipt authority (gateway) | stores a Merkle root of receipt leaves |
| `slash` | slash authority | moves stake to treasury, revokes trust; works during unbonding |

Quote verification runs off-chain because DCAP/SNP chains are too heavy for
on-chain compute. The attestation authority should become a multisig or a
quorum of independent verifiers.

## Next steps

See [ROADMAP.md](ROADMAP.md) for the phased plan.
