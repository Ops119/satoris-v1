/**
 * Remote attestation for inference nodes.
 *
 * A node proves three things before it gets traffic:
 *   1. It runs on genuine TEE hardware (vendor signature chain on the quote).
 *   2. It runs the exact image we expect (measurement on an allowlist).
 *   3. The sealing key clients encrypt to was generated inside that TEE
 *      (the key is bound into the quote's report_data together with a fresh nonce).
 *
 * (1) is vendor-specific crypto and is delegated to a {@link PlatformVerifier}
 * (Intel DCAP for TDX, AMD KDS/VCEK for SEV-SNP, NVIDIA NRAS or local
 * verifier for GPU confidential computing). Everything else — freshness, key
 * binding, measurement allowlist, debug/TCB policy and trust tiering — lives
 * here and is shared by the gateway, the SDK and on-chain registration.
 */
import { fromBase64, sha256, toBase64, toHex } from "@satoris/sealed";

export type TeePlatform = "intel-tdx" | "amd-sev-snp" | "dev-insecure";

export type TcbStatus = "UpToDate" | "SWHardeningNeeded" | "ConfigurationNeeded" | "OutOfDate" | "Revoked";

export type TrustTier = "tee-gpu" | "tee-cpu" | "untrusted";

export interface AttestationEvidence {
  platform: TeePlatform;
  /** Raw CPU TEE quote/report, base64. */
  quote: string;
  /** NVIDIA confidential-computing evidence for the attached GPU(s), base64. */
  gpuEvidence?: string;
  /** Node's X25519 sealing public key, base64 (32 bytes). */
  publicKey: string;
  /** Challenger-supplied nonce, hex. */
  nonce: string;
  /** When the node produced the quote, unix ms. */
  issuedAt: number;
}

/** What a platform verifier extracts after checking the vendor signature chain. */
export interface VerifiedClaims {
  platform: TeePlatform;
  /** Launch measurement (MRTD+RTMRs digest for TDX, MEASUREMENT for SNP), hex. */
  measurement: string;
  /** 64 bytes of report_data the guest put into the quote. */
  reportData: Uint8Array;
  tcbStatus: TcbStatus;
  debug: boolean;
  /** True only if GPU evidence was present and verified to be in CC mode. */
  gpuAttested: boolean;
}

export interface PlatformVerifier {
  readonly platform: TeePlatform;
  /** Must throw if the vendor signature chain or GPU evidence does not verify. */
  verify(evidence: AttestationEvidence): Promise<VerifiedClaims>;
}

export interface AttestationPolicy {
  allowedPlatforms: TeePlatform[];
  /** Hex launch measurements of approved node images. */
  allowedMeasurements: string[];
  allowedTcbStatus: TcbStatus[];
  /** Maximum age of a quote before the node must re-attest. */
  maxAgeMs: number;
  requireGpuAttestation: boolean;
  allowDebug: boolean;
}

export const DEFAULT_POLICY: Omit<AttestationPolicy, "allowedMeasurements"> = {
  allowedPlatforms: ["intel-tdx", "amd-sev-snp"],
  allowedTcbStatus: ["UpToDate"],
  maxAgeMs: 10 * 60 * 1000,
  requireGpuAttestation: true,
  allowDebug: false,
};

export interface AttestationResult {
  ok: boolean;
  tier: TrustTier;
  reasons: string[];
  claims?: VerifiedClaims;
  /** sha256 of the canonical evidence; this is what receipts and the chain reference. */
  evidenceHash: string;
}

/**
 * report_data layout (64 bytes): sha256(publicKey || nonce) || 32 zero bytes.
 * The node computes this inside the TEE when requesting a quote.
 */
export async function expectedReportData(publicKey: Uint8Array, nonceHex: string): Promise<Uint8Array> {
  const nonce = hexToBytes(nonceHex);
  const buf = new Uint8Array(publicKey.length + nonce.length);
  buf.set(publicKey, 0);
  buf.set(nonce, publicKey.length);
  const out = new Uint8Array(64);
  out.set(await sha256(buf), 0);
  return out;
}

export async function evidenceHash(evidence: AttestationEvidence): Promise<string> {
  const canonical = JSON.stringify({
    platform: evidence.platform,
    quote: evidence.quote,
    gpuEvidence: evidence.gpuEvidence ?? null,
    publicKey: evidence.publicKey,
    nonce: evidence.nonce,
    issuedAt: evidence.issuedAt,
  });
  return toHex(await sha256(canonical));
}

export function newNonce(): string {
  return toHex(globalThis.crypto.getRandomValues(new Uint8Array(32)));
}

export interface VerifyOptions {
  policy: AttestationPolicy;
  verifiers: PlatformVerifier[];
  /** If set, evidence must echo this nonce (challenge-response). */
  expectedNonce?: string;
  now?: number;
}

export async function verifyAttestation(
  evidence: AttestationEvidence,
  opts: VerifyOptions,
): Promise<AttestationResult> {
  const { policy } = opts;
  const now = opts.now ?? Date.now();
  const hash = await evidenceHash(evidence);
  const fail = (...reasons: string[]): AttestationResult => ({
    ok: false,
    tier: "untrusted",
    reasons,
    evidenceHash: hash,
  });

  if (!policy.allowedPlatforms.includes(evidence.platform)) {
    return fail(`platform ${evidence.platform} not allowed by policy`);
  }
  const verifier = opts.verifiers.find((v) => v.platform === evidence.platform);
  if (!verifier) return fail(`no verifier registered for ${evidence.platform}`);
  if (opts.expectedNonce !== undefined && evidence.nonce !== opts.expectedNonce) {
    return fail("nonce mismatch");
  }
  if (evidence.issuedAt > now + 60_000) return fail("evidence issued in the future");
  if (now - evidence.issuedAt > policy.maxAgeMs) return fail("evidence is stale");

  let claims: VerifiedClaims;
  try {
    claims = await verifier.verify(evidence);
  } catch (err) {
    return fail(`quote verification failed: ${(err as Error).message}`);
  }

  const reasons: string[] = [];
  if (claims.platform !== evidence.platform) reasons.push("verifier returned claims for a different platform");
  if (!policy.allowedMeasurements.includes(claims.measurement.toLowerCase())) {
    reasons.push(`measurement ${claims.measurement} not in allowlist`);
  }
  if (!policy.allowedTcbStatus.includes(claims.tcbStatus)) reasons.push(`TCB status ${claims.tcbStatus} not allowed`);
  if (claims.debug && !policy.allowDebug) reasons.push("TEE is in debug mode");
  if (policy.requireGpuAttestation && !claims.gpuAttested) reasons.push("GPU attestation required but missing");

  const publicKey = fromBase64(evidence.publicKey);
  if (publicKey.length !== 32) reasons.push("sealing key must be 32 bytes");
  else {
    const expected = await expectedReportData(publicKey, evidence.nonce);
    if (!bytesEqual(expected, claims.reportData)) reasons.push("report_data does not bind the sealing key and nonce");
  }

  if (reasons.length > 0) return { ...fail(...reasons), claims };
  return {
    ok: true,
    tier: claims.gpuAttested ? "tee-gpu" : "tee-cpu",
    reasons: [],
    claims,
    evidenceHash: hash,
  };
}

/**
 * Development-only verifier. The "quote" is unsigned JSON, so this proves
 * nothing; it exists so the full flow can run on a laptop. It only takes effect
 * if a policy explicitly lists "dev-insecure" in allowedPlatforms.
 */
export class DevInsecureVerifier implements PlatformVerifier {
  readonly platform = "dev-insecure" as const;

  async verify(evidence: AttestationEvidence): Promise<VerifiedClaims> {
    const body = JSON.parse(new TextDecoder().decode(fromBase64(evidence.quote))) as {
      measurement: string;
      reportData: string;
      gpu?: boolean;
    };
    return {
      platform: "dev-insecure",
      measurement: body.measurement,
      reportData: hexToBytes(body.reportData),
      tcbStatus: "UpToDate",
      debug: false,
      gpuAttested: body.gpu === true,
    };
  }
}

export async function createDevEvidence(opts: {
  publicKey: Uint8Array;
  nonce: string;
  measurement: string;
  gpu?: boolean;
  now?: number;
}): Promise<AttestationEvidence> {
  const reportData = await expectedReportData(opts.publicKey, opts.nonce);
  const quote = new TextEncoder().encode(
    JSON.stringify({ measurement: opts.measurement, reportData: toHex(reportData), gpu: opts.gpu ?? false }),
  );
  return {
    platform: "dev-insecure",
    quote: toBase64(quote),
    publicKey: toBase64(opts.publicKey),
    nonce: opts.nonce,
    issuedAt: opts.now ?? Date.now(),
  };
}

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) throw new Error("invalid hex");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}
