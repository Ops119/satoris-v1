import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join } from "node:path";
import {
  type AttestationEvidence,
  type TeePlatform,
  createDevEvidence,
  expectedReportData,
} from "@satoris/attestation";
import { toBase64 } from "@satoris/sealed";

/** Produces attestation evidence binding `publicKey` and `nonce` into a hardware quote. */
export interface QuoteProvider {
  readonly platform: TeePlatform;
  getEvidence(publicKey: Uint8Array, nonce: string): Promise<AttestationEvidence>;
}

/** Collects NVIDIA confidential-computing evidence for the attached GPU(s). */
export interface GpuEvidenceProvider {
  getEvidence(nonce: string): Promise<string>;
}

const TSM_REPORT_DIR = "/sys/kernel/config/tsm/report";

/**
 * Real quotes via the Linux configfs-tsm ABI (kernel >= 6.7), which fronts both
 * Intel TDX and AMD SEV-SNP guests: write 64 bytes of report_data to `inblob`,
 * read the signed quote/report back from `outblob`.
 */
export class ConfigfsTsmQuoteProvider implements QuoteProvider {
  constructor(
    readonly platform: Exclude<TeePlatform, "dev-insecure">,
    private readonly gpu?: GpuEvidenceProvider,
    private readonly reportDir = TSM_REPORT_DIR,
  ) {}

  static available(reportDir = TSM_REPORT_DIR): boolean {
    return existsSync(reportDir);
  }

  async getEvidence(publicKey: Uint8Array, nonce: string): Promise<AttestationEvidence> {
    const reportData = await expectedReportData(publicKey, nonce);
    const entry = await mkdtemp(join(this.reportDir, "satoris-"));
    try {
      await writeFile(join(entry, "inblob"), reportData);
      const quote = new Uint8Array(await readFile(join(entry, "outblob")));
      return {
        platform: this.platform,
        quote: toBase64(quote),
        gpuEvidence: this.gpu ? await this.gpu.getEvidence(nonce) : undefined,
        publicKey: toBase64(publicKey),
        nonce,
        issuedAt: Date.now(),
      };
    } finally {
      await rm(entry, { recursive: true, force: true });
    }
  }
}

/** Unsigned evidence for local development. Gateways reject it unless policy allows "dev-insecure". */
export class DevQuoteProvider implements QuoteProvider {
  readonly platform = "dev-insecure" as const;

  constructor(
    private readonly measurement: string,
    private readonly gpu = false,
  ) {}

  getEvidence(publicKey: Uint8Array, nonce: string): Promise<AttestationEvidence> {
    return createDevEvidence({ publicKey, nonce, measurement: this.measurement, gpu: this.gpu });
  }
}
