/**
 * Sealed envelopes: prompts are encrypted on the client to the X25519 key of an
 * attested TEE node, so the gateway (and anyone else on the path) only ever sees
 * ciphertext. The reply is encrypted under a key derived from the same exchange,
 * so only the original client can read it.
 *
 * Construction: ephemeral-static X25519 -> HKDF-SHA256 -> AES-256-GCM.
 * Clear pricing metadata (model, max_tokens) is bound as AAD, so a gateway that
 * lies about it to under- or over-bill makes decryption fail inside the node.
 *
 * Uses WebCrypto only, so it runs in Node >= 22, browsers and React Native
 * runtimes that expose `crypto.subtle` with X25519.
 */

export const SEALED_ALG = "X25519-HKDF-SHA256-A256GCM" as const;
export const SEALED_VERSION = 1 as const;

const REQUEST_INFO = "satoris/v1/request";
const RESPONSE_INFO = "satoris/v1/response";

export interface SealedEnvelope {
  v: typeof SEALED_VERSION;
  alg: typeof SEALED_ALG;
  /** Key id of the recipient public key (see {@link keyId}). */
  kid: string;
  /** Sender's ephemeral X25519 public key, base64. Omitted on replies. */
  epk?: string;
  nonce: string;
  ct: string;
}

/** Clear metadata the gateway needs for pricing and routing; bound as AAD. */
export interface SealedMeta {
  model: string;
  max_tokens: number;
}

export interface NodeKeyPair {
  publicKey: Uint8Array;
  privateKey: CryptoKey;
}

const subtle = globalThis.crypto.subtle;

/** WebCrypto typings want ArrayBuffer-backed views; none of ours are shared buffers. */
const bs = (u: Uint8Array) => u as Uint8Array<ArrayBuffer>;
const enc = new TextEncoder();
const dec = new TextDecoder();

export function toBase64(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

export function fromBase64(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export async function sha256(data: Uint8Array | string): Promise<Uint8Array> {
  const bytes = typeof data === "string" ? enc.encode(data) : data;
  return new Uint8Array(await subtle.digest("SHA-256", bs(bytes)));
}

export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

/** Short, stable identifier for a public key: hex(sha256(pub))[0..32]. */
export async function keyId(publicKey: Uint8Array): Promise<string> {
  return toHex(await sha256(publicKey)).slice(0, 32);
}

/** Canonical AAD for metadata: fixed key order so both sides agree byte-for-byte. */
export function metaAad(meta: SealedMeta): Uint8Array {
  return enc.encode(JSON.stringify({ model: meta.model, max_tokens: meta.max_tokens }));
}

export async function generateNodeKeyPair(): Promise<NodeKeyPair> {
  const kp = (await subtle.generateKey({ name: "X25519" }, true, ["deriveBits"])) as CryptoKeyPair;
  const publicKey = new Uint8Array(await subtle.exportKey("raw", kp.publicKey));
  return { publicKey, privateKey: kp.privateKey };
}

async function importPublic(raw: Uint8Array): Promise<CryptoKey> {
  if (raw.length !== 32) throw new Error("X25519 public key must be 32 bytes");
  return subtle.importKey("raw", bs(raw), { name: "X25519" }, true, []);
}

async function deriveKeys(
  privateKey: CryptoKey,
  peerPublic: CryptoKey,
  salt: Uint8Array,
): Promise<{ request: CryptoKey; response: CryptoKey }> {
  const shared = await subtle.deriveBits({ name: "X25519", public: peerPublic }, privateKey, 256);
  const ikm = await subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
  const derive = (info: string) =>
    subtle.deriveKey(
      { name: "HKDF", hash: "SHA-256", salt: bs(salt), info: enc.encode(info) },
      ikm,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"],
    );
  return { request: await derive(REQUEST_INFO), response: await derive(RESPONSE_INFO) };
}

function randomNonce(): Uint8Array {
  return globalThis.crypto.getRandomValues(new Uint8Array(12));
}

/** Handle the client keeps to decrypt the node's reply. */
export interface ReplyOpener {
  open(envelope: SealedEnvelope): Promise<Uint8Array>;
  openJson<T = unknown>(envelope: SealedEnvelope): Promise<T>;
}

/** Handle the node uses to encrypt its reply back to the client. */
export interface ReplySealer {
  seal(plaintext: Uint8Array): Promise<SealedEnvelope>;
  sealJson(value: unknown): Promise<SealedEnvelope>;
}

/**
 * Client side: encrypt `plaintext` to a node's attested public key.
 * The salt is the recipient's public key concatenated with the ephemeral key,
 * which binds the derived keys to this exact exchange.
 */
export async function seal(
  plaintext: Uint8Array,
  recipientPublicKey: Uint8Array,
  meta: SealedMeta,
): Promise<{ envelope: SealedEnvelope; reply: ReplyOpener }> {
  const eph = (await subtle.generateKey({ name: "X25519" }, true, ["deriveBits"])) as CryptoKeyPair;
  const epk = new Uint8Array(await subtle.exportKey("raw", eph.publicKey));
  const salt = concat(recipientPublicKey, epk);
  const keys = await deriveKeys(eph.privateKey, await importPublic(recipientPublicKey), salt);
  const aad = metaAad(meta);
  const nonce = randomNonce();
  const ct = new Uint8Array(
    await subtle.encrypt({ name: "AES-GCM", iv: bs(nonce), additionalData: bs(aad) }, keys.request, bs(plaintext)),
  );
  const kid = await keyId(recipientPublicKey);
  const envelope: SealedEnvelope = {
    v: SEALED_VERSION,
    alg: SEALED_ALG,
    kid,
    epk: toBase64(epk),
    nonce: toBase64(nonce),
    ct: toBase64(ct),
  };
  const open = async (env: SealedEnvelope) => {
    assertEnvelope(env);
    return new Uint8Array(
      await subtle.decrypt(
        { name: "AES-GCM", iv: bs(fromBase64(env.nonce)), additionalData: bs(aad) },
        keys.response,
        bs(fromBase64(env.ct)),
      ),
    );
  };
  return {
    envelope,
    reply: {
      open,
      openJson: async <T>(env: SealedEnvelope) => JSON.parse(dec.decode(await open(env))) as T,
    },
  };
}

export async function sealJson(value: unknown, recipientPublicKey: Uint8Array, meta: SealedMeta) {
  return seal(enc.encode(JSON.stringify(value)), recipientPublicKey, meta);
}

/**
 * Node side: decrypt an envelope with the node's private key. Throws if the
 * ciphertext or the clear metadata was tampered with.
 */
export async function open(
  envelope: SealedEnvelope,
  node: NodeKeyPair,
  meta: SealedMeta,
): Promise<{ plaintext: Uint8Array; reply: ReplySealer }> {
  assertEnvelope(envelope);
  if (!envelope.epk) throw new Error("request envelope is missing epk");
  const expectedKid = await keyId(node.publicKey);
  if (envelope.kid !== expectedKid) throw new Error("envelope was sealed to a different key");
  const epk = fromBase64(envelope.epk);
  const keys = await deriveKeys(node.privateKey, await importPublic(epk), concat(node.publicKey, epk));
  const aad = metaAad(meta);
  const plaintext = new Uint8Array(
    await subtle.decrypt(
      { name: "AES-GCM", iv: bs(fromBase64(envelope.nonce)), additionalData: bs(aad) },
      keys.request,
      bs(fromBase64(envelope.ct)),
    ),
  );
  const sealReply = async (data: Uint8Array): Promise<SealedEnvelope> => {
    const nonce = randomNonce();
    const ct = new Uint8Array(
      await subtle.encrypt({ name: "AES-GCM", iv: bs(nonce), additionalData: bs(aad) }, keys.response, bs(data)),
    );
    return {
      v: SEALED_VERSION,
      alg: SEALED_ALG,
      kid: expectedKid,
      nonce: toBase64(nonce),
      ct: toBase64(ct),
    };
  };
  return {
    plaintext,
    reply: { seal: sealReply, sealJson: (value) => sealReply(enc.encode(JSON.stringify(value))) },
  };
}

export async function openJson<T = unknown>(envelope: SealedEnvelope, node: NodeKeyPair, meta: SealedMeta) {
  const { plaintext, reply } = await open(envelope, node, meta);
  return { value: JSON.parse(dec.decode(plaintext)) as T, reply };
}

export function isSealedEnvelope(value: unknown): value is SealedEnvelope {
  if (typeof value !== "object" || value === null) return false;
  const v = value as Record<string, unknown>;
  return (
    v.v === SEALED_VERSION &&
    v.alg === SEALED_ALG &&
    typeof v.kid === "string" &&
    typeof v.nonce === "string" &&
    typeof v.ct === "string" &&
    (v.epk === undefined || typeof v.epk === "string")
  );
}

function assertEnvelope(env: SealedEnvelope) {
  if (!isSealedEnvelope(env)) throw new Error("malformed sealed envelope");
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

export * from "./wire.js";
