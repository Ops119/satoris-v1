import { describe, expect, it } from "vitest";
import { generateNodeKeyPair, keyId, open, openJson, seal, sealJson } from "../src/index.js";

const meta = { model: "m", max_tokens: 64 };

describe("sealed envelopes", () => {
  it("round-trips a request and its reply", async () => {
    const node = await generateNodeKeyPair();
    const { envelope, reply } = await sealJson({ hello: "world" }, node.publicKey, meta);
    expect(envelope.kid).toBe(await keyId(node.publicKey));
    expect(JSON.stringify(envelope)).not.toContain("world");

    const opened = await openJson<{ hello: string }>(envelope, node, meta);
    expect(opened.value).toEqual({ hello: "world" });

    const answer = await opened.reply.sealJson({ answer: 42 });
    expect(answer.epk).toBeUndefined();
    expect(await reply.openJson(answer)).toEqual({ answer: 42 });
  });

  it("fails when the clear metadata is altered", async () => {
    const node = await generateNodeKeyPair();
    const { envelope } = await seal(new TextEncoder().encode("hi"), node.publicKey, meta);
    await expect(open(envelope, node, { ...meta, max_tokens: 1 })).rejects.toThrow();
    await expect(open(envelope, node, { ...meta, model: "cheaper" })).rejects.toThrow();
  });

  it("fails for a different node key or tampered ciphertext", async () => {
    const node = await generateNodeKeyPair();
    const other = await generateNodeKeyPair();
    const { envelope } = await seal(new TextEncoder().encode("hi"), node.publicKey, meta);
    await expect(open(envelope, other, meta)).rejects.toThrow(/different key/);

    const ct = Buffer.from(envelope.ct, "base64");
    ct[0]! ^= 1;
    await expect(open({ ...envelope, ct: ct.toString("base64") }, node, meta)).rejects.toThrow();
  });

  it("does not let a reply be replayed as a different exchange", async () => {
    const node = await generateNodeKeyPair();
    const a = await sealJson({ n: 1 }, node.publicKey, meta);
    const b = await sealJson({ n: 2 }, node.publicKey, meta);
    const replyA = await (await openJson(a.envelope, node, meta)).reply.sealJson({ for: "a" });
    await expect(b.reply.open(replyA)).rejects.toThrow();
  });
});
