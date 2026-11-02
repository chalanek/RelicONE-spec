/**
 * Conformance tests for version 4 (file / artifact) of the Sealed Relic
 * format. Like crypto.test.ts, assertions use the literal numbers from
 * encryption-spec.md ("Version 4 — files (artifacts)"), not constants
 * imported from crypto.ts, so a drift between code and spec fails here.
 */
import { describe, expect, it } from "vitest";

import { sealArtifact, sealText, unsealArtifact, unsealText } from "./crypto";

const PASSPHRASE = "correct horse battery staple";
const HEADER_LENGTH = 33;
const GCM_TAG_BYTES = 16;

describe("version 4 — files (artifacts)", () => {
  it("round-trips bytes, mime type and file name", async () => {
    const bytes = new Uint8Array([0, 1, 2, 3, 250, 251, 252, 253, 254, 255]);
    const blob = await sealArtifact(bytes, "image/png", "päť.png", PASSPHRASE);
    const out = await unsealArtifact(blob, PASSPHRASE);
    expect(out.mimeType).toBe("image/png");
    expect(out.fileName).toBe("päť.png");
    expect(Array.from(out.bytes)).toEqual(Array.from(bytes));
  });

  it("writes version byte 0x04 and the exact blob length from the spec", async () => {
    const bytes = new Uint8Array(100);
    const mime = "audio/ogg";
    const name = "a.ogg";
    const blob = await sealArtifact(bytes, mime, name, PASSPHRASE);
    expect(blob[0]).toBe(0x04);
    // spec: 33 + (1 + N + 1 + M + file size) + 16
    expect(blob.byteLength).toBe(
      HEADER_LENGTH + (1 + mime.length + 1 + name.length + bytes.length) + GCM_TAG_BYTES,
    );
  });

  it("allows an empty file name and empty file", async () => {
    const blob = await sealArtifact(new Uint8Array(0), "application/octet-stream", "", PASSPHRASE);
    const out = await unsealArtifact(blob, PASSPHRASE);
    expect(out.fileName).toBe("");
    expect(out.bytes.byteLength).toBe(0);
  });

  it("binds the header as AAD (tampering with the header fails)", async () => {
    const blob = await sealArtifact(new Uint8Array([1, 2, 3]), "text/plain", "x.txt", PASSPHRASE);
    for (const index of [1, 5, 20]) {
      const copy = new Uint8Array(blob);
      copy[index] ^= 0xff;
      await expect(unsealArtifact(copy, PASSPHRASE)).rejects.toThrow();
    }
  });

  it("fails on a wrong passphrase", async () => {
    const blob = await sealArtifact(new Uint8Array([1]), "text/plain", "", PASSPHRASE);
    await expect(unsealArtifact(blob, "wrong passphrase here")).rejects.toThrow();
  });

  it("a text-only reader refuses 0x04 explicitly", async () => {
    const blob = await sealArtifact(new Uint8Array([1]), "text/plain", "", PASSPHRASE);
    await expect(unsealText(blob, PASSPHRASE)).rejects.toThrow();
  });

  it("a file reader refuses a text relic", async () => {
    const blob = await sealText("hello", PASSPHRASE);
    await expect(unsealArtifact(blob, PASSPHRASE)).rejects.toThrow();
  });
});
