/**
 * Tests for the RelicONE Sealed Relic format v1 reference implementation.
 * Cross-checked against encryption-spec.md wherever the spec states a
 * concrete number (header layout, iteration count, format version) — those
 * assertions use the spec's own literal values, not values imported from
 * crypto.ts, so a drift between code and spec would show up as a failure
 * here instead of silently breaking the "independent of the app" promise.
 */
import { describe, expect, it } from "vitest";

import { sealText, unsealText } from "./crypto";

const PASSPHRASE = "correct horse battery staple";

// encryption-spec.md's "Blob format (version 1)" table.
const HEADER_LENGTH = 1 + 4 + 16 + 12; // version + iterations + salt + iv
const GCM_TAG_BYTES = 16;

function corruptedCopy(blob: Uint8Array, index: number): Uint8Array {
  const copy = new Uint8Array(blob);
  copy[index] = copy[index] ^ 0xff;
  return copy;
}

describe("sealText / unsealText round trip", () => {
  it("recovers the original plaintext with the correct passphrase", async () => {
    const plaintext = "The lighthouse keeper's log, entry #12.";
    const blob = await sealText(plaintext, PASSPHRASE);
    await expect(unsealText(blob, PASSPHRASE)).resolves.toBe(plaintext);
  });

  it("round-trips multi-byte UTF-8 content (emoji, diacritics, CJK)", async () => {
    const plaintext = "любовь непреходяща 🌊 café — 永遠";
    const blob = await sealText(plaintext, PASSPHRASE);
    await expect(unsealText(blob, PASSPHRASE)).resolves.toBe(plaintext);
  });

  it("round-trips an empty plaintext", async () => {
    const blob = await sealText("", PASSPHRASE);
    await expect(unsealText(blob, PASSPHRASE)).resolves.toBe("");
  });

  it("produces a different blob each time, even for identical input", async () => {
    const a = await sealText("same content", PASSPHRASE);
    const b = await sealText("same content", PASSPHRASE);
    // Random salt + IV per seal (spec: unique per relic) — two seals of
    // identical plaintext/passphrase must not collide.
    expect(a).not.toEqual(b);
  });
});

describe("passphrase normalization (NFC)", () => {
  it("treats NFC- and NFD-encoded forms of the same visible passphrase as identical", async () => {
    const nfc = "café secret";
    const nfd = nfc.normalize("NFD");
    // Sanity check the two forms are actually different byte sequences —
    // otherwise this test would pass for the wrong reason.
    expect(nfc).not.toBe(nfd);

    const blob = await sealText("what remains", nfc);
    await expect(unsealText(blob, nfd)).resolves.toBe("what remains");
  });
});

describe("wrong passphrase / tampered data", () => {
  it("rejects when unsealing with the wrong passphrase", async () => {
    const blob = await sealText("secret", PASSPHRASE);
    await expect(unsealText(blob, "wrong passphrase")).rejects.toThrow();
  });

  it("rejects when the ciphertext has been tampered with", async () => {
    const blob = await sealText("secret", PASSPHRASE);
    const tampered = corruptedCopy(blob, HEADER_LENGTH);
    await expect(unsealText(tampered, PASSPHRASE)).rejects.toThrow();
  });

  it("rejects a blob that's too short to be a real sealed relic", async () => {
    const tooShort = new Uint8Array(HEADER_LENGTH + GCM_TAG_BYTES - 1);
    await expect(unsealText(tooShort, PASSPHRASE)).rejects.toThrow(
      /too short/,
    );
  });

  it("rejects an unsupported format version", async () => {
    const blob = await sealText("secret", PASSPHRASE);
    const wrongVersion = new Uint8Array(blob);
    wrongVersion[0] = 99;
    await expect(unsealText(wrongVersion, PASSPHRASE)).rejects.toThrow(
      /Unsupported sealed relic format version: 99/,
    );
  });

  it("rejects an implausible PBKDF2 iteration count instead of hanging on it", async () => {
    const blob = await sealText("secret", PASSPHRASE);
    const bogus = new Uint8Array(blob);
    new DataView(bogus.buffer).setUint32(1, 50_000_000, false);
    await expect(unsealText(bogus, PASSPHRASE)).rejects.toThrow(
      /iteration count is implausible/,
    );
  });

  it("rejects a zero iteration count", async () => {
    const blob = await sealText("secret", PASSPHRASE);
    const zeroIterations = new Uint8Array(blob);
    new DataView(zeroIterations.buffer).setUint32(1, 0, false);
    await expect(unsealText(zeroIterations, PASSPHRASE)).rejects.toThrow(
      /iteration count is implausible/,
    );
  });
});

describe("blob format (encryption-spec.md conformance)", () => {
  it("writes format version 1 as the first byte", async () => {
    const blob = await sealText("x", PASSPHRASE);
    expect(blob[0]).toBe(1);
  });

  it("writes the iteration count as a big-endian uint32 matching the spec's 600,000", async () => {
    const blob = await sealText("x", PASSPHRASE);
    const iterations = new DataView(blob.buffer).getUint32(1, false);
    expect(iterations).toBe(600_000);
  });

  it("produces a blob of exactly header + plaintext + GCM tag length", async () => {
    const plaintext = "twelve bytes"; // 12 UTF-8 bytes
    const blob = await sealText(plaintext, PASSPHRASE);
    const plaintextBytes = new TextEncoder().encode(plaintext).byteLength;
    expect(blob.byteLength).toBe(
      HEADER_LENGTH + plaintextBytes + GCM_TAG_BYTES,
    );
  });
});

describe("Web Crypto availability guard", () => {
  it("refuses to run without window.crypto.subtle instead of failing silently", async () => {
    const realCrypto = window.crypto;
    // @ts-expect-error — deliberately simulating an environment without it
    delete window.crypto;
    try {
      await expect(sealText("x", PASSPHRASE)).rejects.toThrow(
        /Web Crypto API is not available/,
      );
    } finally {
      Object.defineProperty(window, "crypto", {
        value: realCrypto,
        configurable: true,
      });
    }
  });
});
