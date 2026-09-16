/**
 * Tests for the RelicONE Sealed Relic format reference implementation.
 * Cross-checked against encryption-spec.md wherever the spec states a
 * concrete number (header layout, iteration count, format version) — those
 * assertions use the spec's own literal values, not values imported from
 * crypto.ts, so a drift between code and spec would show up as a failure
 * here instead of silently breaking the "independent of the app" promise.
 */
import { describe, expect, it } from "vitest";

import { sealText, unsealText } from "./crypto";

const PASSPHRASE = "correct horse battery staple";

// encryption-spec.md's "Blob format" table (identical layout for v1 and v2).
const HEADER_LENGTH = 1 + 4 + 16 + 12; // version + iterations + salt + iv
const SALT_BYTES = 16;
const IV_BYTES = 12;
const GCM_TAG_BYTES = 16;
const PBKDF2_ITERATIONS = 600_000;

function corruptedCopy(blob: Uint8Array, index: number): Uint8Array {
  const copy = new Uint8Array(blob);
  copy[index] = copy[index] ^ 0xff;
  return copy;
}

/**
 * Builds a v1 blob (no AAD) exactly the way the pre-fix `sealText` used to,
 * so tests can confirm that format is still decryptable now that `sealText`
 * itself only ever writes v2. This is what an already-sealed, real v1 relic
 * looks like on the wire.
 */
async function sealTextV1NoAAD(
  plaintext: string,
  passphrase: string,
): Promise<Uint8Array> {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_BYTES));
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));

  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(passphrase.normalize("NFC")),
    "PBKDF2",
    false,
    ["deriveKey"],
  );
  const key = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"],
  );

  const header = new Uint8Array(HEADER_LENGTH);
  header[0] = 1;
  new DataView(header.buffer).setUint32(1, PBKDF2_ITERATIONS, false);
  header.set(salt, 5);
  header.set(iv, 5 + SALT_BYTES);

  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      key,
      new TextEncoder().encode(plaintext),
    ),
  );

  const blob = new Uint8Array(header.length + ciphertext.length);
  blob.set(header, 0);
  blob.set(ciphertext, header.length);
  return blob;
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

  // sealText always writes v2 today, whose header (version || iterations ||
  // salt || IV) is passed as AES-GCM AAD — tampering with any of it must
  // fail the auth tag check, not just incidentally break key derivation or
  // the IV. Cover one byte from each header field so a regression in any of
  // them is caught.
  it.each([
    ["a salt byte", 5],
    ["an IV byte", 5 + 16],
    ["an iteration-count byte", 1],
  ])("rejects when %s has been tampered with (v2, AAD)", async (_label, index) => {
    const blob = await sealText("secret", PASSPHRASE);
    expect(blob[0]).toBe(2); // sanity: this is exercising the v2/AAD path
    const tampered = corruptedCopy(blob, index);
    await expect(unsealText(tampered, PASSPHRASE)).rejects.toThrow();
  });

  it("decrypts a v1 blob (no AAD) correctly — protects already-sealed relics", async () => {
    const blob = await sealTextV1NoAAD("a relic sealed before v2 existed", PASSPHRASE);
    expect(blob[0]).toBe(1);
    await expect(unsealText(blob, PASSPHRASE)).resolves.toBe(
      "a relic sealed before v2 existed",
    );
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
  it("writes format version 2 (AAD-bound) as the first byte", async () => {
    const blob = await sealText("x", PASSPHRASE);
    expect(blob[0]).toBe(2);
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
