/**
 * Tests for the version-3 multi-key (M-of-N) format — see
 * multi-key-encryption-spec.md for the specification these assertions are
 * checked against, and crypto.ts for the reference implementation
 * (sealMultiKey / unsealMultiKey / readMultiKeyParticipants /
 * unwrapMultiKeyShare).
 *
 * The expensive fixtures (full seals, each doing one PBKDF2 derivation per
 * participant) are built once in beforeAll and reused across the tests that
 * only need to read them — real 600,000-iteration PBKDF2 calls are slow
 * enough (~500ms each in this environment) that re-sealing per assertion
 * would make this file take minutes instead of seconds.
 */
import { beforeAll, describe, expect, it } from "vitest";

import {
  readMultiKeyParticipants,
  sealMultiKey,
  unsealMultiKey,
  unwrapMultiKeyShare,
} from "./crypto";

const PLAINTEXT = "the vault combination is written on the back of the photo";

function corruptedCopy(blob: Uint8Array, index: number): Uint8Array {
  const copy = new Uint8Array(blob);
  copy[index] = copy[index] ^ 0xff;
  return copy;
}

describe("sealMultiKey validation (no crypto work — must throw before any PBKDF2 call)", () => {
  it("rejects a single participant", async () => {
    await expect(
      sealMultiKey(PLAINTEXT, [{ label: "Alice", passphrase: "correct horse battery staple" }], 1),
    ).rejects.toThrow(/between 2 and 255 participants/);
  });

  it("rejects more participants than the SSS library supports", async () => {
    const tooMany = Array.from({ length: 256 }, (_, i) => ({
      label: `p${i}`,
      passphrase: "correct horse battery staple",
    }));
    await expect(sealMultiKey(PLAINTEXT, tooMany, 2)).rejects.toThrow(/between 2 and 255/);
  });

  it("rejects a threshold below 2", async () => {
    const participants = [
      { label: "Alice", passphrase: "aaaaaaaaaaaa" },
      { label: "Bob", passphrase: "bbbbbbbbbbbb" },
    ];
    await expect(sealMultiKey(PLAINTEXT, participants, 1)).rejects.toThrow(/threshold/);
  });

  it("rejects a threshold greater than the participant count", async () => {
    const participants = [
      { label: "Alice", passphrase: "aaaaaaaaaaaa" },
      { label: "Bob", passphrase: "bbbbbbbbbbbb" },
    ];
    await expect(sealMultiKey(PLAINTEXT, participants, 3)).rejects.toThrow(/threshold/);
  });
});

describe("round trip (2-of-3)", () => {
  const participants = [
    { label: "Alice", passphrase: "correct horse battery staple" },
    { label: "Bob", passphrase: "another wholly different phrase" },
    { label: "Carol", passphrase: "a third independent secret" },
  ];
  let blob: Uint8Array;

  beforeAll(async () => {
    blob = await sealMultiKey(PLAINTEXT, participants, 2);
  });

  it("exposes participant labels and the threshold without any passphrase", () => {
    const info = readMultiKeyParticipants(blob);
    expect(info.threshold).toBe(2);
    expect(info.participants).toEqual([
      { label: "Alice", index: 0 },
      { label: "Bob", index: 1 },
      { label: "Carol", index: 2 },
    ]);
  });

  it("unseals with Alice + Bob's shares", async () => {
    const a = await unwrapMultiKeyShare(blob, 0, participants[0].passphrase);
    const b = await unwrapMultiKeyShare(blob, 1, participants[1].passphrase);
    await expect(unsealMultiKey(blob, [a, b])).resolves.toBe(PLAINTEXT);
  });

  it("unseals with any other 2-of-3 subset (Alice + Carol)", async () => {
    const a = await unwrapMultiKeyShare(blob, 0, participants[0].passphrase);
    const c = await unwrapMultiKeyShare(blob, 2, participants[2].passphrase);
    await expect(unsealMultiKey(blob, [a, c])).resolves.toBe(PLAINTEXT);
  });

  it("unseals with all 3 shares present, not just the threshold", async () => {
    const a = await unwrapMultiKeyShare(blob, 0, participants[0].passphrase);
    const b = await unwrapMultiKeyShare(blob, 1, participants[1].passphrase);
    const c = await unwrapMultiKeyShare(blob, 2, participants[2].passphrase);
    await expect(unsealMultiKey(blob, [a, b, c])).resolves.toBe(PLAINTEXT);
  });

  it("rejects a wrong passphrase for one specific participant, independent of the others", async () => {
    await expect(unwrapMultiKeyShare(blob, 1, "not bob's real passphrase")).rejects.toThrow();
    // Bob's failure doesn't affect Alice's own, independent wrap.
    await expect(
      unwrapMultiKeyShare(blob, 0, participants[0].passphrase),
    ).resolves.toBeInstanceOf(Uint8Array);
  });

  it("rejects an out-of-range participant index", async () => {
    await expect(unwrapMultiKeyShare(blob, 99, "anything")).rejects.toThrow(
      /Invalid participant index/,
    );
  });

  it("refuses to attempt reconstruction with fewer than the threshold's worth of shares", async () => {
    const a = await unwrapMultiKeyShare(blob, 0, participants[0].passphrase);
    await expect(unsealMultiKey(blob, [a])).rejects.toThrow(/at least 2/);
  });
});

describe("two participants with the same passphrase", () => {
  it("produces independent shares — the passphrase never determines the share's value", async () => {
    const passphrase = "shared by coincidence, not by design";
    const blob = await sealMultiKey(
      PLAINTEXT,
      [
        { label: "Alice", passphrase },
        { label: "Bob", passphrase },
      ],
      2,
    );
    const a = await unwrapMultiKeyShare(blob, 0, passphrase);
    const b = await unwrapMultiKeyShare(blob, 1, passphrase);
    expect(a).not.toEqual(b);
    await expect(unsealMultiKey(blob, [a, b])).resolves.toBe(PLAINTEXT);
  });
});

describe("tampering", () => {
  const participants = [
    { label: "Alice", passphrase: "correct horse battery staple" },
    { label: "Bob", passphrase: "another wholly different phrase" },
  ];
  let blob: Uint8Array;

  beforeAll(async () => {
    blob = await sealMultiKey(PLAINTEXT, participants, 2);
  });

  it("rejects an unsupported format version byte", () => {
    const tampered = corruptedCopy(blob, 0);
    expect(() => readMultiKeyParticipants(tampered)).toThrow(
      /Unsupported sealed relic format version/,
    );
  });

  it("rejects a blob claiming an implausible participant/threshold count", () => {
    const tampered = new Uint8Array(blob);
    tampered[2] = 250; // threshold > actual participant count (still 2 at byte[1])
    expect(() => readMultiKeyParticipants(tampered)).toThrow(/implausible/);
  });

  it("fails a specific participant's own unwrap when their salt is corrupted (AAD binding)", async () => {
    // Byte offset 2 (labelLength) + label bytes ("Alice" = 5) + 4 (iterations)
    // = start of Alice's 16-byte salt, per the record layout in
    // docs/multi-key-encryption-spec.md.
    const aliceSaltOffset = 3 + 1 + "Alice".length + 4;
    const tampered = corruptedCopy(blob, aliceSaltOffset);
    await expect(
      unwrapMultiKeyShare(tampered, 0, participants[0].passphrase),
    ).rejects.toThrow();
  });

  it("fails final decryption when the ciphertext is tampered with, even though every share unwrapped cleanly", async () => {
    const a = await unwrapMultiKeyShare(blob, 0, participants[0].passphrase);
    const b = await unwrapMultiKeyShare(blob, 1, participants[1].passphrase);
    const tampered = corruptedCopy(blob, blob.byteLength - 1);
    await expect(unsealMultiKey(tampered, [a, b])).rejects.toThrow();
  });

  it("rejects a blob too short to contain even a minimal header", () => {
    expect(() => readMultiKeyParticipants(new Uint8Array([3, 2, 2]))).toThrow(
      /too short/,
    );
  });
});

describe("shares that individually unwrap but don't belong together", () => {
  it("fails at final content decryption, not silently — combine() itself doesn't validate", async () => {
    const blobA = await sealMultiKey(
      "relic A's actual content",
      [
        { label: "Alice", passphrase: "alice's real passphrase for A" },
        { label: "Bob", passphrase: "bob's real passphrase for A" },
      ],
      2,
    );
    const blobB = await sealMultiKey(
      "relic B's actual content",
      [
        { label: "Alice", passphrase: "alice's real passphrase for B" },
        { label: "Bob", passphrase: "bob's real passphrase for B" },
      ],
      2,
    );

    const shareAFromA = await unwrapMultiKeyShare(blobA, 0, "alice's real passphrase for A");
    const shareBFromB = await unwrapMultiKeyShare(blobB, 1, "bob's real passphrase for B");

    // Both individual unwraps succeeded above — the mismatch can only be
    // caught once reconstruction is attempted against either blob's own
    // final AES-GCM tag.
    await expect(unsealMultiKey(blobA, [shareAFromA, shareBFromB])).rejects.toThrow();
  });
});

describe("blob format (docs/multi-key-encryption-spec.md conformance)", () => {
  it("writes format version 3 as the first byte, N and M as the next two", async () => {
    const participants = [
      { label: "Alice", passphrase: "aaaaaaaaaaaa" },
      { label: "Bob", passphrase: "bbbbbbbbbbbb" },
      { label: "Carol", passphrase: "cccccccccccc" },
    ];
    const blob = await sealMultiKey(PLAINTEXT, participants, 2);
    expect(blob[0]).toBe(3);
    expect(blob[1]).toBe(3); // N
    expect(blob[2]).toBe(2); // M
  });

  it("round-trips a participant label containing multi-byte UTF-8 characters", async () => {
    const participants = [
      { label: "Aliçe 🔑", passphrase: "aaaaaaaaaaaa" },
      { label: "Bob", passphrase: "bbbbbbbbbbbb" },
    ];
    const blob = await sealMultiKey(PLAINTEXT, participants, 2);
    const info = readMultiKeyParticipants(blob);
    expect(info.participants[0].label).toBe("Aliçe 🔑");
  });
});
