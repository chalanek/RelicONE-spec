/**
 * Tests for the offline CLI decryptor (relicone-decrypt.ts). Covers the
 * CLI's own argument/prompt/output handling — not just unsealText, which
 * crypto.test.ts already covers — plus a real round trip run as a
 * subprocess under plain `node`, to confirm it works without ts-node/tsx or
 * any other dev-only TypeScript runner.
 */
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { sealMultiKey, sealText } from "./crypto";
import { parseArgs, resolveBlob, run } from "./relicone-decrypt";

const PASSPHRASE = "correct horse battery staple";
const PLAINTEXT = "The lighthouse keeper's log, entry #12.";
const CLI_PATH = join(dirname(fileURLToPath(import.meta.url)), "relicone-decrypt.ts");

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "relicone-decrypt-test-"));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe("parseArgs", () => {
  it("parses a bare transaction id / path", () => {
    expect(parseArgs(["some-tx-id"])).toEqual({ input: "some-tx-id" });
  });

  it("parses an --out flag alongside the positional argument", () => {
    expect(parseArgs(["some-tx-id", "--out", "relic.txt"])).toEqual({
      input: "some-tx-id",
      outFile: "relic.txt",
    });
    expect(parseArgs(["--out", "relic.txt", "some-tx-id"])).toEqual({
      input: "some-tx-id",
      outFile: "relic.txt",
    });
  });

  it("throws when no positional argument is given", () => {
    expect(() => parseArgs([])).toThrow(/usage/i);
    expect(() => parseArgs(["--out", "relic.txt"])).toThrow(/usage/i);
  });

  it("throws when --out is missing its value", () => {
    expect(() => parseArgs(["some-tx-id", "--out"])).toThrow(
      /--out requires a file path/,
    );
  });

  it("throws on a second, unexpected positional argument", () => {
    expect(() => parseArgs(["some-tx-id", "extra"])).toThrow(
      /unexpected argument/i,
    );
  });
});

describe("resolveBlob", () => {
  it("reads a local file directly when the input path exists, without touching the network", async () => {
    const blob = await sealText(PLAINTEXT, PASSPHRASE);
    const filePath = join(dir, "relic.bin");
    writeFileSync(filePath, blob);

    const fetchImpl = vi.fn();
    const resolved = await resolveBlob(filePath, fetchImpl);

    expect(resolved).toEqual(blob);
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("fetches from the Arweave gateway when the input isn't an existing local path", async () => {
    const blob = await sealText(PLAINTEXT, PASSPHRASE);
    const fetchImpl = vi.fn(async (url: string) => {
      expect(url).toBe("https://arweave.net/some-tx-id");
      return new Response(blob as BodyInit, { status: 200 });
    });

    const resolved = await resolveBlob("some-tx-id", fetchImpl);
    expect(resolved).toEqual(blob);
  });

  it("throws a clear error when the gateway responds with a non-OK status", async () => {
    const fetchImpl = vi.fn(async () => new Response(null, { status: 404 }));
    await expect(resolveBlob("missing-tx-id", fetchImpl)).rejects.toThrow(
      /HTTP 404/,
    );
  });
});

describe("run (decrypt-from-file path, in-process)", () => {
  it("decrypts a local file and prints the plaintext to stdout", async () => {
    const blob = await sealText(PLAINTEXT, PASSPHRASE);
    const filePath = join(dir, "relic.bin");
    writeFileSync(filePath, blob);

    const writeSpy = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
    try {
      await run([filePath], { promptPassphraseImpl: async () => PASSPHRASE });
      expect(writeSpy).toHaveBeenCalledWith(PLAINTEXT);
    } finally {
      writeSpy.mockRestore();
    }
  });

  it("writes the plaintext to --out instead of stdout when given", async () => {
    const blob = await sealText(PLAINTEXT, PASSPHRASE);
    const filePath = join(dir, "relic.bin");
    const outPath = join(dir, "out.txt");
    writeFileSync(filePath, blob);

    await run([filePath, "--out", outPath], {
      promptPassphraseImpl: async () => PASSPHRASE,
    });

    expect(readFileSync(outPath, "utf8")).toBe(PLAINTEXT);
  });

  it("rejects with a clear error on the wrong passphrase, writing nothing", async () => {
    const blob = await sealText(PLAINTEXT, PASSPHRASE);
    const filePath = join(dir, "relic.bin");
    writeFileSync(filePath, blob);

    await expect(
      run([filePath], { promptPassphraseImpl: async () => "wrong passphrase" }),
    ).rejects.toThrow();
  });
});

describe("run (multi-key / version-3 path, in-process)", () => {
  const participants = [
    { label: "Alice", passphrase: "alice passphrase here" },
    { label: "Bob", passphrase: "bob passphrase here" },
    { label: "Carol", passphrase: "carol passphrase here" },
  ];

  it("decrypts once threshold participants' passphrases are entered, without asking the rest", async () => {
    const blob = await sealMultiKey(PLAINTEXT, participants, 2);
    const filePath = join(dir, "relic.bin");
    writeFileSync(filePath, blob);

    const promptPassphraseImpl = vi.fn(async (promptText?: string) => {
      const participant = participants.find((p) => promptText?.includes(p.label));
      return participant?.passphrase ?? "";
    });

    const writeSpy = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
    try {
      await run([filePath], { promptPassphraseImpl });
      expect(writeSpy).toHaveBeenCalledWith(PLAINTEXT);
    } finally {
      writeSpy.mockRestore();
    }

    // Threshold is 2 (Alice, then Bob) — Carol is never even asked.
    expect(promptPassphraseImpl).toHaveBeenCalledTimes(2);
  });

  it("reports a wrong passphrase for one participant by label and still succeeds with the rest", async () => {
    const blob = await sealMultiKey(PLAINTEXT, participants, 2);
    const filePath = join(dir, "relic.bin");
    writeFileSync(filePath, blob);

    const promptPassphraseImpl = vi.fn(async (promptText?: string) => {
      if (promptText?.includes("Alice")) return "not alice's real passphrase";
      const participant = participants.find((p) => promptText?.includes(p.label));
      return participant?.passphrase ?? "";
    });

    const stderrSpy = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
    const writeSpy = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
    try {
      await run([filePath], { promptPassphraseImpl });
      expect(writeSpy).toHaveBeenCalledWith(PLAINTEXT);
      expect(stderrSpy.mock.calls.flat().join("")).toMatch(/wrong passphrase for "Alice"/);
    } finally {
      writeSpy.mockRestore();
      stderrSpy.mockRestore();
    }

    // Alice (wrong), Bob (correct), Carol (correct) — threshold 2 reached at Carol.
    expect(promptPassphraseImpl).toHaveBeenCalledTimes(3);
  });

  it("throws a clear error, without guessing which passphrase was the problem, when fewer than the threshold are entered correctly", async () => {
    const blob = await sealMultiKey(PLAINTEXT, participants.slice(0, 2), 2);
    const filePath = join(dir, "relic.bin");
    writeFileSync(filePath, blob);

    const promptPassphraseImpl = vi.fn(async () => "");

    await expect(run([filePath], { promptPassphraseImpl })).rejects.toThrow(
      /Only 0 of the required 2 passphrases were entered correctly/,
    );
  });
});

describe("CLI end-to-end under plain `node` (subprocess)", () => {
  it("runs relicone-decrypt.ts directly with `node`, decrypting a local file with a piped, hidden passphrase", async () => {
    const sealed = await sealText(PLAINTEXT, PASSPHRASE);
    const filePath = join(dir, "relic.bin");
    writeFileSync(filePath, sealed);

    const stdout = execFileSync(process.execPath, [CLI_PATH, filePath], {
      input: `${PASSPHRASE}\n`,
      encoding: "utf8",
      stdio: ["pipe", "pipe", "pipe"],
    });

    expect(stdout).toBe(PLAINTEXT);
  });

  it("writes to --out when run as a real subprocess", async () => {
    const sealed = await sealText(PLAINTEXT, PASSPHRASE);
    const filePath = join(dir, "relic.bin");
    const outPath = join(dir, "out.txt");
    writeFileSync(filePath, sealed);

    execFileSync(process.execPath, [CLI_PATH, filePath, "--out", outPath], {
      input: `${PASSPHRASE}\n`,
      encoding: "utf8",
      stdio: ["pipe", "pipe", "pipe"],
    });

    expect(readFileSync(outPath, "utf8")).toBe(PLAINTEXT);
  });

  it("decrypts a multi-key relic with several piped, sequential passphrases", async () => {
    // Regression coverage for a real bug: creating a fresh readline
    // interface per promptPassphrase() call (the original implementation)
    // silently dropped every line after the first when a piped stdin
    // delivered multiple newline-terminated lines in a single "data" event
    // — exactly what `printf 'a\nb\n' | …` does. A multi-key relic is the
    // first real caller that needs more than one prompt in a row.
    const blob = await sealMultiKey(
      PLAINTEXT,
      [
        { label: "Alice", passphrase: "alice passphrase here" },
        { label: "Bob", passphrase: "bob passphrase here" },
      ],
      2,
    );
    const filePath = join(dir, "relic.bin");
    writeFileSync(filePath, blob);

    const stdout = execFileSync(process.execPath, [CLI_PATH, filePath], {
      input: "alice passphrase here\nbob passphrase here\n",
      encoding: "utf8",
      stdio: ["pipe", "pipe", "pipe"],
    });

    expect(stdout).toBe(PLAINTEXT);
  });

  it("exits non-zero with a clear message on the wrong passphrase", async () => {
    const sealed = await sealText(PLAINTEXT, PASSPHRASE);
    const filePath = join(dir, "relic.bin");
    writeFileSync(filePath, sealed);

    let threw = false;
    try {
      execFileSync(process.execPath, [CLI_PATH, filePath], {
        input: "wrong passphrase\n",
        encoding: "utf8",
        stdio: ["pipe", "pipe", "pipe"],
      });
    } catch (err) {
      threw = true;
      const stderr = (err as { stderr?: string }).stderr ?? "";
      expect(stderr).toMatch(/relicone-decrypt:/);
    }
    expect(threw).toBe(true);
  });
});
