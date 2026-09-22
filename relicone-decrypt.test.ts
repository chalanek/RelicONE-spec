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

import { sealText } from "./crypto";
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
