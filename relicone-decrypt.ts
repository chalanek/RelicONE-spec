#!/usr/bin/env node
/**
 * Offline CLI decryptor for RelicONE Sealed Relics — concrete proof that a
 * relic is decryptable without the app, the company, or this repository:
 * this file plus crypto.ts and a passphrase is everything it takes.
 *
 * Usage:
 *   node relicone-decrypt.ts <transaction-id-or-file-path> [--out <file>]
 *
 * The positional argument is either an Arweave transaction id (fetched from
 * a public gateway) or a path to a local file already holding the sealed
 * relic's raw bytes. The passphrase is always requested interactively, with
 * input hidden — it is never accepted as a command-line argument, since that
 * would leak into shell history and be visible to `ps` on a shared machine.
 */
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { createInterface } from "node:readline";
import { pathToFileURL } from "node:url";

import { unsealText } from "./crypto.ts";

const DEFAULT_GATEWAY = "https://arweave.net";

export interface ParsedArgs {
  input: string;
  outFile?: string;
}

export function parseArgs(argv: string[]): ParsedArgs {
  let input: string | undefined;
  let outFile: string | undefined;

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--out") {
      outFile = argv[++i];
      if (outFile === undefined) {
        throw new Error("--out requires a file path");
      }
    } else if (input === undefined) {
      input = arg;
    } else {
      throw new Error(`Unexpected argument: ${arg}`);
    }
  }

  if (input === undefined) {
    throw new Error(
      "Usage: relicone-decrypt <transaction-id-or-file-path> [--out <file>]",
    );
  }

  return { input, outFile };
}

/**
 * Resolves the sealed relic's raw bytes: a local file if `input` names one
 * that exists, otherwise an Arweave transaction id fetched from the public
 * gateway. `fetchImpl` is injectable so tests can exercise the local-file
 * path without any network dependency.
 */
export async function resolveBlob(
  input: string,
  fetchImpl: (url: string) => Promise<Response> = fetch,
): Promise<Uint8Array> {
  if (existsSync(input)) {
    return new Uint8Array(readFileSync(input));
  }

  const url = `${DEFAULT_GATEWAY}/${input}`;
  const response = await fetchImpl(url);
  if (!response.ok) {
    throw new Error(
      `Failed to fetch transaction "${input}" from ${url}: HTTP ${response.status}`,
    );
  }
  return new Uint8Array(await response.arrayBuffer());
}

/**
 * Reads a passphrase from stdin with input hidden. On a real TTY, keystrokes
 * are suppressed and handled a character at a time (so backspace works)
 * without depending on any undocumented readline internals. When stdin isn't
 * a TTY (piped input, as in tests or CI), falls back to a plain line read —
 * there's no terminal to hide echo from anyway.
 */
export function promptPassphrase(promptText = "Passphrase: "): Promise<string> {
  // The prompt and its trailing newline go to stderr, never stdout — stdout
  // is reserved for the decrypted plaintext, so `relicone-decrypt tx-id >
  // out.txt` redirects exactly the relic's content and nothing else.
  const { stdin, stderr } = process;
  stderr.write(promptText);

  if (!stdin.isTTY) {
    return new Promise((resolve) => {
      const rl = createInterface({ input: stdin });
      rl.once("line", (line) => {
        rl.close();
        resolve(line);
      });
    });
  }

  return new Promise((resolve, reject) => {
    let value = "";
    stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding("utf8");

    const cleanup = () => {
      stdin.setRawMode(false);
      stdin.pause();
      stdin.removeListener("data", onData);
    };

    const onData = (chunk: string) => {
      for (const char of chunk) {
        if (char === "\r" || char === "\n") {
          cleanup();
          stderr.write("\n");
          resolve(value);
          return;
        }
        if (char === "\u0003") {
          // Ctrl-C
          cleanup();
          stderr.write("\n");
          reject(new Error("Aborted"));
          return;
        }
        if (char === "\u007f" || char === "\b") {
          value = value.slice(0, -1);
          continue;
        }
        value += char;
      }
    };

    stdin.on("data", onData);
  });
}

export async function run(
  argv: string[],
  deps: {
    fetchImpl?: (url: string) => Promise<Response>;
    promptPassphraseImpl?: typeof promptPassphrase;
  } = {},
): Promise<void> {
  const { input, outFile } = parseArgs(argv);
  const fetchImpl = deps.fetchImpl ?? fetch;
  const promptPassphraseImpl = deps.promptPassphraseImpl ?? promptPassphrase;

  const blob = await resolveBlob(input, fetchImpl);
  const passphrase = await promptPassphraseImpl();
  const plaintext = await unsealText(blob, passphrase);

  if (outFile) {
    writeFileSync(outFile, plaintext, "utf8");
  } else {
    process.stdout.write(plaintext);
  }
}

const isMainModule =
  process.argv[1] !== undefined &&
  import.meta.url === pathToFileURL(process.argv[1]).href;

if (isMainModule) {
  run(process.argv.slice(2)).catch((err) => {
    console.error(`relicone-decrypt: ${err instanceof Error ? err.message : err}`);
    process.exitCode = 1;
  });
}
