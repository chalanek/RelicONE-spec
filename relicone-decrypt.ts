#!/usr/bin/env node
/**
 * Offline CLI decryptor for RelicONE Sealed Relics — concrete proof that a
 * relic is decryptable without the app, the company, or this repository:
 * this file plus crypto.ts and a passphrase (or, for a multi-key relic, M
 * of N participants' passphrases) is everything it takes.
 *
 * Usage:
 *   node relicone-decrypt.ts <transaction-id-or-file-path> [--out <file>]
 *
 * The positional argument is either an Arweave transaction id (fetched from
 * a public gateway) or a path to a local file already holding the sealed
 * relic's raw bytes. Every passphrase is always requested interactively,
 * with input hidden — never accepted as a command-line argument, since that
 * would leak into shell history and be visible to `ps` on a shared machine.
 *
 * A version-3 (multi-key, M-of-N) relic prompts once per participant, in
 * order, stopping as soon as enough passphrases have been entered
 * correctly — see multi-key-encryption-spec.md.
 */
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { createInterface, type Interface } from "node:readline";
import { pathToFileURL } from "node:url";

import {
  readMultiKeyParticipants,
  unsealMultiKey,
  unsealText,
  unwrapMultiKeyShare,
} from "./crypto.ts";

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

// Non-TTY (piped) stdin line reader, shared across every promptPassphrase()
// call in the process — a multi-key relic needs up to N sequential prompts
// (see decryptMultiKey below).
//
// A fresh `readline.createInterface` per call is wrong: it reads and
// internally buffers *all* currently-available bytes from the stream the
// moment it's created, not just up to the next newline, so a second/third
// already-buffered line gets silently discarded when that first interface
// is closed after its one "line" event.
//
// A hand-rolled buffer split on "\n" (an earlier version of this file) is
// *also* wrong, in the opposite direction: it drops a final line that has
// no trailing newline. That's not a corner case here — it's the common
// case for the last passphrase in a script, heredoc, or piped password-
// manager output with no trailing newline, and dropping it means the very
// last participant's correct passphrase reads as silently "skipped", not
// "wrong" (verified — see relicone-decrypt.test.ts).
//
// A single, persistent `readline.Interface`, consumed one line at a time
// through its async-iterator protocol, gets both right: it queues lines
// internally regardless of how many arrive in one "data" event, *and*
// flushes a final unterminated line as its last iteration result at EOF —
// exactly the guarantee this file needs and neither alternative provides.
let sharedStdinInterface: Interface | null = null;
let sharedStdinLines: AsyncIterator<string> | null = null;

/** Resolves with the next line from piped stdin, or `null` at EOF. */
async function readNextStdinLine(): Promise<string | null> {
  if (!sharedStdinLines) {
    sharedStdinInterface = createInterface({ input: process.stdin });
    sharedStdinLines = sharedStdinInterface[Symbol.asyncIterator]();
  }
  const result = await sharedStdinLines.next();
  return result.done ? null : result.value;
}

/**
 * Reads a passphrase from stdin with input hidden. On a real TTY, keystrokes
 * are suppressed and handled a character at a time (so backspace works)
 * without depending on any undocumented readline internals. When stdin isn't
 * a TTY (piped input, as in tests, CI, or scripted multi-key input), falls
 * back to a plain line read — there's no terminal to hide echo from anyway.
 */
export function promptPassphrase(promptText = "Passphrase: "): Promise<string> {
  // The prompt and its trailing newline go to stderr, never stdout — stdout
  // is reserved for the decrypted plaintext, so `relicone-decrypt tx-id >
  // out.txt` redirects exactly the relic's content and nothing else.
  const { stdin, stderr } = process;
  stderr.write(promptText);

  if (!stdin.isTTY) {
    return readNextStdinLine().then((line) => line ?? "");
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

/**
 * Decrypts a version-3 (multi-key) blob, prompting once per participant in
 * order and stopping as soon as `threshold` of them have been entered
 * correctly. A wrong passphrase for one participant is reported by label
 * and doesn't block trying the rest — see multi-key-encryption-spec.md's
 * "layered verification" property. If every participant has been asked and
 * the threshold still isn't met, throws rather than hanging or guessing.
 */
async function decryptMultiKey(
  blob: Uint8Array,
  promptPassphraseImpl: typeof promptPassphrase,
): Promise<string> {
  const { threshold, participants } = readMultiKeyParticipants(blob);
  process.stderr.write(
    `Multi-key relic: ${threshold} of ${participants.length} participants' passphrases are needed together.\n`,
  );

  const shares: Uint8Array[] = [];
  for (const participant of participants) {
    if (shares.length >= threshold) break;

    const passphrase = await promptPassphraseImpl(
      `Passphrase for "${participant.label}" (Enter to skip): `,
    );
    if (!passphrase) continue;

    try {
      shares.push(await unwrapMultiKeyShare(blob, participant.index, passphrase));
      process.stderr.write(`  unlocked "${participant.label}" (${shares.length}/${threshold})\n`);
    } catch {
      process.stderr.write(`  wrong passphrase for "${participant.label}"\n`);
    }
  }

  if (shares.length < threshold) {
    throw new Error(
      `Only ${shares.length} of the required ${threshold} passphrases were entered correctly.`,
    );
  }

  return unsealMultiKey(blob, shares);
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
  const plaintext =
    blob[0] === 3
      ? await decryptMultiKey(blob, promptPassphraseImpl)
      : await unsealText(blob, await promptPassphraseImpl());

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
