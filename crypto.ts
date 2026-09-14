/**
 * Reference implementation of the RelicONE Sealed Relic format v1 — see
 * encryption-spec.md in this repository for the full specification. This
 * file must never send a passphrase or derived key anywhere; it only runs
 * in the browser.
 */

const FORMAT_VERSION = 1;
const PBKDF2_ITERATIONS = 600_000;
const SALT_BYTES = 16;
const IV_BYTES = 12;
const HEADER_LENGTH = 1 + 4 + SALT_BYTES + IV_BYTES;
const GCM_TAG_BYTES = 16;
// Generous headroom over the 600k default so a future format version can
// raise it without breaking this decoder — but still small enough that a
// hostile or corrupted blob can't force an effectively-infinite key
// derivation. Only matters once untrusted input reaches this function (see
// unsealText's doc comment below).
const MAX_PLAUSIBLE_PBKDF2_ITERATIONS = 5_000_000;

function assertBrowserCrypto() {
  if (typeof window === "undefined" || !window.crypto?.subtle) {
    throw new Error("Web Crypto API is not available in this environment");
  }
}

async function deriveKey(
  passphrase: string,
  salt: Uint8Array,
  iterations: number,
): Promise<CryptoKey> {
  // NFC-normalize before encoding: the same passphrase can arrive as
  // different Unicode byte sequences depending on OS/keyboard/IME
  // (precomposed vs. decomposed characters), which would otherwise derive
  // a different key on a different machine for what the user believes is
  // an identical passphrase. See encryption-spec.md.
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(passphrase.normalize("NFC")),
    "PBKDF2",
    false,
    ["deriveKey"],
  );

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt as BufferSource,
      iterations,
      hash: "SHA-256",
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

/**
 * Encrypts UTF-8 text with a key derived from `passphrase` and returns the
 * self-contained sealed blob ready to upload to Arweave. The passphrase
 * itself is never returned, stored, or transmitted.
 */
export async function sealText(
  plaintext: string,
  passphrase: string,
): Promise<Uint8Array> {
  assertBrowserCrypto();

  const salt = crypto.getRandomValues(new Uint8Array(SALT_BYTES));
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const key = await deriveKey(passphrase, salt, PBKDF2_ITERATIONS);

  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv as BufferSource },
      key,
      new TextEncoder().encode(plaintext),
    ),
  );

  const header = new Uint8Array(1 + 4 + SALT_BYTES + IV_BYTES);
  header[0] = FORMAT_VERSION;
  new DataView(header.buffer).setUint32(1, PBKDF2_ITERATIONS, false);
  header.set(salt, 5);
  header.set(iv, 5 + SALT_BYTES);

  const blob = new Uint8Array(header.length + ciphertext.length);
  blob.set(header, 0);
  blob.set(ciphertext, header.length);
  return blob;
}

/**
 * Reverses `sealText`. Kept alongside the encrypt path so the reference
 * implementation stays a single, mechanically-checkable source of truth for
 * encryption-spec.md.
 *
 * Unlike `sealText`, this may run on genuinely untrusted input — RelicONE's
 * own `/unseal` page accepts any Arweave transaction ID, not just ones it
 * produced itself (see encryption-spec.md's independence claim). The two
 * checks below exist only because of that — they reject blobs that can't
 * possibly be valid before touching `crypto.subtle`, instead of letting
 * them fail slowly (or not at all).
 */
export async function unsealText(
  blob: Uint8Array,
  passphrase: string,
): Promise<string> {
  assertBrowserCrypto();

  if (blob.byteLength < HEADER_LENGTH + GCM_TAG_BYTES) {
    throw new Error("This isn't a valid sealed relic — the data is too short.");
  }

  const version = blob[0];
  if (version !== FORMAT_VERSION) {
    throw new Error(`Unsupported sealed relic format version: ${version}`);
  }

  const iterations = new DataView(
    blob.buffer,
    blob.byteOffset,
    blob.byteLength,
  ).getUint32(1, false);
  if (iterations === 0 || iterations > MAX_PLAUSIBLE_PBKDF2_ITERATIONS) {
    // A real relic's header always holds whatever PBKDF2_ITERATIONS was set
    // to at sealing time (600,000 today) — never 0, never anything close to
    // this ceiling. Bail out instead of deriving a key that could take
    // minutes to hours.
    throw new Error("This isn't a valid sealed relic — its iteration count is implausible.");
  }

  const salt = blob.slice(5, 5 + SALT_BYTES);
  const iv = blob.slice(5 + SALT_BYTES, 5 + SALT_BYTES + IV_BYTES);
  const ciphertext = blob.slice(HEADER_LENGTH);

  const key = await deriveKey(passphrase, salt, iterations);
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: iv as BufferSource },
    key,
    ciphertext as BufferSource,
  );

  return new TextDecoder().decode(plaintext);
}
