/**
 * Client-side encryption for sealed relics.
 *
 * Implements the RelicONE Sealed Relic format — see
 * docs/encryption-spec.md for the full, app-independent specification.
 * This file must never send a passphrase or derived key anywhere; it only
 * runs in the browser.
 *
 * Two format versions exist. Version 1 (no AAD) is preserved forever,
 * unchanged, because relics were already sealed under it before this
 * distinction existed — redefining it in place would make them permanently
 * undecryptable. Version 2 (header bound to the ciphertext as AES-GCM AAD)
 * is what `sealText` writes going forward. See docs/encryption-spec.md for
 * the full rationale.
 *
 * A third, independent format — version 3, multi-key (M-of-N) unlock via
 * Shamir's Secret Sharing — is implemented further below
 * (`sealMultiKey`/`unsealMultiKey` and their helpers). It shares this
 * file's primitives (PBKDF2, AES-256-GCM, NFC normalization) but is a
 * separate track, not a revision of versions 1/2: see
 * docs/multi-key-encryption-spec.md for its own full specification.
 * `sealText`/`unsealText` above are untouched by it.
 */

import { combine, split } from "shamir-secret-sharing";

const FORMAT_VERSION_V1_NO_AAD = 1;
const FORMAT_VERSION_V2_AAD = 2;
const CURRENT_FORMAT_VERSION = FORMAT_VERSION_V2_AAD;
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
  if (typeof globalThis.crypto?.subtle?.decrypt !== "function") {
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
  // an identical passphrase. See docs/encryption-spec.md.
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

  const header = new Uint8Array(1 + 4 + SALT_BYTES + IV_BYTES);
  header[0] = CURRENT_FORMAT_VERSION;
  new DataView(header.buffer).setUint32(1, PBKDF2_ITERATIONS, false);
  header.set(salt, 5);
  header.set(iv, 5 + SALT_BYTES);

  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv: iv as BufferSource,
        additionalData: header as BufferSource,
      },
      key,
      new TextEncoder().encode(plaintext),
    ),
  );

  const blob = new Uint8Array(header.length + ciphertext.length);
  blob.set(header, 0);
  blob.set(ciphertext, header.length);
  return blob;
}

/**
 * Reverses `sealText`. Kept alongside the encrypt path so the reference
 * implementation stays a single, mechanically-checkable source of truth for
 * docs/encryption-spec.md.
 *
 * Unlike `sealText`, this now runs on genuinely untrusted input: RelicONE's
 * `/unseal` page accepts any Arweave transaction ID, not just ones this app
 * produced (see src/lib/arweave-gateway.ts and docs/encryption-spec.md's
 * independence claim). The two checks below exist only because of that —
 * they reject blobs that can't possibly be valid before touching
 * `crypto.subtle`, instead of letting them fail slowly (or not at all).
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
  if (
    version !== FORMAT_VERSION_V1_NO_AAD &&
    version !== FORMAT_VERSION_V2_AAD
  ) {
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

  const header = blob.slice(0, HEADER_LENGTH);
  const salt = blob.slice(5, 5 + SALT_BYTES);
  const iv = blob.slice(5 + SALT_BYTES, 5 + SALT_BYTES + IV_BYTES);
  const ciphertext = blob.slice(HEADER_LENGTH);

  const key = await deriveKey(passphrase, salt, iterations);
  // v1 blobs were sealed with no AAD at all — passing `header` here for a
  // v1 blob would fail the GCM tag check against a real v1 relic that was
  // never sealed with it. v2 blobs must always pass it, or header tampering
  // (version/iterations/salt/IV) would go undetected.
  const plaintext = await crypto.subtle.decrypt(
    version === FORMAT_VERSION_V2_AAD
      ? {
          name: "AES-GCM",
          iv: iv as BufferSource,
          additionalData: header as BufferSource,
        }
      : {
          name: "AES-GCM",
          iv: iv as BufferSource,
        },
    key,
    ciphertext as BufferSource,
  );

  return new TextDecoder().decode(plaintext);
}

// --- Multi-key (M-of-N) unlock — format version 3 ---
//
// See docs/multi-key-encryption-spec.md for the full byte layout and
// rationale. Summary: a random content encryption key (CEK) encrypts the
// relic exactly like version 2 above; the CEK itself (never the content)
// is split via Shamir's Secret Sharing into N shares, and each share is
// independently wrapped with one participant's own passphrase using the
// same PBKDF2 + AES-256-GCM primitives as versions 1/2. Any M of the N
// wraps opening correctly is enough to reconstruct the CEK.

const FORMAT_VERSION_V3_MULTI_KEY = 3;
const MULTI_KEY_CEK_BYTES = 32; // 256-bit content key, same size as v1/v2's derived key
const MULTI_KEY_MIN_PARTICIPANTS = 2; // shamir-secret-sharing's own floor
const MULTI_KEY_MAX_PARTICIPANTS = 255; // shamir-secret-sharing's own ceiling (1-byte x-coordinate)
const LABEL_LENGTH_BYTES = 1;
const WRAPPED_SHARE_LENGTH_BYTES = 2;
// version + N + M
const MULTI_KEY_FIXED_HEADER_BYTES = 3;
// The fixed-size portion of one participant record, excluding the
// variable-length label and wrapped share (see the byte-layout table in
// docs/multi-key-encryption-spec.md): iterations(4) + salt(16) + iv(12).
const PARTICIPANT_RECORD_FIXED_BYTES = 4 + SALT_BYTES + IV_BYTES;

export type MultiKeyParticipant = { label: string; passphrase: string };
export type MultiKeyParticipantInfo = { label: string; index: number };

function assertValidParticipantCounts(participantCount: number, threshold: number) {
  if (
    participantCount < MULTI_KEY_MIN_PARTICIPANTS ||
    participantCount > MULTI_KEY_MAX_PARTICIPANTS
  ) {
    throw new Error(
      `Multi-key sealing needs between ${MULTI_KEY_MIN_PARTICIPANTS} and ${MULTI_KEY_MAX_PARTICIPANTS} participants.`,
    );
  }
  if (threshold < MULTI_KEY_MIN_PARTICIPANTS || threshold > participantCount) {
    throw new Error(
      `The threshold must be between ${MULTI_KEY_MIN_PARTICIPANTS} and the number of participants (${participantCount}).`,
    );
  }
}

/**
 * Encrypts UTF-8 text so that any `threshold` of `participants` can jointly
 * unseal it, but any `threshold - 1` of them reveal nothing — see
 * docs/multi-key-encryption-spec.md. No passphrase, share, or the content
 * key is ever returned, stored, or transmitted; only the finished blob is.
 */
export async function sealMultiKey(
  plaintext: string,
  participants: MultiKeyParticipant[],
  threshold: number,
): Promise<Uint8Array> {
  assertBrowserCrypto();
  assertValidParticipantCounts(participants.length, threshold);

  const cek = crypto.getRandomValues(new Uint8Array(MULTI_KEY_CEK_BYTES));
  const shares = await split(cek, participants.length, threshold);

  const participantCount = participants.length;
  const recordBytesList: Uint8Array[] = [];

  for (let i = 0; i < participantCount; i++) {
    const labelBytes = new TextEncoder().encode(participants[i].label);
    if (labelBytes.length > 255) {
      throw new Error(`Participant label "${participants[i].label}" is too long.`);
    }

    const salt = crypto.getRandomValues(new Uint8Array(SALT_BYTES));
    const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
    const key = await deriveKey(participants[i].passphrase, salt, PBKDF2_ITERATIONS);

    // Everything fixed-position about this one record — see the "wrapped
    // share" row of the byte-layout table in
    // docs/multi-key-encryption-spec.md for why this exact slice is used
    // as AAD, both here and when unwrapping.
    const recordHeader = new Uint8Array(
      LABEL_LENGTH_BYTES + labelBytes.length + PARTICIPANT_RECORD_FIXED_BYTES,
    );
    recordHeader[0] = labelBytes.length;
    recordHeader.set(labelBytes, LABEL_LENGTH_BYTES);
    new DataView(recordHeader.buffer).setUint32(
      LABEL_LENGTH_BYTES + labelBytes.length,
      PBKDF2_ITERATIONS,
      false,
    );
    recordHeader.set(salt, LABEL_LENGTH_BYTES + labelBytes.length + 4);
    recordHeader.set(iv, LABEL_LENGTH_BYTES + labelBytes.length + 4 + SALT_BYTES);

    const aad = new Uint8Array(MULTI_KEY_FIXED_HEADER_BYTES + recordHeader.length);
    aad[0] = FORMAT_VERSION_V3_MULTI_KEY;
    aad[1] = participantCount;
    aad[2] = threshold;
    aad.set(recordHeader, MULTI_KEY_FIXED_HEADER_BYTES);

    const wrappedShare = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv as BufferSource, additionalData: aad as BufferSource },
        key,
        shares[i] as BufferSource,
      ),
    );

    const record = new Uint8Array(
      recordHeader.length + WRAPPED_SHARE_LENGTH_BYTES + wrappedShare.length,
    );
    record.set(recordHeader, 0);
    new DataView(record.buffer).setUint16(recordHeader.length, wrappedShare.length, false);
    record.set(wrappedShare, recordHeader.length + WRAPPED_SHARE_LENGTH_BYTES);
    recordBytesList.push(record);

    shares[i].fill(0);
  }

  const recordsTotalBytes = recordBytesList.reduce((sum, r) => sum + r.length, 0);
  const header = new Uint8Array(MULTI_KEY_FIXED_HEADER_BYTES + recordsTotalBytes + IV_BYTES);
  header[0] = FORMAT_VERSION_V3_MULTI_KEY;
  header[1] = participantCount;
  header[2] = threshold;
  let offset = MULTI_KEY_FIXED_HEADER_BYTES;
  for (const record of recordBytesList) {
    header.set(record, offset);
    offset += record.length;
  }
  const finalIv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  header.set(finalIv, offset);

  const cekKey = await crypto.subtle.importKey(
    "raw",
    cek as BufferSource,
    "AES-GCM",
    false,
    ["encrypt"],
  );
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: finalIv as BufferSource, additionalData: header as BufferSource },
      cekKey,
      new TextEncoder().encode(plaintext),
    ),
  );
  cek.fill(0);

  const blob = new Uint8Array(header.length + ciphertext.length);
  blob.set(header, 0);
  blob.set(ciphertext, header.length);
  return blob;
}

type ParsedMultiKeyRecord = {
  label: string;
  iterations: number;
  salt: Uint8Array;
  iv: Uint8Array;
  aad: Uint8Array;
  wrappedShare: Uint8Array;
};

type ParsedMultiKeyBlob = {
  threshold: number;
  records: ParsedMultiKeyRecord[];
  finalIv: Uint8Array;
  ciphertext: Uint8Array;
  headerAad: Uint8Array;
};

/**
 * Structurally parses a version-3 blob — shared by `readMultiKeyParticipants`
 * (labels/threshold only, no crypto, safe to call before any passphrase is
 * known) and `unwrapMultiKeyShare`/`unsealMultiKey` below (which need the
 * per-record crypto material too). Every bounds check here exists because,
 * like `unsealText`, this runs on genuinely untrusted input — any Arweave
 * transaction, not just ones this app produced.
 */
function parseMultiKeyBlob(blob: Uint8Array): ParsedMultiKeyBlob {
  if (blob.byteLength < MULTI_KEY_FIXED_HEADER_BYTES + IV_BYTES + GCM_TAG_BYTES) {
    throw new Error("This isn't a valid sealed relic — the data is too short.");
  }
  if (blob[0] !== FORMAT_VERSION_V3_MULTI_KEY) {
    throw new Error(`Unsupported sealed relic format version: ${blob[0]}`);
  }

  const participantCount = blob[1];
  const threshold = blob[2];
  if (
    participantCount < MULTI_KEY_MIN_PARTICIPANTS ||
    participantCount > MULTI_KEY_MAX_PARTICIPANTS ||
    threshold < MULTI_KEY_MIN_PARTICIPANTS ||
    threshold > participantCount
  ) {
    throw new Error("This isn't a valid sealed relic — its participant counts are implausible.");
  }

  const view = new DataView(blob.buffer, blob.byteOffset, blob.byteLength);
  const records: ParsedMultiKeyRecord[] = [];
  let offset = MULTI_KEY_FIXED_HEADER_BYTES;

  function readBytes(length: number): Uint8Array {
    if (offset + length > blob.byteLength) {
      throw new Error("This isn't a valid sealed relic — the data is truncated.");
    }
    const bytes = blob.slice(offset, offset + length);
    offset += length;
    return bytes;
  }

  for (let i = 0; i < participantCount; i++) {
    const recordStart = offset;
    const labelLength = readBytes(LABEL_LENGTH_BYTES)[0];
    const labelBytes = readBytes(labelLength);
    if (offset + PARTICIPANT_RECORD_FIXED_BYTES > blob.byteLength) {
      throw new Error("This isn't a valid sealed relic — the data is truncated.");
    }
    const iterations = view.getUint32(offset, false);
    offset += 4;
    const salt = readBytes(SALT_BYTES);
    const iv = readBytes(IV_BYTES);
    if (iterations === 0 || iterations > MAX_PLAUSIBLE_PBKDF2_ITERATIONS) {
      throw new Error(
        "This isn't a valid sealed relic — its iteration count is implausible.",
      );
    }
    const recordHeaderEnd = offset;
    if (offset + WRAPPED_SHARE_LENGTH_BYTES > blob.byteLength) {
      throw new Error("This isn't a valid sealed relic — the data is truncated.");
    }
    const wrappedShareLength = view.getUint16(offset, false);
    offset += WRAPPED_SHARE_LENGTH_BYTES;
    const wrappedShare = readBytes(wrappedShareLength);

    const aad = new Uint8Array(MULTI_KEY_FIXED_HEADER_BYTES + (recordHeaderEnd - recordStart));
    aad[0] = FORMAT_VERSION_V3_MULTI_KEY;
    aad[1] = participantCount;
    aad[2] = threshold;
    aad.set(blob.slice(recordStart, recordHeaderEnd), MULTI_KEY_FIXED_HEADER_BYTES);

    records.push({
      label: new TextDecoder().decode(labelBytes),
      iterations,
      salt,
      iv,
      aad,
      wrappedShare,
    });
  }

  const headerEnd = offset + IV_BYTES;
  if (headerEnd + GCM_TAG_BYTES > blob.byteLength) {
    throw new Error("This isn't a valid sealed relic — the data is truncated.");
  }
  const finalIv = readBytes(IV_BYTES);
  const headerAad = blob.slice(0, headerEnd);
  const ciphertext = blob.slice(headerEnd);

  return { threshold, records, finalIv, ciphertext, headerAad };
}

/**
 * Reads a version-3 blob's non-secret metadata — participant labels and the
 * threshold — without any passphrase. Safe to call as soon as a blob is
 * fetched, so `/unseal` can render the "M of N" participant list before
 * anyone has entered anything.
 */
export function readMultiKeyParticipants(blob: Uint8Array): {
  threshold: number;
  participants: MultiKeyParticipantInfo[];
} {
  const parsed = parseMultiKeyBlob(blob);
  return {
    threshold: parsed.threshold,
    participants: parsed.records.map((record, index) => ({ label: record.label, index })),
  };
}

/**
 * Attempts to unwrap one participant's own share with one passphrase.
 * Succeeds or fails independently of every other participant — a wrong
 * passphrase here fails this AES-GCM tag check specifically, before SSS
 * combination is ever attempted (see docs/multi-key-encryption-spec.md's
 * "layered verification" discussion). Throws on a wrong passphrase, an
 * out-of-range index, or a tampered record.
 */
export async function unwrapMultiKeyShare(
  blob: Uint8Array,
  participantIndex: number,
  passphrase: string,
): Promise<Uint8Array> {
  assertBrowserCrypto();
  const parsed = parseMultiKeyBlob(blob);
  const record = parsed.records[participantIndex];
  if (!record) {
    throw new Error("Invalid participant index.");
  }

  const key = await deriveKey(passphrase, record.salt, record.iterations);
  const share = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: record.iv as BufferSource,
      additionalData: record.aad as BufferSource,
    },
    key,
    record.wrappedShare as BufferSource,
  );
  return new Uint8Array(share);
}

/**
 * Reconstructs the content key from `shares` (at least `threshold` of them,
 * any subset) and decrypts the relic. `shares` need not be in participant
 * order — `combine` and the final AES-GCM tag don't care which subset was
 * used, only that it's a valid one; see docs/multi-key-encryption-spec.md
 * for why a mismatched-but-individually-valid set of shares is still caught
 * here, at the content layer, rather than by the SSS library itself.
 */
export async function unsealMultiKey(
  blob: Uint8Array,
  shares: Uint8Array[],
): Promise<string> {
  assertBrowserCrypto();
  const parsed = parseMultiKeyBlob(blob);
  if (shares.length < parsed.threshold) {
    throw new Error(
      `Need at least ${parsed.threshold} unlocked shares — only ${shares.length} so far.`,
    );
  }

  const cek = await combine(shares);
  const key = await crypto.subtle.importKey("raw", cek as BufferSource, "AES-GCM", false, [
    "decrypt",
  ]);
  const plaintext = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: parsed.finalIv as BufferSource,
      additionalData: parsed.headerAad as BufferSource,
    },
    key,
    parsed.ciphertext as BufferSource,
  );
  cek.fill(0);

  return new TextDecoder().decode(plaintext);
}
