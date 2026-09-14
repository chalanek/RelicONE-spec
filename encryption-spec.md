# RelicONE — Sealed Relic Encryption Spec (v1)

> Open specification. Goal: anyone, at any time — even after the RelicONE
> app or the company behind it is gone — can decrypt the content from an
> Arweave transaction and a passphrase (if the user kept one), using only
> this specification and standard cryptographic libraries.

This is the sole, authoritative specification of the format. The
reference implementation lives in [`crypto.ts`](./crypto.ts) (`sealText` /
`unsealText`), but the specification itself is language- and
library-agnostic — the format below can be implemented in any environment
with a standard cryptographic library (Web Crypto, OpenSSL, libsodium via
manual primitives, Node `crypto`, Python `cryptography`, ...).

## Overview

1. Content (v1: plain text, UTF-8) is encrypted **in the user's browser**,
   before anything leaves the device.
2. The encryption key is **derived from a user-supplied passphrase** via
   PBKDF2.
3. The resulting self-contained blob (header + ciphertext) is uploaded to
   Arweave. The Arweave transaction **is** the sealed relic — everything
   needed to decrypt it, given the passphrase, lives in that blob alone.

## Primitives

| Purpose | Algorithm | Parameters |
|---|---|---|
| Key derivation (KDF) | PBKDF2-HMAC-SHA256 | 600,000 iterations, random 16-byte salt |
| Content encryption | AES-256-GCM | random 12-byte IV/nonce, 256-bit key |
| Text encoding | UTF-8 | plaintext and passphrase |
| Passphrase normalization | Unicode NFC | applied **before** UTF-8 encoding |

600,000 iterations matches OWASP's (2023) recommendation for
PBKDF2-HMAC-SHA256. The iteration count is part of the format (see
below), so a future app version can raise it without breaking decryption
of older relics.

**Passphrase normalization is mandatory.** A visually identical
passphrase can have different byte sequences depending on
OS/keyboard/IME (decomposed vs. composed characters — e.g. "é" as one
code point vs. "e" plus a combining accent). Without normalization, the
same passphrase typed on a different device could silently and
irreversibly derive a different key. The passphrase must therefore always
be normalized to NFC (`passphrase.normalize("NFC")` in the Web Crypto
API) before being UTF-8-encoded. Every independent implementation must
follow this step, or the recoverability this format promises does not
hold.

## Blob format (version 1)

The blob is a byte sequence uploaded to Arweave unmodified:

```
+----------+----------------+-------------+------------+------------------+
| version  | PBKDF2 iters   | salt        | IV (nonce) | ciphertext       |
| 1 byte   | 4 bytes (BE)   | 16 bytes    | 12 bytes   | rest of blob     |
+----------+----------------+-------------+------------+------------------+
```

- **version** (`uint8`) — `0x01` for this format. A future incompatible
  format change increments this number.
- **PBKDF2 iterations** (`uint32`, big-endian) — the exact iteration
  count used when this particular relic was sealed.
- **salt** (16 random bytes) — PBKDF2 input, unique per relic.
- **IV / nonce** (12 random bytes) — AES-GCM input, unique per relic.
- **ciphertext** — AES-256-GCM output (`ciphertext || auth tag`, exactly
  as a standard GCM implementation returns it, including the 16-byte
  authentication tag at the end).

The header (version + iterations + salt + IV) has a fixed length of 33
bytes and is **not** secret on its own — it's useless without the
passphrase.

## Sealing (encryption)

1. Generate a random 16-byte salt and a random 12-byte IV using a
   cryptographically secure generator (`crypto.getRandomValues` in the
   browser).
2. Normalize the passphrase to Unicode NFC, then UTF-8-encode it.
3. Derive a 256-bit key: `PBKDF2-HMAC-SHA256(NFC(passphrase), salt,
   600,000 iterations)`.
4. Encrypt the UTF-8 bytes of the text with `AES-256-GCM(key, IV,
   plaintext)` — no additional authenticated data (AAD).
5. Assemble the blob per the format above: `version || iterations || salt
   || IV || ciphertext`.
6. Upload the blob as the content of an Arweave transaction.

## Unsealing (decryption) — independent of the app

1. Download the Arweave transaction's content
   (`https://arweave.net/<tx-id>` or any other Arweave gateway).
2. Read the first byte — must be `0x01`.
3. Read the next 4 bytes as a big-endian `uint32` — the iteration count.
4. Read the next 16 bytes as the salt, the next 12 bytes as the IV.
5. The rest of the blob is the ciphertext (including the GCM tag).
6. Derive the key the same way as during sealing (passphrase normalized
   to NFC), using the salt and iteration count read from the blob.
7. Decrypt `AES-256-GCM(key, IV, ciphertext)` → UTF-8 plaintext.

The reference implementation of both directions (`sealText`/`unsealText`)
lives in [`crypto.ts`](./crypto.ts) and uses only the Web Crypto API — no
app-specific or non-public cryptography.

**Recommended defense when decrypting from an untrusted source.** Anyone
(RelicONE or another independent implementation) can, via any Arweave
gateway, land on a tx id that doesn't contain a valid sealed relic at all
— foreign content, a corrupted blob, or deliberately crafted data. Before
running PBKDF2 based on the header just read, it's recommended to verify:

- **Minimum blob length** — fewer than 33 header bytes plus a 16-byte GCM
  tag (49 bytes) cannot be a valid relic.
- **A sane upper bound on the iteration count** — the header carries an
  iteration count with no built-in limit; without a ceiling, an
  attacker-chosen, arbitrarily large number can block PBKDF2 for an
  unreasonable amount of time. An implementation should reject values
  well above anything the app itself has ever written (600,000 today —
  see `MAX_PLAUSIBLE_PBKDF2_ITERATIONS` in [`crypto.ts`](./crypto.ts)),
  with enough headroom for future increases to the default.

Both checks apply only on the decryption side — they change nothing
about the blob format or what `sealText` writes.
