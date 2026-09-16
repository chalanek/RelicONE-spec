# RelicONE — Sealed Relic Encryption Spec

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

## Format versions

Two versions of the blob format exist, distinguished by the version byte
described below:

- **Version 1** — the original format. The header (version, iterations,
  salt, IV) sits next to the ciphertext but is **not** cryptographically
  bound to it: AES-GCM is called with no additional authenticated data
  (AAD). Preserved **permanently, unchanged** — relics were already sealed
  under this format before version 2 existed, and redefining what version
  1 means would make those relics permanently undecryptable. Any
  implementation must keep decrypting version-1 blobs exactly as described
  here, forever.
- **Version 2** — the current format, and what `sealText` writes today.
  Identical byte layout to version 1, but the header is passed to AES-GCM
  as AAD, so tampering with the version byte, iteration count, salt, or IV
  causes GCM's authentication tag check to fail by design, not merely as a
  side effect of the header also feeding key derivation or the IV.

A reader decrypting an existing relic must read the version byte first and
follow the matching Unsealing path below — the two versions decrypt
differently.

## Overview

1. Content (plain text, UTF-8) is encrypted **in the user's browser**,
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

## Blob format (versions 1 and 2 — identical layout)

The blob is a byte sequence uploaded to Arweave unmodified. Versions 1 and
2 share exactly the same byte layout; only whether the header is used as
AES-GCM AAD differs (see Sealing/Unsealing below).

```
+----------+----------------+-------------+------------+------------------+
| version  | PBKDF2 iters   | salt        | IV (nonce) | ciphertext       |
| 1 byte   | 4 bytes (BE)   | 16 bytes    | 12 bytes   | rest of blob     |
+----------+----------------+-------------+------------+------------------+
```

- **version** (`uint8`) — `0x01` (no AAD, preserved forever) or `0x02`
  (AAD-bound, current default). Any other value is an unsupported/unknown
  format.
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

Sealing always writes the **current** format, version 2.

1. Generate a random 16-byte salt and a random 12-byte IV using a
   cryptographically secure generator (`crypto.getRandomValues` in the
   browser).
2. Normalize the passphrase to Unicode NFC, then UTF-8-encode it.
3. Derive a 256-bit key: `PBKDF2-HMAC-SHA256(NFC(passphrase), salt,
   600,000 iterations)`.
4. Assemble the 33-byte header per the format above: `0x02 || iterations
   || salt || IV`.
5. Encrypt the UTF-8 bytes of the text with `AES-256-GCM(key, IV,
   plaintext)`, passing the assembled header as additional authenticated
   data (AAD). This cryptographically binds the header to the ciphertext:
   any tampering with the version byte, iteration count, salt, or IV
   causes GCM's authentication tag check to fail by design, not merely as
   a side effect of the header also feeding key derivation or the IV.
6. Assemble the blob: `header || ciphertext` (i.e. `version || iterations
   || salt || IV || ciphertext`).
7. Upload the blob as the content of an Arweave transaction.

Version 1 is never written by current sealing code. It exists in this
spec only because relics sealed before version 2 existed must remain
decryptable — see Unsealing below.

## Unsealing (decryption) — independent of the app

1. Download the Arweave transaction's content
   (`https://arweave.net/<tx-id>` or any other Arweave gateway).
2. Read the first byte — the **version**. Must be `0x01` or `0x02`;
   anything else is an unsupported format and decryption must stop here.
3. Read the next 4 bytes as a big-endian `uint32` — the iteration count.
4. Read the next 16 bytes as the salt, the next 12 bytes as the IV.
5. The rest of the blob is the ciphertext (including the GCM tag). The
   first 33 bytes read in steps 2–4 (version || iterations || salt || IV)
   are the header.
6. Derive the key the same way as during sealing (passphrase normalized
   to NFC), using the salt and iteration count read from the blob.
7. Decrypt `AES-256-GCM(key, IV, ciphertext)` → UTF-8 plaintext, branching
   on the version byte read in step 2:
   - **Version 1** — decrypt with **no** additional authenticated data.
     This is the original format's exact behavior, preserved forever so
     relics sealed under it keep decrypting. The header is *not*
     cryptographically bound to the ciphertext for these relics; only the
     wrong-passphrase/wrong-IV/wrong-salt side effects of GCM happen to
     make gross header tampering fail, not an explicit guarantee.
   - **Version 2** — decrypt **with** the 33-byte header from step 5 as
     AAD, the same value used during sealing. If the header was tampered
     with after sealing (or doesn't match the ciphertext for any other
     reason), GCM's authentication check fails and decryption throws, by
     design.

   Passing the wrong AAD mode for a given version (e.g. treating a
   version-1 blob as if it were AAD-bound) will make decryption of a
   validly-sealed relic fail — the branch on the version byte is not
   optional.

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
