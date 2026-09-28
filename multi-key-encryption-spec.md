# RelicONE — Multi-Key (M-of-N) Sealed Relic Spec (Version 3)

> Open specification, sibling to
> [`encryption-spec.md`](./encryption-spec.md). Same goal, same
> independence claim: anyone, at any time — even after the RelicONE app or
> the company behind it is gone — can decrypt this format from an Arweave
> transaction and M of N participants' passphrases, using only this
> specification and standard cryptographic libraries.

This document describes **version 3** of the sealed relic blob format —
a distinct track from versions 1/2, not a later revision of them. Version
3 requires **M of N** independently-held passphrases to unlock, instead of
one. Versions 1 and 2 (see `encryption-spec.md`) are entirely untouched by
this: a `sealText`-produced relic never becomes a version-3 relic, and a
reader must still branch on the first byte of any blob to know which
specification applies.

Why a separate document rather than a new section of the main spec: version
3's header is variable-length and repeats a per-participant record N
times, which doesn't fit the existing spec's fixed 33-byte-header framing
without either confusing the two or diluting the rigor of the original.

## Overview

1. A random 256-bit **content encryption key (CEK)** is generated. The
   relic's content is encrypted with it exactly like version 2 (AES-256-GCM,
   header bound as AAD) — see "Content encryption" below.
2. The CEK — never the content directly — is split via **Shamir's Secret
   Sharing (SSS)** into N shares, such that any M of them reconstruct it
   but any M−1 reveal zero information about it.
3. Each of the N shares is independently wrapped with its own participant's
   passphrase, using the same primitives as version 1/2 (PBKDF2-HMAC-SHA256
   → AES-256-GCM), each with its own random salt, IV, and iteration count.
4. The app itself never stores any passphrase, any share, or the CEK, for
   any participant — the same absolute invariant as versions 1/2, applied
   N times instead of once.

Reconstructing the relic requires: the blob (from Arweave), and M of the N
participants' passphrases, entered anywhere against this same blob (order
doesn't matter, and participants don't need to coordinate through
RelicONE or any other service — see "Independence" below).

## Primitives

Identical to versions 1/2 (see `encryption-spec.md` § Primitives), applied
per-participant for the wrapping layer and once more for the content
layer:

| Purpose | Algorithm | Parameters |
|---|---|---|
| Key derivation (KDF), per participant | PBKDF2-HMAC-SHA256 | 600,000 iterations, random 16-byte salt |
| Share wrapping, per participant | AES-256-GCM | random 12-byte IV, 256-bit key |
| Content encryption | AES-256-GCM | random 12-byte IV, 256-bit key (the CEK) |
| Secret splitting | Shamir's Secret Sharing over GF(256) | N shares, threshold M, operating on the 32-byte CEK |
| Text encoding | UTF-8 | plaintext and passphrases |
| Passphrase normalization | Unicode NFC | applied to each participant's passphrase before UTF-8 encoding, same as v1/v2 |

The reference SSS implementation is
[`shamir-secret-sharing`](https://github.com/privy-io/shamir-secret-sharing)
(Privy), independently audited by
[Cure53](https://cure53.de/audit-report_privy-sss-library.pdf) and
[Zellic](https://github.com/Zellic/publications/blob/master/Privy_Shamir_Secret_Sharing_-_Zellic_Audit_Report.pdf).
Its `split`/`combine` functions operate on raw bytes (`Uint8Array` in,
`Uint8Array` out) with no format of their own beyond the share encoding
described below — any independent, standards-conformant SSS
implementation over GF(256) producing the same share encoding
(one extra byte per share, carrying the share's x-coordinate) is
interoperable with this spec; a reader is not required to use this
specific library.

**Bounds required by the algorithm itself:** N and M must each be at
least 2 and at most 255 (a single-share "threshold" degenerates to the
existing single-passphrase format, and GF(256) arithmetic limits x-coordinates
to one byte). M must be at most N.

## Blob format (version 3)

Unlike versions 1/2's fixed 33-byte header, version 3's header is
variable-length: three fixed bytes, then N variable-length participant
records, then a 12-byte IV for the content layer.

```
+---------+-----+-----+------------------------+-----------+----------------+
| version | N   | M   | participant record × N | final IV  | ciphertext     |
| 1 byte  | 1 B | 1 B | (variable)             | 12 bytes  | rest of blob   |
+---------+-----+-----+------------------------+-----------+----------------+
```

- **version** (`uint8`) — always `0x03` for this format.
- **N** (`uint8`) — total number of participants. `2`–`255`.
- **M** (`uint8`) — threshold: number of participants required to
  reconstruct the CEK. `2`–`N`.

### Participant record (repeated N times, in order)

```
+--------------+----------------+----------------+----------+----------+------------------+------------------+
| label length | label          | PBKDF2 iters   | salt     | IV       | wrapped share len| wrapped share    |
| 1 byte       | (variable)     | 4 bytes (BE)   | 16 bytes | 12 bytes | 2 bytes (BE)     | (variable)       |
+--------------+----------------+----------------+----------+----------+------------------+------------------+
```

- **label length** (`uint8`) — byte length of the UTF-8-encoded label
  that follows. `0`–`255`. A label identifies a participant to the humans
  involved (e.g. "Alice") — it is not secret, is not used in any key
  derivation, and an empty label (length `0`) is valid though the app's
  own UI requires a non-empty one.
- **label** — UTF-8 bytes, exactly `label length` of them. Not normalized;
  encoded exactly as entered.
- **PBKDF2 iterations** (`uint32`, big-endian) — this participant's own
  iteration count, independent of every other participant's.
- **salt** (16 random bytes) — this participant's own PBKDF2 salt.
- **IV** (12 random bytes) — this participant's own AES-GCM IV, for
  wrapping their share.
- **wrapped share length** (`uint16`, big-endian) — byte length of the
  wrapped share that follows (ciphertext including its 16-byte GCM tag).
  With a 32-byte CEK and this library's share encoding (secret length + 1
  byte for the x-coordinate), this is always `49` today — but a reader
  must use this field, not assume that number, since it is part of the
  self-describing format.
- **wrapped share** — `AES-256-GCM(participant key, IV, raw share)`,
  with **additional authenticated data (AAD)** equal to
  `version || N || M || label length || label || iterations || salt || IV`
  (i.e. every fixed-position byte of this one participant's own record,
  up to but not including the wrapped share itself). This binds a
  participant's wrapped share to their own label, salt, IV, and iteration
  count, and to the relic's overall N/M — tampering with any of it fails
  this participant's own GCM authentication check before anything else is
  attempted.

### After the N records

- **final IV** (12 random bytes) — the IV for the content layer (distinct
  from any per-participant IV above).
- **ciphertext** — the rest of the blob:
  `AES-256-GCM(CEK, final IV, plaintext)`, with **AAD equal to the entire
  header** — every byte of the blob from the version byte through the
  final IV, inclusive (i.e. everything except the ciphertext itself).
  This means tampering with *anything* in the header — the version, N,
  M, any participant's label/iterations/salt/IV/wrapped-share-length, or
  the final IV — is caught here even if it somehow passed every
  per-participant check, exactly mirroring version 2's AAD-binding
  philosophy in `encryption-spec.md`.

## Sealing (encryption)

1. Collect N participants, each contributing a label and a passphrase
   (entered directly, never round-tripped through RelicONE's server), and
   a threshold M (`2 ≤ M ≤ N`).
2. Generate a random 256-bit CEK (`crypto.getRandomValues`).
3. Split the CEK via SSS into N shares, threshold M
   (`split(cek, N, M)` → `Uint8Array[]`, one share per participant, in the
   same order as the participant list).
4. For each participant `i` (in order):
   a. Generate a random 16-byte salt and 12-byte IV.
   b. Normalize participant `i`'s passphrase to NFC, UTF-8-encode it, and
      derive a 256-bit key via PBKDF2-HMAC-SHA256 (600,000 iterations,
      this salt) — identical procedure to version 1/2's key derivation.
   c. Assemble this participant's record header:
      `label length || label || iterations || salt || IV`.
   d. Encrypt share `i` with `AES-256-GCM(key, IV, share_i)`, passing
      `version || N || M || <this record's header>` as AAD.
   e. Append the wrapped share length (`uint16` BE) and the wrapped share
      itself to the record.
5. Concatenate: `version(0x03) || N || M || record_1 || … || record_N`.
   This is the full header (everything computed so far).
6. Generate a random 12-byte final IV.
7. Encrypt the UTF-8 bytes of the plaintext with
   `AES-256-GCM(CEK, final IV, plaintext)`, passing the **entire header
   from step 5, plus the final IV**, as AAD.
8. Assemble the blob: `header || final IV || ciphertext`.
9. Upload the blob as the content of an Arweave transaction, exactly like
   version 2.
10. Discard the CEK, every share, and every passphrase — none of them is
    ever stored or transmitted anywhere by the app.

## Unsealing (decryption) — independent of the app

1. Download the Arweave transaction's content, same as version 1/2.
2. Read the first byte. `0x03` means this specification applies (`0x01`/
   `0x02` mean `encryption-spec.md` applies instead — a reader must branch
   here before assuming either format).
3. Read `N` (byte 2) and `M` (byte 3). Reject if either is outside
   `2`–`255`, or `M > N` — not a valid version-3 relic.
4. Walk the N participant records in order, reading each field per the
   layout above. A record whose declared lengths would run past the end
   of the blob means the blob is truncated or corrupt — stop and reject,
   the same defensive posture as version 1/2's minimum-length check.
5. After the Nth record, read the 12-byte final IV, then treat the
   remainder of the blob as the ciphertext.
6. For each participant a person can supply a passphrase for (order
   doesn't matter, and not everyone needs to be present — only M of N):
   a. Derive a key via PBKDF2-HMAC-SHA256 using *that participant's own*
      salt and iteration count (from their record) and the entered
      passphrase (NFC-normalized).
   b. Decrypt that participant's wrapped share with
      `AES-256-GCM(key, their IV, their wrapped share)`, passing
      `version || N || M || <that record's header>` as AAD (identical to
      what was used to wrap it).
   c. **If this fails, the passphrase entered for this specific
      participant is wrong** (or the record was tampered with) — this is
      known before anything else is attempted, and without touching any
      other participant's data. This is the "layered verification"
      property: each wrap is independently authenticated.
   d. On success, the decrypted bytes are that participant's raw SSS
      share.
7. Once at least M shares have been recovered this way (from any M of the
   N participants — which M doesn't matter), reconstruct the CEK:
   `combine(shares)`. Fewer than M shares present is not a partial or
   degraded state — SSS mathematically cannot reconstruct anything from
   them, so a reader must not attempt `combine` yet, and must present
   this as an explicit "M of N needed, only that many present so far"
   state rather than a silent hang or a misleading generic error.
8. Decrypt the content: `AES-256-GCM(CEK, final IV, ciphertext)`, passing
   the entire header **and** the final IV (everything read in steps
   2–5) as AAD.
9. **If step 8 fails despite every individual share in step 6 having
   passed its own check,** the shares that were combined don't actually
   belong together — for example, one of the "successfully" unwrapped
   shares came from a different relic's blob entirely (same passphrase
   reused elsewhere is not this case; see "Edge cases" below), or the
   blob's ciphertext portion is corrupted. `combine()` itself does not
   validate the shares it's given and can silently return a wrong CEK —
   this final AES-GCM authentication tag is what actually catches that,
   not any check inside the SSS library. Report this the same way version
   1/2's spec recommends reporting a wrong passphrase: honestly, without
   claiming to know which of the inputs was the problem.

## Independence from the app

Nothing above requires RelicONE, an account, or any network call beyond
fetching the one Arweave transaction. A participant needs only: the
transaction ID, their own passphrase, and this specification (or the
reference implementation of `sealMultiKey`/`unsealMultiKey` alongside
`sealText`/`unsealText` in [`crypto.ts`](./crypto.ts), and the offline CLI
in [`relicone-decrypt.ts`](./relicone-decrypt.ts), which supports this
format too). Participants never need an app account, never see each
other's passphrases, and never need to be online at the same time as each
other — "M of N present" can be satisfied by people entering their
passphrase into the same browser session (or the same CLI invocation) one
after another, at whatever pace suits them, or (for an independent
implementation) via any process that ends up with M valid shares before
calling `combine`.

## Edge cases

- **A relic's creator as one of the N participants.** No special
  handling — they hold a passphrase like anyone else and their share is
  wrapped identically.
- **Two participants choosing the same passphrase.** Harmless. Shares are
  independent random-looking values produced by `split`, not derived from
  the passphrase — the passphrase only decides *whose wrapping layer*
  opens, never what the share's value is. Two participants with identical
  passphrases simply both successfully unwrap their own (distinct)
  shares.
- **Fewer than M participants present.** See step 7 above — this must
  read as an explicit, honest state, not a hang or a generic failure.
- **A wrong passphrase for one specific participant.** Caught at that
  participant's own wrap (step 6c) before SSS is ever invoked — the
  error is attributable to that participant, unlike a wrong single
  passphrase in version 1/2 (where "wrong passphrase" and "tampered
  ciphertext" are indistinguishable).
- **Corrupted or foreign shares that individually unwrap correctly but
  don't reconstruct together.** Caught at the final content decryption
  (step 8/9), never silently accepted — see step 9's discussion of
  `combine()`'s own lack of verification.

## Practical limits (not part of the cryptographic format)

RelicONE's own `/seal` UI caps the number of participants it will let
someone configure for a new relic — a product decision about what a
personal relic plausibly needs, not a cryptographic one. This spec and
its reference `unsealMultiKey`/`relicone-decrypt.ts` place no such ceiling
beyond the algorithm's own 255-share bound: a reader must be able to
unseal a version-3 relic with more participants than RelicONE's own
`/seal` would ever create, since another implementation is free to
produce one.
