# RelicONE — Sealed Relic Encryption Spec

The open, standalone specification for the "Sealed Relic" format used by
RelicONE — a permanent, decentralized, encrypted vault built on Arweave.
Client-side AES-256-GCM with a PBKDF2-derived key, designed so a sealed
relic stays decryptable without the app, the company behind it, or this
repository — using only the format below and a standard cryptographic
library. Two formats exist: the original single-passphrase format
(versions 1/2) and a multi-key, M-of-N format (version 3) built on
Shamir's Secret Sharing, where any M of N participants' own passphrases
together unlock a relic that no fewer than M reveal anything about.

- [`encryption-spec.md`](./encryption-spec.md) — the full single-passphrase
  specification (v1/v2): primitives, the exact byte layout, and the
  sealing/unsealing procedures.
- [`multi-key-encryption-spec.md`](./multi-key-encryption-spec.md) — the
  multi-key (M-of-N, v3) specification, a distinct byte format sibling to
  the above, not a revision of it.
- [`crypto.ts`](./crypto.ts) — the reference implementation (Web Crypto API
  plus the audited, zero-runtime-dependency
  [`shamir-secret-sharing`](https://www.npmjs.com/package/shamir-secret-sharing)
  library for v3's secret splitting) that both specs above are checked
  against. Runs anywhere the Web Crypto API is available — a browser, or
  plain Node.js 20+ (`globalThis.crypto.subtle`), no `node:crypto` legacy
  module needed.
- [`crypto.test.ts`](./crypto.test.ts) /
  [`multi-key-crypto.test.ts`](./multi-key-crypto.test.ts) — conformance
  tests: round trips, passphrase normalization, tamper detection, and the
  exact byte values each spec promises (format version, iteration count,
  blob length, participant/threshold bounds).
- [`relicone-decrypt.ts`](./relicone-decrypt.ts) — an offline CLI
  decryptor, for both formats. Concrete proof of the "decryptable without
  the app, the company, or this repository" claim below: it decrypts a
  real sealed relic from nothing but a public Arweave gateway (or a local
  copy of the blob) and a passphrase (or, for a multi-key relic, M of N
  participants' passphrases, prompted one at a time), using only this
  repository.

## Decrypting a relic yourself, without the app

```bash
npm install

# From a live Arweave transaction (fetched from https://arweave.net/<tx-id>):
node relicone-decrypt.ts <transaction-id>

# From a blob you already downloaded, entirely offline:
node relicone-decrypt.ts ./relic.bin

# Write the plaintext to a file instead of stdout:
node relicone-decrypt.ts <transaction-id> --out relic.txt
```

Runs under plain `node` — no `ts-node`, `tsx`, or build step — on
**Node.js 22.18.0 or later**, where TypeScript type stripping is enabled
by default. On Node 22.6.0–22.17.x, pass `--experimental-strip-types`
explicitly (`node --experimental-strip-types relicone-decrypt.ts
<transaction-id>`); Node 20.x cannot run `.ts` files directly at all.
Every passphrase is always requested interactively, with input hidden; none
is ever accepted as a command-line argument, since that would leak into
shell history and be visible to `ps` on a shared machine. For a multi-key
(version-3) relic, the CLI detects this automatically and prompts once per
participant, in order, stopping as soon as enough have been entered
correctly — see [`multi-key-encryption-spec.md`](./multi-key-encryption-spec.md).

Run the tests yourself:

```bash
npm install
npm test
```

RelicONE's own application repository is private — this repository exists
so the encryption format itself doesn't have to be.
