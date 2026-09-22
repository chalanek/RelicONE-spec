# RelicONE — Sealed Relic Encryption Spec

The open, standalone specification for the "Sealed Relic" format used by
RelicONE — a permanent, decentralized, encrypted vault built on Arweave.
Client-side AES-256-GCM with a PBKDF2-derived key, designed so a sealed
relic stays decryptable without the app, the company behind it, or this
repository — using only the format below and a standard cryptographic
library.

- [`encryption-spec.md`](./encryption-spec.md) — the full specification:
  primitives, the exact byte layout, and the sealing/unsealing procedures.
- [`crypto.ts`](./crypto.ts) — a dependency-free reference implementation
  (Web Crypto API only) that this spec is checked against. Runs anywhere
  the Web Crypto API is available — a browser, or plain Node.js 20+
  (`globalThis.crypto.subtle`), no `node:crypto` legacy module needed.
- [`crypto.test.ts`](./crypto.test.ts) — conformance tests: round trips,
  passphrase normalization, tamper detection, and the exact byte values
  the spec promises (format version, iteration count, blob length).
- [`relicone-decrypt.ts`](./relicone-decrypt.ts) — an offline CLI
  decryptor. Concrete proof of the "decryptable without the app, the
  company, or this repository" claim below: it decrypts a real sealed
  relic from nothing but a public Arweave gateway (or a local copy of the
  blob) and a passphrase, using only this repository.

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

Runs under plain `node` — no `ts-node`, `tsx`, or build step. The
passphrase is always requested interactively, with input hidden; it is
never accepted as a command-line argument, since that would leak into
shell history and be visible to `ps` on a shared machine.

Run the tests yourself:

```bash
npm install
npm test
```

RelicONE's own application repository is private — this repository exists
so the encryption format itself doesn't have to be.
