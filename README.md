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
  (Web Crypto API only) that this spec is checked against.
- [`crypto.test.ts`](./crypto.test.ts) — conformance tests: round trips,
  passphrase normalization, tamper detection, and the exact byte values
  the spec promises (format version, iteration count, blob length).

Run the tests yourself:

```bash
npm install
npm test
```

RelicONE's own application repository is private — this repository exists
so the encryption format itself doesn't have to be.
