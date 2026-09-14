/**
 * jsdom's own `window.crypto` doesn't reliably implement `SubtleCrypto` —
 * `crypto.ts` needs the real thing (AES-256-GCM, PBKDF2) to do anything
 * meaningful. Node has provided a fully working Web Crypto API as
 * `globalThis.crypto` since v19, so point jsdom's window at that instead of
 * whatever stub it ships with.
 */
Object.defineProperty(window, "crypto", {
  value: globalThis.crypto,
  configurable: true,
});
