# Threat Model

## Assets
1. File contents and file names (confidentiality).
2. Integrity/authenticity of stored and transferred files.
3. Passphrase, access token, server master key and TLS private key.
4. Server availability.

## Trust assumptions
- The **client machine** is trusted. The **network** and the **server's disk/admin** are *not* trusted with plaintext.
- The server's TLS certificate is distributed to clients out-of-band (certificate pinning).

## Architecture at a glance

```
 client --TLS 1.2+ (pinned cert)--> server
   |  AES-256-GCM chunk + HMAC            |  re-encrypt chunk (AES-256-GCM, master.key)
   |  key = scrypt(passphrase, salt)      v
   +- passphrase never leaves client   disk: files/<id>/chunks/N.bin (ciphertext only)
```

Three independent layers: **TLS** (in transit) -> **client-side AES-GCM + HMAC** (end-to-end) -> **server master-key AES-GCM** (at rest).

## Threats & mitigations

| # | Threat | Mitigation | Residual risk |
|---|---|---|---|
| 1 | **Man-in-the-middle** / eavesdropping | TLS >= 1.2; the client verifies the server certificate and hostname against a **pinned self-signed cert** (`--cafile`). The payload is additionally end-to-end encrypted, so even a TLS break exposes only ciphertext. | If the cert file is obtained over an insecure channel, the first trust decision is weak. Distribute it out-of-band. |
| 2 | **Key management** - weak/lost keys | Keys derived with **scrypt** (N=2^15) from the passphrase and a fresh 16-byte **per-file salt**; **HKDF** splits independent AES and HMAC keys. The passphrase and keys never reach the server. | A weak passphrase can be brute-forced offline if ciphertext is stolen. A lost passphrase means unrecoverable data (by design). |
| 3 | **Tampering** with chunks in transit or on disk | Per-chunk SHA-256 (transport), HMAC-SHA256 verified before decryption, AES-GCM tag, and a whole-file SHA-256 inside the encrypted metadata. Server-side AES-GCM also detects disk corruption. Downloads go to a `.part` file and are renamed only after full verification. | - |
| 4 | **Chunk reordering / swapping / replay between files** | `file_id:index` is bound as AAD (GCM) and HMAC input; the chunk count is authenticated in the encrypted metadata and compared with the server's claim (detects truncation/extension). | - |
| 5 | **Nonce reuse** | Fresh random 96-bit nonce per chunk (`os.urandom`); keys are per file. | Negligible collision probability at supported sizes (<= 100 000 chunks per key). |
| 6 | **Unauthorized access** | Shared access token compared in constant time; failed attempts are delayed (1 s) and the connection is closed. | Single shared token, no per-user identity or per-IP rate limit. Use a firewall/VPN for exposed servers. |
| 7 | **Path traversal** | `file_id` must match `^[0-9a-f]{32}$`; stored names are never used as server paths; the client strips directory components from the decrypted file name. | - |
| 8 | **Denial of service** | Max header (64 KB) and body (4 MB) sizes, max 100 000 chunks per file, socket and handshake timeouts, threaded handlers. | No global quotas or per-client rate limiting. |
| 9 | **Server compromise** | The attacker gets only end-to-end ciphertext (the master key adds nothing beyond the client layer). File names are encrypted. | Metadata leaks: approximate file size, upload time, number of chunks. |
| 10 | **Interrupted transfers** | Resumable uploads: the server reports stored chunks and the client sends only the missing ones. Atomic writes prevent half-written chunks. | - |

## Out of scope / limitations
- No user accounts, sharing, or key rotation; no forward secrecy for stored files if the passphrase leaks.
- Not audited - **educational project**. Do not use for high-assurance secrets without review.

## Hardening checklist for real deployments
- Keep `master.key` and `certs/server.key` on separate storage with `chmod 600`.
- Run behind a firewall / VPN; use a CA-signed cert if clients cannot pin.
- Use long random passphrases (4+ random words) and rotate the access token.
- Add rate limiting, quotas and audit logging.
