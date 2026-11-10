# Syntecxhub Secure File Transfer

![CI](https://github.com/<your-username>/Syntecxhub_Secure_File_Transfer/actions/workflows/ci.yml/badge.svg)

Encrypted file upload/download between a client and a server, with encrypted
storage on the server - built for the **Syntecxhub Internship - Project 2**
(*Encrypted File Transfer & Secure File Storage*).

## Features

| Requirement | Implementation |
|---|---|
| Encrypted upload/download (AES + secure channel) | **AES-256-GCM** end-to-end + **TLS 1.2+** with pinned certificate |
| Chunking | 1 MB chunks, streamed (large files never fully in memory) |
| Integrity checks (HMAC) | HMAC-SHA256 per chunk (verified before decryption) + GCM tag + SHA-256 per chunk and for the whole file |
| Resume support | `upload --resume <file_id>` sends only the missing chunks |
| Files encrypted on server disk | Client-side encryption **plus** server master-key AES-GCM re-encryption; file names encrypted too |
| Safe retrieval | Verified into a `.part` file, renamed only after all checks pass; path-traversal-proof |
| Threat model | [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) (MITM, key management, tampering, DoS, ...) |

## Installation

```bash
git clone https://github.com/<your-username>/Syntecxhub_Secure_File_Transfer.git
cd Syntecxhub_Secure_File_Transfer
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Quick start

```bash
# 1. Create a TLS certificate (add --host for the server's name/IP; repeatable)
python -m secure_transfer gen-cert --host localhost --host 127.0.0.1

# 2. Start the server (terminal 1)
export SFT_TOKEN="choose-a-long-random-token"
python -m secure_transfer server --host 127.0.0.1 --port 8443

# 3. Upload (terminal 2) - the passphrase is prompted and never sent to the server
export SFT_TOKEN="choose-a-long-random-token"
python -m secure_transfer upload ./secret.pdf
#   file_id: 3f9c...   <- keep this

# 4. List / download / delete
python -m secure_transfer list
python -m secure_transfer download 3f9c... -o ./downloads
python -m secure_transfer delete 3f9c...

# Resume an interrupted upload
python -m secure_transfer upload ./big.iso --resume 3f9c...
```

**Remote use:** copy `certs/server.crt` (the certificate only, never the `.key`) to
the client machine and pass `--cafile path/to/server.crt --host <server>`.

## Protocol

Each message: `[4-byte header length][JSON header][binary body]`.

| op | purpose |
|---|---|
| `init` | start/resume upload; server returns authoritative salt + stored chunk list |
| `put_chunk` | upload one encrypted chunk (+ SHA-256 and HMAC tag) |
| `complete` | finish upload with the encrypted metadata (name, size, SHA-256) |
| `get_meta` / `get_chunk` | download |
| `list` / `delete` | management |

## Security design (summary)

1. `scrypt(passphrase, per-file salt)` -> HKDF -> independent **AES** and **HMAC** keys.
2. Each chunk: AES-256-GCM, random nonce, AAD = `file_id:index`; HMAC-SHA256 over `aad || ciphertext`.
3. TLS protects the channel; the server only ever sees ciphertext and stores it
   re-encrypted under its own master key (`server_data/master.key`).
4. Downloads verify HMAC -> GCM tag -> chunk count -> whole-file SHA-256.

Read the full analysis in [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

> ⚠️ Educational project, not independently audited. **If you lose the
> passphrase, the data cannot be recovered.** Never commit `certs/*.key`,
> `server_data/` or tokens (already in `.gitignore`).

## Testing

```bash
pip install -r requirements-dev.txt
python -m pytest
```

Tests cover crypto round-trips, tamper/swap/wrong-key detection, end-to-end
transfer, plaintext-absence on disk, resume, bad token, path traversal and
untrusted certificates.

## Project layout

```
secure_transfer/  crypto.py · protocol.py · server.py · client.py · certs.py · cli.py
tests/            unit + end-to-end tests
docs/             THREAT_MODEL.md
```

## License

MIT
