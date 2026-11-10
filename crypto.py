"""Client-side cryptography.

* Keys: scrypt(passphrase, per-file salt) -> HKDF -> separate AES and HMAC keys.
* Confidentiality + integrity: AES-256-GCM per chunk, with AAD binding the
  chunk to (file_id, index) so chunks cannot be swapped, reordered or replayed.
* Defence in depth: an extra HMAC-SHA256 over (aad || ciphertext), verified
  *before* decryption.
"""
from __future__ import annotations

import hashlib
import hmac
import os
from typing import Tuple, Union

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

CHUNK_SIZE = 1024 * 1024
NONCE_LEN = 12
SALT_LEN = 16
TAG_LEN = 32  # HMAC-SHA256


class IntegrityError(Exception):
    """Data failed authentication (tampered, wrong key or wrong passphrase)."""


def derive_keys(passphrase: str, salt: bytes, n: int = 2 ** 15) -> Tuple[bytes, bytes]:
    """Return (aes_key, hmac_key) derived from a passphrase and salt."""
    master = Scrypt(salt=salt, length=32, n=n, r=8, p=1).derive(passphrase.encode())
    enc = HKDF(hashes.SHA256(), 32, None, b"sft-enc").derive(master)
    mac = HKDF(hashes.SHA256(), 32, None, b"sft-mac").derive(master)
    return enc, mac


def _aad(file_id: str, index: Union[int, str]) -> bytes:
    return f"{file_id}:{index}".encode()


def encrypt_chunk(enc_key: bytes, mac_key: bytes, file_id: str,
                  index: Union[int, str], plaintext: bytes) -> Tuple[bytes, bytes]:
    """Return (nonce||ciphertext, hmac_tag)."""
    aad = _aad(file_id, index)
    nonce = os.urandom(NONCE_LEN)
    blob = nonce + AESGCM(enc_key).encrypt(nonce, plaintext, aad)
    return blob, hmac.new(mac_key, aad + blob, hashlib.sha256).digest()


def decrypt_chunk(enc_key: bytes, mac_key: bytes, file_id: str,
                  index: Union[int, str], blob: bytes, tag: bytes) -> bytes:
    aad = _aad(file_id, index)
    expected = hmac.new(mac_key, aad + blob, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, tag):
        raise IntegrityError("HMAC verification failed")
    try:
        return AESGCM(enc_key).decrypt(blob[:NONCE_LEN], blob[NONCE_LEN:], aad)
    except Exception as exc:  # cryptography.exceptions.InvalidTag
        raise IntegrityError("AES-GCM authentication failed") from exc
