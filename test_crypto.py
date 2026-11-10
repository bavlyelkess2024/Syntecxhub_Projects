import pytest

from secure_transfer.crypto import (IntegrityError, decrypt_chunk, derive_keys,
                                    encrypt_chunk)

SALT = b"0123456789abcdef"


@pytest.fixture
def keys():
    return derive_keys("correct horse", SALT, n=2 ** 10)


def test_roundtrip(keys):
    blob, tag = encrypt_chunk(*keys, "f" * 32, 0, b"hello world")
    assert b"hello" not in blob
    assert decrypt_chunk(*keys, "f" * 32, 0, blob, tag) == b"hello world"


def test_nonce_is_random(keys):
    a, _ = encrypt_chunk(*keys, "f" * 32, 0, b"same")
    b, _ = encrypt_chunk(*keys, "f" * 32, 0, b"same")
    assert a != b


def test_tamper_detected(keys):
    blob, tag = encrypt_chunk(*keys, "f" * 32, 0, b"secret")
    bad = bytearray(blob)
    bad[-1] ^= 1
    with pytest.raises(IntegrityError):
        decrypt_chunk(*keys, "f" * 32, 0, bytes(bad), tag)


def test_chunk_swap_detected(keys):
    blob, tag = encrypt_chunk(*keys, "f" * 32, 0, b"chunk zero")
    with pytest.raises(IntegrityError):
        decrypt_chunk(*keys, "f" * 32, 1, blob, tag)       # wrong index
    with pytest.raises(IntegrityError):
        decrypt_chunk(*keys, "e" * 32, 0, blob, tag)       # wrong file


def test_wrong_passphrase(keys):
    blob, tag = encrypt_chunk(*keys, "f" * 32, 0, b"secret")
    other = derive_keys("wrong", SALT, n=2 ** 10)
    with pytest.raises(IntegrityError):
        decrypt_chunk(*other, "f" * 32, 0, blob, tag)
