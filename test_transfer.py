import os

import pytest

from secure_transfer.client import Client, TransferError
from secure_transfer.crypto import IntegrityError

PW = "a strong passphrase"


def make_file(path, size):
    data = os.urandom(size)
    path.write_bytes(data)
    return data


def test_upload_download_roundtrip(env):
    src = env.tmp / "report.bin"
    data = make_file(src, 350_000)                       # 4 chunks of 100 KB
    with env.connect() as c:
        fid = c.upload(str(src), PW, chunk_size=100_000)
        out = c.download(fid, PW, str(env.tmp / "out"))
    assert open(out, "rb").read() == data
    assert os.path.basename(out) == "report.bin"


def test_server_disk_holds_no_plaintext(env):
    src = env.tmp / "doc.txt"
    marker = b"TOP-SECRET-MARKER-1234567890"
    src.write_bytes(marker * 1000)
    with env.connect() as c:
        fid = c.upload(str(src), PW, chunk_size=10_000)
    for p in (env.data / "files" / fid).rglob("*"):
        if p.is_file():
            assert marker not in p.read_bytes()
            assert b"doc.txt" not in p.read_bytes()      # file name is encrypted too


def test_empty_file(env):
    src = env.tmp / "empty"
    src.write_bytes(b"")
    with env.connect() as c:
        fid = c.upload(str(src), PW)
        out = c.download(fid, PW, str(env.tmp / "o"))
    assert open(out, "rb").read() == b""


def test_wrong_passphrase_fails(env):
    src = env.tmp / "a.bin"
    make_file(src, 1000)
    with env.connect() as c:
        fid = c.upload(str(src), PW)
        with pytest.raises(IntegrityError):
            c.download(fid, "nope", str(env.tmp / "o"))
    assert not list((env.tmp / "o").glob("*")) if (env.tmp / "o").exists() else True


def test_bad_token_rejected(env):
    with env.connect(token="wrong") as c:
        with pytest.raises((TransferError, ConnectionError)):
            c.list_files()


def test_resume_skips_stored_chunks(env):
    src = env.tmp / "big.bin"
    data = make_file(src, 500_000)                       # 5 chunks

    class Boom(Exception):
        pass

    def die_after_two(index, total, sent):
        if index == 1:
            raise Boom()

    fid = "ab" * 16
    with env.connect() as c:
        with pytest.raises(Boom):
            c.upload(str(src), PW, file_id=fid, chunk_size=100_000, progress=die_after_two)
    sent_flags = []
    with env.connect() as c:
        c.upload(str(src), PW, file_id=fid, chunk_size=100_000,
                 progress=lambda i, t, s: sent_flags.append(s))
        out = c.download(fid, PW, str(env.tmp / "o"))
    assert sent_flags == [False, False, True, True, True]
    assert open(out, "rb").read() == data


def test_tampered_storage_detected(env):
    src = env.tmp / "t.bin"
    make_file(src, 2000)
    with env.connect() as c:
        fid = c.upload(str(src), PW)
        chunk = env.data / "files" / fid / "chunks" / "0.bin"
        raw = bytearray(chunk.read_bytes())
        raw[20] ^= 0xFF
        chunk.write_bytes(bytes(raw))
        with pytest.raises(TransferError):
            c.download(fid, PW, str(env.tmp / "o"))


@pytest.mark.parametrize("bad", ["../../etc/passwd", "..", "x" * 32, "A" * 32, ""])
def test_path_traversal_rejected(env, bad):
    with env.connect() as c:
        with pytest.raises(TransferError):
            c.download(bad, PW, str(env.tmp / "o"))


def test_list_and_delete(env):
    src = env.tmp / "l.bin"
    make_file(src, 100)
    with env.connect() as c:
        fid = c.upload(str(src), PW)
        assert [f["file_id"] for f in c.list_files()] == [fid]
        c.delete(fid)
        assert c.list_files() == []


def test_untrusted_certificate_rejected(env, tmp_path):
    from secure_transfer.certs import generate_self_signed
    import ssl
    other = str(tmp_path / "other.crt")
    generate_self_signed(other, str(tmp_path / "other.key"))
    port = env.connect().sock.getpeername()[1]
    with pytest.raises(ssl.SSLError):
        Client("127.0.0.1", port, "t", other)
