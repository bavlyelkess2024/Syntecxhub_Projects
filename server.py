"""TLS file server with encrypted-at-rest chunk storage."""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import re
import shutil
import socket
import socketserver
import ssl
import threading
import time
from pathlib import Path
from typing import Dict, List, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .crypto import NONCE_LEN, SALT_LEN, TAG_LEN
from .protocol import ProtocolError, recv_msg, send_msg

log = logging.getLogger("secure_transfer.server")
FILE_ID_RE = re.compile(r"^[0-9a-f]{32}$")   # blocks path traversal
MAX_CHUNKS = 100_000


class ServerError(Exception):
    pass


class AuthError(ServerError):
    pass


def _atomic_write(path: Path, data: bytes) -> None:
    tmp = path.with_name(path.name + f".{os.urandom(4).hex()}.tmp")
    tmp.write_bytes(data)
    os.replace(tmp, path)


class Storage:
    """On-disk store. Every chunk is re-encrypted with a server master key
    (AES-256-GCM) so the disk never holds data in a usable form, even if the
    client sent unencrypted data. The master key lives in `master.key`."""

    def __init__(self, data_dir: str):
        self.root = Path(data_dir)
        self.files = self.root / "files"
        self.files.mkdir(parents=True, exist_ok=True)
        key_path = self.root / "master.key"
        if not key_path.exists():
            fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(os.urandom(32))
        self._aes = AESGCM(key_path.read_bytes())
        self._lock = threading.Lock()

    # -- helpers
    def _dir(self, file_id: str) -> Path:
        if not isinstance(file_id, str) or not FILE_ID_RE.match(file_id):
            raise ServerError("invalid file_id")
        return self.files / file_id

    def _seal(self, data: bytes, aad: bytes) -> bytes:
        nonce = os.urandom(NONCE_LEN)
        return nonce + self._aes.encrypt(nonce, data, aad)

    def _open(self, rec: bytes, aad: bytes) -> bytes:
        return self._aes.decrypt(rec[:NONCE_LEN], rec[NONCE_LEN:], aad)

    def _state(self, file_id: str) -> Dict:
        path = self._dir(file_id) / "state.json"
        if not path.exists():
            raise ServerError("file not found")
        return json.loads(path.read_text())

    @staticmethod
    def _have(d: Path) -> List[int]:
        return sorted(int(p.stem) for p in (d / "chunks").glob("*.bin"))

    # -- operations
    def init_upload(self, file_id: str, salt_hex: str, total: int) -> Tuple[str, List[int]]:
        if not isinstance(total, int) or not 1 <= total <= MAX_CHUNKS:
            raise ServerError("invalid chunk count")
        if len(bytes.fromhex(salt_hex)) != SALT_LEN:
            raise ServerError("invalid salt")
        d = self._dir(file_id)
        with self._lock:
            if (d / "state.json").exists():
                st = json.loads((d / "state.json").read_text())
                if st["complete"]:
                    raise ServerError("file already exists")
                if st["total"] != total:
                    raise ServerError("chunk count mismatch for resume")
            else:
                (d / "chunks").mkdir(parents=True)
                st = {"salt": salt_hex, "total": total, "complete": False,
                      "meta": None, "created": int(time.time())}
                _atomic_write(d / "state.json", json.dumps(st).encode())
        return st["salt"], self._have(d)

    def put_chunk(self, file_id: str, index: int, sha256_hex: str,
                  tag_hex: str, blob: bytes) -> None:
        st = self._state(file_id)
        if st["complete"]:
            raise ServerError("file already complete")
        if not isinstance(index, int) or not 0 <= index < st["total"]:
            raise ServerError("chunk index out of range")
        if hashlib.sha256(blob).hexdigest() != sha256_hex:
            raise ServerError("chunk checksum mismatch")
        tag = bytes.fromhex(tag_hex)
        if len(tag) != TAG_LEN:
            raise ServerError("invalid tag")
        rec = self._seal(tag + blob, f"{file_id}:{index}".encode())
        _atomic_write(self._dir(file_id) / "chunks" / f"{index}.bin", rec)

    def complete(self, file_id: str, meta: Dict) -> None:
        d = self._dir(file_id)
        with self._lock:
            st = self._state(file_id)
            if self._have(d) != list(range(st["total"])):
                raise ServerError("upload incomplete")
            st.update(complete=True, meta=meta)
            _atomic_write(d / "state.json", json.dumps(st).encode())

    def get_meta(self, file_id: str) -> Dict:
        st = self._state(file_id)
        if not st["complete"]:
            raise ServerError("upload not complete")
        return {"salt": st["salt"], "total": st["total"], "meta": st["meta"]}

    def get_chunk(self, file_id: str, index: int) -> Tuple[bytes, bytes]:
        st = self._state(file_id)
        if not st["complete"]:
            raise ServerError("upload not complete")
        if not isinstance(index, int) or not 0 <= index < st["total"]:
            raise ServerError("chunk index out of range")
        rec = (self._dir(file_id) / "chunks" / f"{index}.bin").read_bytes()
        try:
            plain = self._open(rec, f"{file_id}:{index}".encode())
        except Exception:
            raise ServerError("stored chunk failed integrity check")
        return plain[:TAG_LEN], plain[TAG_LEN:]

    def list_files(self) -> List[Dict]:
        out = []
        for d in sorted(self.files.iterdir()):
            try:
                st = json.loads((d / "state.json").read_text())
            except (OSError, ValueError):
                continue
            out.append({"file_id": d.name, "chunks": st["total"],
                        "complete": st["complete"], "created": st["created"]})
        return out

    def delete(self, file_id: str) -> None:
        d = self._dir(file_id)
        if not d.exists():
            raise ServerError("file not found")
        with self._lock:
            shutil.rmtree(d)


class _Handler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        sock: ssl.SSLSocket = self.request
        try:
            sock.settimeout(15)
            sock.do_handshake()
            sock.settimeout(60)
        except (ssl.SSLError, OSError):
            return
        while True:
            try:
                header, body = recv_msg(sock)
            except (ConnectionError, socket.timeout, ssl.SSLError, OSError):
                return
            except ProtocolError as exc:
                self._reply(sock, {"status": "error", "error": str(exc)})
                return
            close = False
            try:
                resp, rbody = self.server.dispatch(header, body)
            except AuthError:
                resp, rbody, close = {"status": "error", "error": "authentication failed"}, b"", True
            except ServerError as exc:
                resp, rbody = {"status": "error", "error": str(exc)}, b""
            except (ValueError, KeyError, TypeError):
                resp, rbody = {"status": "error", "error": "bad request"}, b""
            except Exception:
                log.exception("internal error")
                resp, rbody = {"status": "error", "error": "internal error"}, b""
            if not self._reply(sock, resp, rbody) or close:
                return

    @staticmethod
    def _reply(sock, header, body=b"") -> bool:
        try:
            send_msg(sock, header, body)
            return True
        except OSError:
            return False


class TransferServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address, storage: Storage, token: str, certfile: str, keyfile: str):
        super().__init__(address, _Handler)
        self.storage = storage
        self.token_hash = hashlib.sha256(token.encode()).digest()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(certfile, keyfile)
        self._ctx = ctx

    def get_request(self):
        sock, addr = super().get_request()
        return self._ctx.wrap_socket(sock, server_side=True,
                                     do_handshake_on_connect=False), addr

    def dispatch(self, h: Dict, body: bytes) -> Tuple[Dict, bytes]:
        token = h.get("token")
        if not isinstance(token, str) or not hmac.compare_digest(
                hashlib.sha256(token.encode()).digest(), self.token_hash):
            time.sleep(1)  # slow down brute force
            raise AuthError()
        op, st = h.get("op"), self.storage
        ok: Dict = {"status": "ok"}
        if op == "init":
            salt, have = st.init_upload(h["file_id"], h["salt"], h["total"])
            return {**ok, "salt": salt, "have": have}, b""
        if op == "put_chunk":
            st.put_chunk(h["file_id"], h["index"], h["sha256"], h["tag"], body)
            return ok, b""
        if op == "complete":
            if not isinstance(h["meta"], dict):
                raise ServerError("bad meta")
            st.complete(h["file_id"], h["meta"])
            return ok, b""
        if op == "get_meta":
            return {**ok, **st.get_meta(h["file_id"])}, b""
        if op == "get_chunk":
            tag, blob = st.get_chunk(h["file_id"], h["index"])
            return {**ok, "tag": tag.hex(), "sha256": hashlib.sha256(blob).hexdigest()}, blob
        if op == "list":
            return {**ok, "files": st.list_files()}, b""
        if op == "delete":
            st.delete(h["file_id"])
            return ok, b""
        raise ServerError("unknown operation")


def serve(host: str, port: int, data_dir: str, token: str, cert: str, key: str) -> None:
    srv = TransferServer((host, port), Storage(data_dir), token, cert, key)
    log.info("listening on %s:%d (TLS)", host, port)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
