"""Client: end-to-end encrypted chunked upload (resumable) and download."""
from __future__ import annotations

import hashlib
import json
import math
import os
import secrets
import socket
import ssl
from typing import Callable, Dict, List, Optional

from .crypto import (CHUNK_SIZE, SALT_LEN, IntegrityError, decrypt_chunk,
                     derive_keys, encrypt_chunk)
from .protocol import recv_msg, send_msg

Progress = Optional[Callable[[int, int, bool], None]]  # (index, total, was_sent)


class TransferError(Exception):
    pass


class Client:
    def __init__(self, host: str, port: int, token: str, cafile: str,
                 timeout: float = 30.0):
        ctx = ssl.create_default_context(cafile=cafile)   # verifies cert + hostname
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        raw = socket.create_connection((host, port), timeout=timeout)
        self.sock = ctx.wrap_socket(raw, server_hostname=host)
        self.token = token

    def close(self) -> None:
        self.sock.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def _call(self, header: Dict, body: bytes = b""):
        send_msg(self.sock, {**header, "token": self.token}, body)
        resp, rbody = recv_msg(self.sock)
        if resp.get("status") != "ok":
            raise TransferError(resp.get("error", "request failed"))
        return resp, rbody

    # -- upload
    def upload(self, path: str, passphrase: str, file_id: Optional[str] = None,
               chunk_size: int = CHUNK_SIZE, progress: Progress = None) -> str:
        """Encrypt and upload `path`. Pass the `file_id` of an interrupted
        upload to resume it (already-stored chunks are skipped)."""
        size = os.path.getsize(path)
        total = max(1, math.ceil(size / chunk_size))
        file_id = file_id or secrets.token_hex(16)
        resp, _ = self._call({"op": "init", "file_id": file_id,
                              "salt": os.urandom(SALT_LEN).hex(), "total": total})
        have = set(resp["have"])
        enc_key, mac_key = derive_keys(passphrase, bytes.fromhex(resp["salt"]))

        whole = hashlib.sha256()
        with open(path, "rb") as fh:
            for index in range(total):
                data = fh.read(chunk_size)
                whole.update(data)
                sent = index not in have
                if sent:
                    blob, tag = encrypt_chunk(enc_key, mac_key, file_id, index, data)
                    self._call({"op": "put_chunk", "file_id": file_id, "index": index,
                                "sha256": hashlib.sha256(blob).hexdigest(),
                                "tag": tag.hex()}, blob)
                if progress:
                    progress(index, total, sent)

        meta = json.dumps({"name": os.path.basename(path), "size": size,
                           "total": total, "sha256": whole.hexdigest()}).encode()
        mblob, mtag = encrypt_chunk(enc_key, mac_key, file_id, "meta", meta)
        self._call({"op": "complete", "file_id": file_id,
                    "meta": {"blob": mblob.hex(), "tag": mtag.hex()}})
        return file_id

    # -- download
    def download(self, file_id: str, passphrase: str, out_dir: str = ".",
                 progress: Progress = None) -> str:
        info, _ = self._call({"op": "get_meta", "file_id": file_id})
        enc_key, mac_key = derive_keys(passphrase, bytes.fromhex(info["salt"]))
        try:
            meta = json.loads(decrypt_chunk(
                enc_key, mac_key, file_id, "meta",
                bytes.fromhex(info["meta"]["blob"]), bytes.fromhex(info["meta"]["tag"])))
        except IntegrityError as exc:
            raise IntegrityError("wrong passphrase or tampered metadata") from exc
        if meta["total"] != info["total"]:
            raise IntegrityError("chunk count mismatch (truncation/extension attack?)")

        name = os.path.basename(str(meta["name"]).replace("\\", "/"))
        if name in ("", ".", ".."):
            raise TransferError("unsafe file name in metadata")
        os.makedirs(out_dir, exist_ok=True)
        dest, part = os.path.join(out_dir, name), os.path.join(out_dir, name + ".part")

        whole = hashlib.sha256()
        try:
            with open(part, "wb") as out:
                for index in range(meta["total"]):
                    resp, blob = self._call({"op": "get_chunk", "file_id": file_id,
                                             "index": index})
                    if hashlib.sha256(blob).hexdigest() != resp["sha256"]:
                        raise IntegrityError(f"chunk {index} corrupted in transit")
                    data = decrypt_chunk(enc_key, mac_key, file_id, index, blob,
                                         bytes.fromhex(resp["tag"]))
                    whole.update(data)
                    out.write(data)
                    if progress:
                        progress(index, meta["total"], True)
            if whole.hexdigest() != meta["sha256"]:
                raise IntegrityError("final SHA-256 mismatch")
        except Exception:
            if os.path.exists(part):
                os.remove(part)
            raise
        os.replace(part, dest)
        return dest

    def list_files(self) -> List[Dict]:
        return self._call({"op": "list"})[0]["files"]

    def delete(self, file_id: str) -> None:
        self._call({"op": "delete", "file_id": file_id})
