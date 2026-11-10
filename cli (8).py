"""Command-line interface."""
from __future__ import annotations

import argparse
import getpass
import logging
import os
import sys
from typing import List, Optional

from . import __version__
from .certs import generate_self_signed


def _secret(value: Optional[str], env: str, prompt: str) -> str:
    return value or os.environ.get(env) or getpass.getpass(prompt)


def _connect(a):
    from .client import Client
    token = _secret(a.token, "SFT_TOKEN", "Access token: ")
    return Client(a.host, a.port, token, a.cafile)


def _progress(index: int, total: int, sent: bool) -> None:
    print(f"\r  chunk {index + 1}/{total}{'' if sent else ' (already on server)'}   ",
          end="", flush=True)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="secure-transfer",
                                description="Encrypted file transfer & secure storage")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("gen-cert", help="generate a self-signed TLS certificate")
    g.add_argument("--cert", default="certs/server.crt")
    g.add_argument("--key", default="certs/server.key")
    g.add_argument("--host", action="append", help="SAN host/IP (repeatable)")

    s = sub.add_parser("server", help="run the server")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8443)
    s.add_argument("--data-dir", default="server_data")
    s.add_argument("--cert", default="certs/server.crt")
    s.add_argument("--key", default="certs/server.key")
    s.add_argument("--token", help="access token (or env SFT_TOKEN)")

    def client_args(sp):
        sp.add_argument("--host", default="127.0.0.1")
        sp.add_argument("--port", type=int, default=8443)
        sp.add_argument("--cafile", default="certs/server.crt",
                        help="trusted server certificate (pinning)")
        sp.add_argument("--token", help="access token (or env SFT_TOKEN)")

    u = sub.add_parser("upload", help="encrypt and upload a file")
    client_args(u)
    u.add_argument("path")
    u.add_argument("--resume", metavar="FILE_ID", help="resume an interrupted upload")
    u.add_argument("--passphrase", help="(or env SFT_PASSPHRASE; prompted if omitted)")

    d = sub.add_parser("download", help="download and decrypt a file")
    client_args(d)
    d.add_argument("file_id")
    d.add_argument("-o", "--out-dir", default=".")
    d.add_argument("--passphrase")

    l = sub.add_parser("list", help="list stored files")
    client_args(l)
    r = sub.add_parser("delete", help="delete a stored file")
    client_args(r)
    r.add_argument("file_id")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    a = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    try:
        if a.cmd == "gen-cert":
            generate_self_signed(a.cert, a.key, a.host or ["localhost", "127.0.0.1"])
            print(f"Certificate: {a.cert}\nPrivate key: {a.key} (keep secret!)")
        elif a.cmd == "server":
            from .server import serve
            token = _secret(a.token, "SFT_TOKEN", "Access token: ")
            serve(a.host, a.port, a.data_dir, token, a.cert, a.key)
        elif a.cmd == "upload":
            pw = _secret(a.passphrase, "SFT_PASSPHRASE", "Encryption passphrase: ")
            with _connect(a) as c:
                fid = a.resume
                if not fid:
                    import secrets
                    fid = secrets.token_hex(16)
                print(f"file_id: {fid}  (use --resume {fid} if interrupted)")
                c.upload(a.path, pw, file_id=fid, progress=_progress)
            print("\nUpload complete. Keep your passphrase safe - it cannot be recovered.")
        elif a.cmd == "download":
            pw = _secret(a.passphrase, "SFT_PASSPHRASE", "Encryption passphrase: ")
            with _connect(a) as c:
                dest = c.download(a.file_id, pw, a.out_dir, progress=_progress)
            print(f"\nSaved and verified: {dest}")
        elif a.cmd == "list":
            with _connect(a) as c:
                for f in c.list_files():
                    state = "complete" if f["complete"] else "partial"
                    print(f"{f['file_id']}  {f['chunks']} chunks  {state}")
        elif a.cmd == "delete":
            with _connect(a) as c:
                c.delete(a.file_id)
            print("Deleted.")
    except Exception as exc:
        print(f"\nerror: {exc}", file=sys.stderr)
        return 1
    return 0
