"""Length-prefixed wire protocol: [4-byte header len][JSON header][body]."""
from __future__ import annotations

import json
import struct
from typing import Dict, Tuple

MAX_HEADER = 64 * 1024          # DoS limit on JSON header size
MAX_BODY = 4 * 1024 * 1024      # DoS limit on a single chunk body


class ProtocolError(Exception):
    """Malformed or oversized message."""


def recv_exact(sock, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        part = sock.recv(min(65536, n - len(buf)))
        if not part:
            raise ConnectionError("connection closed")
        buf += part
    return bytes(buf)


def send_msg(sock, header: Dict, body: bytes = b"") -> None:
    header = dict(header, body_len=len(body))
    raw = json.dumps(header).encode()
    sock.sendall(struct.pack(">I", len(raw)) + raw + body)


def recv_msg(sock) -> Tuple[Dict, bytes]:
    (hlen,) = struct.unpack(">I", recv_exact(sock, 4))
    if hlen == 0 or hlen > MAX_HEADER:
        raise ProtocolError("invalid header size")
    try:
        header = json.loads(recv_exact(sock, hlen))
    except ValueError as exc:
        raise ProtocolError("invalid header") from exc
    if not isinstance(header, dict):
        raise ProtocolError("invalid header")
    blen = header.get("body_len", 0)
    if not isinstance(blen, int) or blen < 0 or blen > MAX_BODY:
        raise ProtocolError("invalid body size")
    return header, (recv_exact(sock, blen) if blen else b"")
