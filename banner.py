"""Port probing, banner grabbing and service/version detection."""
from __future__ import annotations

import re
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Iterable, List, Optional, Tuple

HTTP_PORTS = {80, 8000, 8008, 8080, 8888}
TLS_HTTP_PORTS = {443, 8443}

_SSH_RE = re.compile(r"SSH-\d(?:\.\d+)?-([A-Za-z]+)[_\- ]?(\d+(?:\.\d+)+)")
_GENERIC_RE = re.compile(r"([A-Za-z][A-Za-z\-]+)[/_ \-](\d+(?:\.\d+)+)")
_IGNORED_NAMES = {"ssh", "http", "https", "ftp", "smtp", "esmtp", "imap", "pop"}


@dataclass
class Service:
    port: int
    banner: str
    product: Optional[str] = None
    version: Optional[str] = None


def grab_banner(host: str, port: int, timeout: float = 3.0) -> Optional[str]:
    """Return the banner of host:port, or None if the port is closed."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError:
        return None
    try:
        sock.settimeout(timeout)
        if port in TLS_HTTP_PORTS:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False  # scanning: we only read the banner
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        if port in HTTP_PORTS or port in TLS_HTTP_PORTS:
            sock.sendall(f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
        try:
            return sock.recv(2048).decode(errors="ignore").strip()
        except (socket.timeout, ssl.SSLError, OSError):
            return ""
    except (ssl.SSLError, OSError):
        return ""
    finally:
        sock.close()


def detect_service(banner: Optional[str]) -> Optional[Tuple[str, str]]:
    """Extract (product, version) from a banner, or None."""
    if not banner:
        return None
    m = _SSH_RE.search(banner)
    if m:
        return m.group(1), m.group(2)
    server = re.search(r"^Server:\s*(.+)$", banner, re.I | re.M)
    if banner.upper().startswith("HTTP/"):
        if not server:
            return None
        text = server.group(1)
    else:
        text = banner.splitlines()[0]
    for m in _GENERIC_RE.finditer(text):
        if m.group(1).lower() not in _IGNORED_NAMES:
            return m.group(1), m.group(2)
    return None


def scan_ports(host: str, ports: Iterable[int], timeout: float = 3.0,
               workers: int = 20) -> List[Service]:
    """Probe ports concurrently and return the open ones, sorted by port."""
    ports = list(ports)

    def probe(port: int) -> Optional[Service]:
        banner = grab_banner(host, port, timeout)
        if banner is None:
            return None
        svc = detect_service(banner)
        return Service(port, banner, *(svc or (None, None)))

    with ThreadPoolExecutor(max_workers=workers) as pool:
        return sorted((s for s in pool.map(probe, ports) if s), key=lambda s: s.port)
