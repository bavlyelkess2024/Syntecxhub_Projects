import socket
import threading

import pytest

from cve_scanner import nvd
from cve_scanner.banner import detect_service, grab_banner, scan_ports
from cve_scanner.cli import parse_ports
from cve_scanner.report import to_json, to_markdown


@pytest.mark.parametrize("banner,expected", [
    ("SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5", ("OpenSSH", "8.2")),
    ("220 (vsFTPd 2.3.4)", ("vsFTPd", "2.3.4")),
    ("220 ProFTPD 1.3.5 Server ready", ("ProFTPD", "1.3.5")),
    ("HTTP/1.1 200 OK\r\nServer: Apache/2.4.49 (Unix)\r\n", ("Apache", "2.4.49")),
    ("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n", None),
    ("", None),
    (None, None),
])
def test_detect_service(banner, expected):
    assert detect_service(banner) == expected


def test_parse_ports():
    assert parse_ports("80, 22,8000-8002") == [22, 80, 8000, 8001, 8002]
    with pytest.raises(ValueError):
        parse_ports("70000")


def _banner_server(banner: bytes):
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)

    def serve():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            conn.sendall(banner)
            conn.close()

    threading.Thread(target=serve, daemon=True).start()
    return srv, srv.getsockname()[1]


def test_grab_banner_and_scan():
    srv, port = _banner_server(b"220 (vsFTPd 2.3.4)\r\n")
    try:
        assert "vsFTPd" in grab_banner("127.0.0.1", port)
        services = scan_ports("127.0.0.1", [port])
        assert services[0].product == "vsFTPd" and services[0].version == "2.3.4"
    finally:
        srv.close()


def test_closed_port_returns_none():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    assert grab_banner("127.0.0.1", port, timeout=1) is None


def test_offline_lookup():
    hits = nvd.lookup_offline("vsFTPd", "2.3.4")
    assert hits and hits[0]["id"] == "CVE-2011-2523"
    assert nvd.lookup_offline("vsftpd", "9.9") == []


def test_nvd_parsing_and_filtering(monkeypatch):
    fake = {"vulnerabilities": [
        {"cve": {"id": "CVE-1", "descriptions": [{"lang": "en", "value": "Apache httpd bug"}],
                 "metrics": {"cvssMetricV31": [{"baseSeverity": "HIGH",
                                                "cvssData": {"baseScore": 7.5}}]}}},
        {"cve": {"id": "CVE-2", "descriptions": [{"lang": "en", "value": "Unrelated product"}],
                 "metrics": {}}},
    ]}

    class Resp:
        def raise_for_status(self): pass
        def json(self): return fake

    monkeypatch.setattr(nvd.requests, "get", lambda *a, **k: Resp())
    out = nvd.lookup_nvd("Apache", "2.4.49")
    assert [c["id"] for c in out] == ["CVE-1"]
    assert out[0]["severity"] == "HIGH" and out[0]["score"] == 7.5


def test_reports():
    findings = [{"port": 21, "product": "vsFTPd", "version": "2.3.4", "banner": "x",
                 "cves": nvd.lookup_offline("vsftpd", "2.3.4")}]
    md = to_markdown("10.0.0.1", findings)
    assert "CVE-2011-2523" in md and "responsible disclosure" in md.lower()
    assert '"CVE-2011-2523"' in to_json("10.0.0.1", findings)
