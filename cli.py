"""Command-line interface."""
from __future__ import annotations

import argparse
import sys
import time
from typing import List, Optional

from . import __version__
from .banner import scan_ports
from .nvd import lookup_nvd, lookup_offline
from .report import to_json, to_markdown

DEFAULT_PORTS = "21,22,23,25,80,110,143,443,3306,5432,8080,8443"


def parse_ports(spec: str) -> List[int]:
    """Parse '22,80,8000-8010' into a sorted list of ports."""
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = (int(x) for x in part.split("-", 1))
            ports.update(range(lo, hi + 1))
        else:
            ports.add(int(part))
    if not ports or min(ports) < 1 or max(ports) > 65535:
        raise ValueError("ports must be between 1 and 65535")
    return sorted(ports)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cve-scanner",
        description="Lightweight scanner: banner grabbing + CVE matching. "
                    "Only scan systems you are authorized to test.")
    p.add_argument("host", help="target hostname or IP")
    p.add_argument("-p", "--ports", default=DEFAULT_PORTS,
                   help=f"ports, e.g. 22,80,8000-8010 (default: {DEFAULT_PORTS})")
    p.add_argument("-o", "--out", default="report.md", help="report path")
    p.add_argument("--format", choices=["md", "json"], default="md")
    p.add_argument("--offline", action="store_true",
                   help="use only the bundled signature DB (no network lookups)")
    p.add_argument("--api-key", help="NVD API key (higher rate limit)")
    p.add_argument("--timeout", type=float, default=3.0, help="socket timeout (s)")
    p.add_argument("--version", action="version", version=__version__)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        ports = parse_ports(args.ports)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    print("[!] Only scan systems you own or are explicitly authorized to test.")
    services = scan_ports(args.host, ports, timeout=args.timeout)
    if not services:
        print("[-] No open ports found.")

    findings = []
    for svc in services:
        label = f"{svc.product} {svc.version}" if svc.product else "unknown service"
        print(f"[+] {svc.port}/tcp open  {label}")
        cves: list = []
        if svc.product and svc.version:
            cves = lookup_offline(svc.product, svc.version)
            if not args.offline:
                try:
                    cves += lookup_nvd(svc.product, svc.version, args.api_key)
                except Exception as exc:  # network/API errors must not abort the scan
                    print(f"    [!] NVD lookup failed: {exc}", file=sys.stderr)
                time.sleep(1 if args.api_key else 6)  # NVD rate limits
        seen, unique = set(), []
        for c in cves:
            if c["id"] not in seen:
                seen.add(c["id"])
                unique.append(c)
        findings.append({"port": svc.port, "product": svc.product,
                         "version": svc.version, "banner": svc.banner[:200],
                         "cves": unique})

    render = to_json if args.format == "json" else to_markdown
    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write(render(args.host, findings))
    print(f"[✓] Report saved to {args.out}")
    return 0
