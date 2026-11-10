"""CVE lookups: NVD API 2.0 (online) and a bundled signature DB (offline)."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Optional

import requests

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
_SIGNATURES = Path(__file__).parent / "data" / "signatures.json"


def _sort(cves: List[Dict]) -> List[Dict]:
    return sorted(cves, key=lambda c: (SEVERITY_ORDER.get(c["severity"], 4),
                                       -(c["score"] or 0)))


def lookup_offline(product: str, version: str) -> List[Dict]:
    """Match against the bundled signature database (exact product+version)."""
    sigs = json.loads(_SIGNATURES.read_text(encoding="utf-8"))
    return _sort([
        {"id": s["cve"], "score": s["score"], "severity": s["severity"],
         "description": s["description"], "source": "signature"}
        for s in sigs
        if s["product"].lower() == product.lower() and s["version"] == version
    ])


def lookup_nvd(product: str, version: str, api_key: Optional[str] = None,
               limit: int = 10, timeout: int = 20) -> List[Dict]:
    """Query NVD for CVEs mentioning `product` and `version`.

    NVD keyword search is fuzzy, so results are filtered to descriptions that
    mention the product name. Treat them as *candidates*, not confirmed vulns.
    """
    headers = {"apiKey": api_key} if api_key else {}
    params = {"keywordSearch": f"{product} {version}", "resultsPerPage": limit}
    resp = requests.get(NVD_URL, params=params, headers=headers, timeout=timeout)
    resp.raise_for_status()

    results = []
    for item in resp.json().get("vulnerabilities", []):
        cve = item["cve"]
        desc = next((d["value"] for d in cve.get("descriptions", [])
                     if d.get("lang") == "en"), "")
        if product.lower() not in desc.lower():
            continue
        score, severity = None, "UNKNOWN"
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metrics = cve.get("metrics", {}).get(key)
            if metrics:
                data = metrics[0]["cvssData"]
                score = data.get("baseScore")
                severity = (metrics[0].get("baseSeverity")
                            or data.get("baseSeverity", "UNKNOWN")).upper()
                break
        results.append({"id": cve["id"], "score": score, "severity": severity,
                        "description": desc[:250], "source": "nvd"})
    return _sort(results)
