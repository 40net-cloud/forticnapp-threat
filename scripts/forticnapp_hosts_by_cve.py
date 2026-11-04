#!/usr/bin/env python3
"""
List hosts affected by one or more CVEs using the Lacework / FortiCNAPP v2 API.

Usage:
    export LW_ACCOUNT="youraccount"          # the part before .lacework.net
    export LW_API_KEY="YOUR_KEY_ID"
    export LW_API_SECRET="YOUR_SECRET"
    uv run forticnapp_hosts_by_cve.py CVE-2024-3094 CVE-2021-44228 --days 1 --csv out.csv

Dependencies are managed by uv (see pyproject.toml and README.md).
"""
import argparse
import csv
import os
import sys
from datetime import datetime, timedelta, timezone

import requests

ACCOUNT = os.environ.get("LW_ACCOUNT")
API_KEY = os.environ.get("LW_API_KEY")
API_SECRET = os.environ.get("LW_API_SECRET")


def get_token(base_url: str) -> str:
    """Exchange key ID + secret for a short-lived bearer token."""
    resp = requests.post(
        f"{base_url}/api/v2/access/tokens",
        headers={"X-LW-UAKS": API_SECRET, "Content-Type": "application/json"},
        json={"keyId": API_KEY, "expiryTime": 3600},
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()["token"]


def search_hosts(base_url: str, token: str, cves: list[str], days: int) -> list[dict]:
    """Return all host-vulnerability records matching the given CVEs."""
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    now = datetime.now(timezone.utc)
    start = now - timedelta(days=days)

    # Single CVE -> eq; multiple -> in
    if len(cves) == 1:
        vuln_filter = {"field": "vulnId", "expression": "eq", "value": cves[0]}
    else:
        vuln_filter = {"field": "vulnId", "expression": "in", "values": cves}

    body = {
        "timeFilter": {
            "startTime": start.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "endTime": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        },
        "filters": [vuln_filter],
    }

    results = []
    resp = requests.post(
        f"{base_url}/api/v2/Vulnerabilities/Hosts/search",
        headers=headers, json=body, timeout=60,
    )
    resp.raise_for_status()
    payload = resp.json()
    results.extend(payload.get("data", []))

    # Pagination: follow nextPage until it is empty
    while True:
        next_url = (payload.get("paging") or {}).get("urls", {}).get("nextPage")
        if not next_url:
            break
        resp = requests.get(next_url, headers=headers, timeout=60)
        resp.raise_for_status()
        payload = resp.json()
        results.extend(payload.get("data", []))

    return results


def summarize(records: list[dict]) -> list[dict]:
    """Flatten records to one row per (host, CVE, package), deduplicated."""
    seen, rows = set(), []
    for r in records:
        feature = r.get("featureKey", {}) or {}
        row = {
            "machine_id": r.get("mid"),
            "hostname": (r.get("evalCtx", {}) or {}).get("hostname"),
            "cve": r.get("vulnId"),
            "severity": r.get("severity"),
            "package": feature.get("name"),
            "version": feature.get("version_installed"),
            "status": r.get("status"),
            "fix_version": (r.get("fixInfo", {}) or {}).get("fixed_version"),
        }
        key = (row["machine_id"], row["cve"], row["package"], row["version"])
        if key not in seen:
            seen.add(key)
            rows.append(row)
    return rows


def main():
    parser = argparse.ArgumentParser(description="Find hosts affected by CVEs.")
    parser.add_argument("cves", nargs="+", help="One or more CVE IDs")
    parser.add_argument("--days", type=int, default=1, help="Look-back window in days")
    parser.add_argument("--csv", help="Optional path to write CSV output")
    args = parser.parse_args()

    if not all([ACCOUNT, API_KEY, API_SECRET]):
        sys.exit("Set LW_ACCOUNT, LW_API_KEY and LW_API_SECRET environment variables.")

    base_url = f"https://{ACCOUNT}.lacework.net"
    token = get_token(base_url)
    records = search_hosts(base_url, token, [c.upper() for c in args.cves], args.days)
    rows = summarize(records)

    print(f"{len(rows)} affected host/package rows "
          f"across {len({r['machine_id'] for r in rows})} hosts")
    for r in rows:
        print(f"{r['cve']:<16} {r['severity']:<9} {str(r['hostname']):<35} "
              f"{r['package']} {r['version']}")

    if args.csv and rows:
        with open(args.csv, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=rows[0].keys())
            writer.writeheader()
            writer.writerows(rows)
        print(f"Wrote {args.csv}")


if __name__ == "__main__":
    main()
