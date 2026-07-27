#!/usr/bin/env python3
"""
Cybersecurity Daily Log Generator
Fetches real CVE data from NVD and CISA KEV, generates a structured daily journal entry.
Designed to run unattended via cron. Verified commits appear on GitHub contribution graph.
"""

import json
import os
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

# --- Configuration ---
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API_URL = "https://api.first.org/data/v1/epss"
USER_AGENT = "cybersecurity-daily-log/1.0 (duranruizsantiago-lang)"
REPO_DIR = Path(__file__).parent.resolve()
REQUEST_TIMEOUT = 30


def fetch_json(url: str, timeout: int = REQUEST_TIMEOUT) -> dict | None:
    """Fetch JSON from a URL with error handling."""
    try:
        import ssl
        ctx = ssl.create_default_context()
        req = Request(url, headers={"User-Agent": USER_AGENT})
        with urlopen(req, timeout=timeout, context=ctx) as resp:
            return json.loads(resp.read().decode())
    except Exception:
        # Fallback: some environments have SSL cert issues
        try:
            import ssl
            ctx = ssl._create_unverified_context()
            req = Request(url, headers={"User-Agent": USER_AGENT})
            with urlopen(req, timeout=timeout, context=ctx) as resp:
                return json.loads(resp.read().decode())
        except (URLError, HTTPError, json.JSONDecodeError, Exception) as e:
            print(f"  [!] Failed to fetch {url}: {e}", file=sys.stderr)
            return None


def fetch_cves_published_today() -> list[dict]:
    """Fetch CVEs published today from the NVD API."""
    today = datetime.now(timezone.utc)
    start = today.replace(hour=0, minute=0, second=0, microsecond=0)
    end = today.replace(hour=23, minute=59, second=59, microsecond=999999)

    start_str = start.strftime("%Y-%m-%dT%H:%M:%S.000")
    end_str = end.strftime("%Y-%m-%dT%H:%M:%S.000")

    # Use lastModStartDate to catch CVEs modified today (more results than pubStartDate alone)
    url = (
        f"{NVD_API_URL}?"
        f"lastModStartDate={start_str}&lastModEndDate={end_str}"
        f"&resultsPerPage=50&noRejected"
    )

    print(f"  Fetching: NVD CVEs modified today...")
    data = fetch_json(url)
    if not data:
        return []

    cves = data.get("vulnerabilities", [])
    results = []
    for item in cves:
        cve = item.get("cve", {})
        metrics = cve.get("metrics", {}).get("cvssMetricV31", [])
        cvss_data = metrics[0].get("cvssData", {}) if metrics else {}
        score = cvss_data.get("baseScore", 0)
        severity = cvss_data.get("baseSeverity", "UNKNOWN")

        results.append({
            "id": cve.get("id", "UNKNOWN"),
            "description": (
                cve.get("descriptions", [{}])[0].get("value", "No description")[:300]
            ),
            "cvss_score": score,
            "severity": severity,
            "published": cve.get("published", ""),
        })

    results.sort(key=lambda x: x["cvss_score"], reverse=True)
    print(f"  Found {len(results)} CVEs")
    return results


def fetch_cisa_kev() -> list[dict]:
    """Fetch CISA Known Exploited Vulnerabilities catalog for recent additions."""
    print(f"  Fetching: CISA KEV catalog...")
    data = fetch_json(CISA_KEV_URL)
    if not data:
        return []

    # Filter for recently added (last 2 days to catch updates)
    cutoff = datetime.now(timezone.utc) - timedelta(days=2)
    recent = []
    for vuln in data.get("vulnerabilities", []):
        try:
            added_date = datetime.strptime(
                vuln.get("dateAdded", ""), "%Y-%m-%d"
            ).replace(tzinfo=timezone.utc)
            if added_date >= cutoff:
                recent.append({
                    "cve": vuln.get("cveID", ""),
                    "vendor": vuln.get("vendorProject", ""),
                    "product": vuln.get("product", ""),
                    "vuln_name": vuln.get("vulnerabilityName", ""),
                    "date_added": vuln.get("dateAdded", ""),
                    "due_date": vuln.get("dueDate", ""),
                    "required_action": vuln.get("requiredAction", ""),
                    "ransomware": vuln.get("knownRansomwareCampaignUse", ""),
                })
        except ValueError:
            continue

    print(f"  Found {len(recent)} recent KEV additions")
    return recent


def generate_markdown(cves: list[dict], kev: list[dict]) -> str:
    """Generate the daily journal markdown entry."""
    today = datetime.now(timezone.utc)
    date_str = today.strftime("%Y-%m-%d")
    date_display = today.strftime("%A, %B %d, %Y")

    critical = [c for c in cves if c["cvss_score"] >= 9.0]
    high = [c for c in cves if 7.0 <= c["cvss_score"] < 9.0]
    medium = [c for c in cves if 4.0 <= c["cvss_score"] < 7.0]
    low = [c for c in cves if c["cvss_score"] > 0 and c["cvss_score"] < 4.0]

    lines = []
    lines.append(f"# {date_display}")
    lines.append("")
    lines.append(f"> Automated daily cybersecurity journal — {date_str}")
    lines.append("")

    # --- Summary ---
    lines.append("## 📊 Daily Summary")
    lines.append("")
    lines.append(f"| Metric | Count |")
    lines.append(f"|--------|-------|")
    lines.append(f"| CVEs published/modified today | {len(cves)} |")
    lines.append(f"| Critical (CVSS ≥ 9.0) | {len(critical)} |")
    lines.append(f"| High (CVSS 7.0–8.9) | {len(high)} |")
    lines.append(f"| Medium (CVSS 4.0–6.9) | {len(medium)} |")
    lines.append(f"| CISA KEV additions | {len(kev)} |")
    lines.append("")

    # --- Critical CVEs ---
    if critical:
        lines.append("## 🔴 Critical Vulnerabilities (CVSS ≥ 9.0)")
        lines.append("")
        for cve in critical:
            lines.append(f"### {cve['id']} — CVSS {cve['cvss_score']}")
            lines.append("")
            desc = cve["description"].replace("\n", " ")
            lines.append(f"{desc}")
            lines.append("")
            lines.append(f"- **Severity:** {cve['severity']}")
            lines.append(f"- **Published:** {cve['published']}")
            lines.append("")
    else:
        lines.append("## 🔴 Critical Vulnerabilities")
        lines.append("")
        lines.append("No critical CVEs published today.")
        lines.append("")

    # --- High CVEs ---
    if high:
        lines.append("## 🟠 High-Severity Vulnerabilities (CVSS 7.0–8.9)")
        lines.append("")
        for cve in high[:10]:
            desc = cve["description"].replace("\n", " ")[:200]
            lines.append(f"- **{cve['id']}** (CVSS {cve['cvss_score']}): {desc}")
        lines.append("")
    else:
        lines.append("## 🟠 High-Severity Vulnerabilities")
        lines.append("")
        lines.append("No high-severity CVEs published today.")
        lines.append("")

    # --- CISA KEV ---
    if kev:
        lines.append("## ⚠️ CISA KEV — Actively Exploited")
        lines.append("")
        lines.append("Vulnerabilities recently added to CISA's Known Exploited Vulnerabilities catalog:")
        lines.append("")
        for k in kev:
            ransomware = " 🔒 Ransomware" if k["ransomware"].lower() == "known" else ""
            lines.append(f"### {k['cve']} — {k['vendor']} {k['product']}{ransomware}")
            lines.append("")
            lines.append(f"- **Vulnerability:** {k['vuln_name']}")
            lines.append(f"- **Date Added:** {k['date_added']}")
            lines.append(f"- **Due Date:** {k['due_date']}")
            lines.append(f"- **Required Action:** {k['required_action']}")
            lines.append("")
    else:
        lines.append("## ⚠️ CISA KEV — Actively Exploited")
        lines.append("")
        lines.append("No new KEV additions in the last 2 days.")
        lines.append("")

    # --- Threat Landscape ---
    lines.append("## 🌐 Threat Landscape")
    lines.append("")
    if cves:
        vendors = {}
        for cve in cves:
            desc = cve["description"]
            for vendor in ["Microsoft", "Google", "Apple", "Adobe", "Apache", "Linux",
                          "Cisco", "VMware", "Oracle", "Fortinet", "Palo Alto",
                          "Citrix", "Atlassian", "WordPress", "Kubernetes", "Docker"]:
                if vendor.lower() in desc.lower():
                    vendors[vendor] = vendors.get(vendor, 0) + 1

        if vendors:
            lines.append("**Most affected vendors today:**")
            for vendor, count in sorted(vendors.items(), key=lambda x: x[1], reverse=True)[:5]:
                lines.append(f"- {vendor}: {count} CVE(s)")
            lines.append("")

        avg_score = sum(c["cvss_score"] for c in cves) / len(cves) if cves else 0
        lines.append(f"**Average CVSS score today:** {avg_score:.1f}")
        lines.append("")
    else:
        lines.append("No new CVE data available for today.")
        lines.append("")

    # --- Security Tip ---
    tips = [
        "Keep all software and dependencies updated. Patch management is your first line of defense against known vulnerabilities.",
        "Implement network segmentation to limit lateral movement in case of a breach. Critical systems should never share the same network segment as user workstations.",
        "Enable Multi-Factor Authentication (MFA) on all externally accessible services. MFA blocks 99.9% of automated credential attacks.",
        "Review your CISA KEV catalog weekly. If any of your software appears there, patch immediately — these are being actively exploited.",
        "Monitor your attack surface continuously. New vulnerabilities are discovered daily; what was secure yesterday may not be today.",
        "Implement the principle of least privilege. Users and services should only have the minimum permissions needed to function.",
        "Use honeypots and deception technology to detect attackers early in the kill chain, before they reach production systems.",
        "Regularly audit your CI/CD pipelines for exposed secrets, dependency vulnerabilities, and misconfigurations.",
        "Encrypt data at rest and in transit. Assume your perimeter will be breached and protect the data itself.",
        "Maintain an incident response plan and test it regularly. The worst time to write your IR plan is during an incident.",
    ]
    tip_idx = today.day % len(tips)
    lines.append("## 💡 Security Tip of the Day")
    lines.append("")
    lines.append(f"> {tips[tip_idx]}")
    lines.append("")

    # --- Footer ---
    lines.append("---")
    lines.append("")
    lines.append(
        f"*This journal is automatically generated daily using data from the "
        f"[NVD API](https://nvd.nist.gov/developers/vulnerabilities) and "
        f"[CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog). "
        f"Part of the [Cybersecurity Daily Log](https://github.com/duranruizsantiago-lang/cybersecurity-daily-log) project.*"
    )
    lines.append("")

    return "\n".join(lines)


def write_journal(content: str) -> Path:
    """Write the journal entry to the appropriate path."""
    today = datetime.now(timezone.utc)
    year = today.strftime("%Y")
    month = today.strftime("%m")
    day = today.strftime("%d")

    journal_dir = REPO_DIR / "journal" / year / month
    journal_dir.mkdir(parents=True, exist_ok=True)

    filepath = journal_dir / f"{day}.md"
    filepath.write_text(content, encoding="utf-8")
    print(f"  Written: {filepath}")
    return filepath


def git_commit_and_push(filepath: Path):
    """Stage, commit, and push the journal entry."""
    import subprocess

    def run(cmd: list[str]) -> bool:
        result = subprocess.run(cmd, cwd=REPO_DIR, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"  [!] git {' '.join(cmd)} failed: {result.stderr.strip()}", file=sys.stderr)
            return False
        return True

    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    # Stage
    if not run(["git", "add", str(filepath.relative_to(REPO_DIR))]):
        return

    # Commit
    if not run(["git", "commit", "-m", f"docs: daily cybersecurity journal — {today}"]):
        # Check if nothing to commit (already committed today)
        return

    # Push
    if not run(["git", "push", "origin", "main"]):
        return

    print(f"  ✓ Committed and pushed: {today}")


def main():
    print(f"\n{'='*60}")
    print(f"Cybersecurity Daily Log Generator")
    print(f"Run: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(f"{'='*60}\n")

    # 1. Fetch data
    cves = fetch_cves_published_today()
    kev = fetch_cisa_kev()

    # 2. Generate markdown
    print(f"\n  Generating journal entry...")
    markdown = generate_markdown(cves, kev)

    # 3. Write to file
    filepath = write_journal(markdown)

    # 4. Commit and push
    print(f"\n  Pushing to GitHub...")
    git_commit_and_push(filepath)

    print(f"\n{'='*60}")
    print(f"✓ Daily log complete")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
