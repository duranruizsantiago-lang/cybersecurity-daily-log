<p align="center">
  <h1 align="center">🛡️ Cybersecurity Daily Log</h1>
  <p align="center">
    <strong>Automated daily cybersecurity journal — CVE tracking, threat intelligence, and security research</strong>
  </p>
  <p align="center">
    <img src="https://img.shields.io/badge/Python-3.14+-3776AB?style=flat-square&logo=python&logoColor=white" />
    <img src="https://img.shields.io/badge/NVD-API-00ADD8?style=flat-square" />
    <img src="https://img.shields.io/badge/Updated-Daily-brightgreen?style=flat-square" />
    <img src="https://img.shields.io/badge/License-MIT-blue.svg" />
  </p>
</p>

---

## About

This repository serves as a living cybersecurity journal — automatically updated every day with real vulnerability data from the National Vulnerability Database (NVD), CISA Known Exploited Vulnerabilities (KEV) catalog, and curated threat intelligence.

Each entry captures the day's most critical CVEs, emerging threats, and actionable security insights. The goal is to build a continuous, verifiable record of cybersecurity awareness while maintaining an active contribution history.

## How It Works

A Python script runs daily via cron, fetching:

- **NVD CVE 2.0 API** — Latest published CVEs with CVSS scores and severity ratings
- **CISA KEV Catalog** — Vulnerabilities known to be actively exploited in the wild
- **EPSS scores** — Exploit Prediction Scoring System data for prioritization

The script generates a structured markdown journal entry under `journal/YYYY/MM/DD.md` and commits it automatically.

## Journal Structure

```
journal/
├── 2026/
│   ├── 07/
│   │   ├── 27.md
│   │   ├── 28.md
│   │   └── ...
```

Each entry contains:

- **Critical CVEs** (CVSS ≥ 9.0) published that day
- **High-severity CVEs** (CVSS 7.0–8.9)
- **CISA KEV additions** — vulnerabilities being actively exploited
- **Threat landscape summary** — attack vectors, affected vendors, trends
- **Security tip of the day** — actionable defensive guidance

## Technologies Demonstrated

- **Automation & DevOps** — Cron-based scheduled execution, git automation
- **API Integration** — NVD REST API, CISA KEV catalog, EPSS data
- **Data Curation** — Automated aggregation and formatting of threat intelligence
- **Python Engineering** — API client design, error handling, markdown generation
- **GitHub Actions / Cron** — Scheduled workflows with verified commits

---

## About the Author

**Santiago Durán Ruiz** — Cybersecurity Engineer focused on threat intelligence, ML security, and cloud defense.

- GitHub: [duranruizsantiago-lang](https://github.com/duranruizsantiago-lang)
- Portfolio: [Monitor the Situation Dashboard](https://github.com/duranruizsantiago-lang/monitor-the-situation-dashboard) | [Honeypot Network](https://github.com/duranruizsantiago-lang/honeypot-network) | [AI Threat Detection](https://github.com/duranruizsantiago-lang/ai-threat-detection)

## License

MIT
