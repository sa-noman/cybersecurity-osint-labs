# Cybersecurity & OSINT Labs

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)
![Security](https://img.shields.io/badge/Focus-Defensive%20Security-111827)
![OSINT](https://img.shields.io/badge/OSINT-Verification-0F766E)

A practical collection of beginner-friendly defensive cybersecurity and OSINT labs focused on safe analysis, public metadata, source verification, and authorized systems.

## Labs

| # | Lab | Focus |
|---|---|---|
| 01 | Linux Security Basics | Permissions and local security checks |
| 02 | Network Enumeration Analysis | Offline analysis of saved Nmap-style XML |
| 03 | HTTP Header Analysis | Common browser-facing security headers |
| 04 | Log Analysis | Repeated failed-login patterns |
| 05 | OSINT Source Verification | Structured source and claim checks |
| 06 | Domain & DNS OSINT | Public DNS records |
| 07 | File Metadata Analysis | File metadata, timestamps, MIME type, and SHA-256 |

## Safety Scope

Use these labs only with your own systems, sample data, public metadata, or systems you are explicitly authorized to inspect.

## Quick Start

```bash
git clone https://github.com/sa-noman/cybersecurity-osint-labs.git
cd cybersecurity-osint-labs
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
```

On Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
```

## Example Commands

```bash
python 03-http-header-analysis/app.py https://example.com
python 04-log-analysis/app.py sample-data/auth.log
python 05-osint-source-verification/app.py sample-data/source_record.json
python 06-domain-dns-osint/app.py example.com
python 07-file-metadata-analysis/app.py sample-data/sample.txt
```

## Disclaimer

These are learning and defensive-analysis projects. Automated findings should be verified before important decisions.
