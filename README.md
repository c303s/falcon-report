# Falcon Report

This repository contains a Python report generator for CrowdStrike Falcon.

The main script is `falcon_overview.py`.

It uses only the Python standard library (no SDK and no third-party Python package dependencies).

## Requirements

- Python 3.10 or newer
- A CrowdStrike Falcon API client with the required scopes listed below

## Required API Scopes

Minimum required:

- `alerts.read`
- `cases.read`

Optional (enables direct API-backed paths where available):

- `incidents.read`
- `falcon_complete_dashboard`

The same list is stored in `api_scopes.txt`.

## Install And Run

One command to download, set up, and run:

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/c303s/falcon-report/main/install.sh)"
```

The installer:

- verifies Python 3.10+
- resolves the latest commit SHA on `main` via GitHub API
- downloads a SHA-pinned copy of `falcon_overview.py`
- launches it

Manual alternative:

```bash
curl -fsSL https://raw.githubusercontent.com/c303s/falcon-report/main/falcon_overview.py -o falcon_overview.py
python3 falcon_overview.py
```

## First Run Behavior

On first run, the script prompts for Falcon API credentials and optional Falcon Query Language filters, then stores them in `.env` in the current working directory.

If `.env` already exists, the script uses it and asks whether you want to update the saved values.

## Re-run Setup

```bash
python3 falcon_overview.py --setup
```

## Notes

- `CrowdScore` uses the Falcon Incidents API endpoint when available.
- If incidents access is unavailable, the script falls back to an estimated score based on available activity signals.
- OverWatch and some NG-SIEM paths are tenant/scope dependent; optional filters can be stored in `.env`.