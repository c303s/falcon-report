# Falcon Report

This repository contains a Python report generator for CrowdStrike Falcon.

Current version: `0.01a`

Build date: `08.06.2026`

Disclaimer: This is an independent community project and is not an official CrowdStrike tool.

The main script is `falcon_report.py`.

It uses only the Python standard library (no SDK and no third-party Python package dependencies).

## Files

- `README.md`: General details
- `api_scopes.txt`: Require API client scopes
- `falcon_report.py`: main file
- `install.sh`: help you to get started

## Requirements

- Python 3.10 or newer
- A CrowdStrike Falcon API client with the required scopes listed below

## Required API Scopes

Minimum required:

- `alerts.read`
- `cases.read`

The same list is stored in `api_scopes.txt`.

## Install And Run

One command to download, set up, and run:

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/c303s/falcon-report/main/install.sh)"
```

The installer:

- verifies Python 3.10+
- resolves the latest commit SHA on `main` via GitHub API
- downloads a SHA-pinned copy of `falcon_report.py`
- launches it

Manual alternative:

```bash
curl -fsSL https://raw.githubusercontent.com/c303s/falcon-report/main/falcon_report.py -o falcon_report.py
python3 falcon_report.py
```

Windows (PowerShell) alternative:

```powershell
powershell -ExecutionPolicy Bypass -Command "iwr -useb https://raw.githubusercontent.com/c303s/falcon-report/main/falcon_report.py -OutFile falcon_report.py; python falcon_report.py"
```

## First Run Behavior

On first run, the script prompts for Falcon API credentials and optional Falcon Query Language filters, then stores them in `.env` in the current working directory.

If `.env` already exists, the script uses it and asks whether you want to update the saved values.

## Re-run Setup

```bash
python3 falcon_report.py --setup
```
