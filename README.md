# passbolt-audit

> Audit Passbolt CE passwords for weak, reused, and compromised credentials.

[![Python](https://img.shields.io/pypi/pyversions/passbolt-audit.svg)](https://pypi.org/project/passbolt-audit/)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)

## Install

```bash
pip install passbolt-audit
```

## Requirements

- Python 3.11+
- [go-passbolt-cli](https://github.com/passbolt/go-passbolt-cli) installed
- `zxcvbn` package (installed automatically)

## Setup

Before running the audit, you must configure `go-passbolt-cli` manually:

```bash
# Configure with your Passbolt server, password, and GPG key file
passbolt --serverAddress https://your-passbolt-server.com \
         --userPassword "your-password" \
         --userPrivateKeyFile /path/to/your/private-key.asc \
         configure
```

**Note:** 
- The GPG key must not have a passphrase (go-passbolt-cli doesn't support passphrase-protected keys)
- You can check your key with: `gpg --list-packets your-key.asc`
- If you see "S2K" or "protection", the key is protected
- If you get TLS certificate errors, add `tlsskipverify = true` to `~/.config/go-passbolt-cli/go-passbolt-cli.toml`

## Usage

```bash
passbolt-audit --server https://your-passbolt-server.com --output report.csv
```

### Options

- `--server, -s`: Passbolt server URL (required)
- `--configure, -c`: Show configuration instructions
- `--output, -o`: CSV output file (default: `passbolt_audit_YYYYMMDD_HHMMSS.csv`)
- `--weak-only`: Include only weak passwords in CSV
- `--reused-only`: Include only reused passwords in CSV
- `--skip-hibp`: Skip Have I Been Pwned check
- `--limite, -n`: Limit to N resources for testing (0 = all)
- `--key, -k`: Custom GPG private key file path

## Features

- **Password strength analysis** using zxcvbn
- **Reused password detection** using SHA-256 comparison
- **HIBP breach check** using k-anonymity (only sends first 5 chars of SHA-1)
- **CSV export** with filtering options
- **Terminal summary** with color output

## Development

```bash
git clone https://github.com/<user>/passbolt-audit.git
cd passbolt-audit
pip install -e ".[test]"

# run tests
pytest

# format
ruff format src/ tests/

# lint
ruff check src/ tests/

# type check
mypy src/
```