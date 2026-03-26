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
- [go-passbolt-cli](https://github.com/passbolt/go-passbolt-cli) installed and configured
- `zxcvbn` package (installed automatically)

## Usage

```bash
passbolt-audit --output reporte.csv
```

### Options

- `--output, -o`: CSV output file (default: `passbolt_audit_YYYYMMDD_HHMMSS.csv`)
- `--solo-debiles`: Include only weak passwords in CSV
- `--solo-reutilizadas`: Include only reused passwords in CSV
- `--skip-hibp`: Skip Have I Been Pwned check
- `--limite, -n`: Limit to N resources for testing (0 = all)

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