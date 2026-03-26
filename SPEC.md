# SPEC.md — passbolt-audit

## Purpose

A Python CLI tool for auditing Passbolt CE passwords to identify weak, reused, and compromised passwords. It uses zxcvbn for strength analysis and Have I Been Pwned (HIBP) API with k-anonymity to detect compromised passwords without exposing actual passwords.

## Scope

### In Scope
- Fetch resources from Passbolt CE via go-passbolt-cli
- Evaluate password strength using zxcvbn scoring (0-4)
- Detect reused passwords across resources (SHA-256 comparison)
- Check passwords against HIBP database using k-anonymity API
- Generate CSV reports with audit results
- CLI interface with filtering options
- Color terminal output with progress indicators

### Not in Scope
- Modifying Passbolt data
- GUI interface
- Database storage
- Email notifications
- Integration with other password managers

## Public API / Interface

### CLI Command

```
passbolt-audit [OPTIONS]
```

**Options:**
- `--output, -o PATH`: CSV output file (default: `passbolt_audit_YYYYMMDD_HHMMSS.csv`)
- `--solo-debiles`: Include only weak passwords in CSV
- `--solo-reutilizadas`: Include only reused passwords in CSV
- `--skip-hibp`: Skip HIBP check
- `--limite, -n INT`: Limit to N resources for testing (0 = all)

### Python API

**`passbolt_audit.cli.main() -> int`**
- Entry point for CLI execution
- Returns 0 on success, non-zero on error

**`passbolt_audit.core.get_all_resources() -> list[dict]`**
- Fetches all resources from Passbolt via passbolt CLI
- Returns list of resource dictionaries

**`passbolt_audit.core.get_secret(resource_id: str) -> str | None`**
- Fetches and decrypts secret for a given resource ID
- Returns password string or None on failure

**`passbolt_audit.core.evaluar_password(password: str, nombre: str, usuario: str) -> dict`**
- Evaluates password strength using zxcvbn
- Args: password, resource name, username
- Returns dict with: score, label, longitud, debil, razon, sugerencias, crack_time

**`passbolt_audit.core.consultar_hibp_bulk(resultados: list[dict], delay: float = 0.7) -> int`**
- Checks all unique passwords against HIBP API
- Uses k-anonymity (only sends first 5 chars of SHA-1)
- Deduplicates to minimize API calls
- Modifies resultados in-place, returns count of pwned passwords

**`passbolt_audit.core.detectar_reutilizadas(resultados: list[dict]) -> tuple[int, int]`**
- Detects reused passwords across resources
- Returns (total_reutilizadas, grupos_count)
- Modifies resultados in-place

**`passbolt_audit.core.generar_reporte_csv(resultados: list[dict], path: str) -> None`**
- Writes results to CSV file
- Includes all fields: id, nombre, usuario, uri, score, fortaleza, longitud, debil, razon, crack_time_offline, sugerencias, reutilizada, grupo_reutilizacion, veces_reutilizada, pwned, pwned_count

**`passbolt_audit.core.imprimir_resumen(resultados: list[dict], total_reutilizadas: int, grupos_reutilizacion: int, total_pwned: int = 0) -> None`**
- Prints terminal summary with statistics
- Shows distribution by score, top weak passwords, reused groups

### Configuration Constants

- `UMBRAL_DEBIL: int = 2` - Score threshold for weak passwords (0-4)
- `LONGITUD_MINIMA: int = 12` - Minimum password length

## Data Formats

### Input (from Passbolt CLI)
- JSON output from `passbolt list resource -j`
- JSON output from `passbolt get resource --id <id> -j`

### Output (CSV)
- UTF-8 encoded CSV with headers
- Fields: id, nombre, usuario, uri, score, fortaleza, longitud, debil, razon, crack_time_offline, sugerencias, reutilizada, grupo_reutilizacion, veces_reutilizada, pwned, pwned_count

### HIBP API
- GET to `https://api.pwnedpasswords.com/range/<prefix>`
- Returns lines: `<suffix>:<count>`
- Uses SHA-1 hashing with k-anonymity

## Edge Cases

1. **Empty or unreadable password** - Return score -1, label "Sin contraseña", mark as weak
2. **Passbolt CLI not installed** - Exit with error message pointing to installation
3. **Network timeout to HIBP** - Continue with pwned=None for affected passwords
4. **Invalid JSON from Passbolt** - Log error, skip resource, continue processing
5. **Rate limiting from HIBP** - Use 0.7s delay between requests
6. **TOTP-only resources** - Mark as error (no password to evaluate)
7. **Very long password (>200 chars)** - zxcvbn handles gracefully
8. **Unicode passwords** - Encode as UTF-8 before hashing/SHA-1
9. **No resources returned** - Exit with error message
10. **Duplicate resource IDs** - Process normally, deduplication is by password hash

## Performance & Constraints

- O(n) API calls to Passbolt (one per resource)
- O(unique_passwords) API calls to HIBP (deduplicated by SHA-1)
- Memory: stores all results in memory (acceptable for typical use)
- Network: requires internet for HIBP checks
- Dependencies: zxcvbn, go-passbolt-cli (external)
- Python version: >= 3.11