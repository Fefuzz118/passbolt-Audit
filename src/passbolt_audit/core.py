"""Core functionality for Passbolt audit tool."""

import csv
import hashlib
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections import defaultdict
from typing import Any, cast

UMBRAL_DEBIL = 2
LONGITUD_MINIMA = 12

SCORE_LABELS = {
    0: "Very weak",
    1: "Weak",
    2: "Acceptable",
    3: "Strong",
    4: "Very strong",
}

DEFAULT_KEYFILE = os.path.expanduser("~/.gnupg/passbolt_private.key")


def configure_passbolt(server_address: str, user_password: str, private_key_path: str) -> bool:
    """Show manual configuration instructions."""
    print("[*] To configure go-passbolt-cli, run:")
    print()
    print("    passbolt --serverAddress <URL> --userPassword <PASS> --userPrivateKeyFile <KEY> configure")
    print()
    print("    <URL>  = Your Passbolt server (e.g., https://passbolt.dc.in.antel.net.uy)")
    print("    <PASS> = Your Passbolt password")
    print("    <KEY>  = Path to your GPG private key file")
    print()
    print("    IMPORTANT: The GPG key must NOT have a passphrase.")
    print("               go-passbolt-cli does not support passphrase-protected keys.")
    print()
    print("    To check if your key has a passphrase:")
    print("        gpg --list-packets your-key.asc | grep -i s2k")
    print("    If you see 'S2K' or 'protection', the key is protected.")
    print()
    print("    To get an unprotected key, export it without passphrase from GPG.")
    return False


def run_cli(args: list[str]) -> str | None:
    """Execute go-passbolt-cli and return output as string."""
    try:
        result = subprocess.run(
            ["passbolt"] + args,
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode != 0:
            return None
        return result.stdout.strip()
    except FileNotFoundError:
        return None
    except subprocess.TimeoutExpired:
        return None


def get_all_resources() -> list[dict[str, Any]]:
    """Fetch all resources from Passbolt."""
    output = run_cli(["list", "resource", "-j"])
    if not output:
        return []
    try:
        resources = json.loads(output)
        return cast("list[dict[str, Any]]", resources)
    except json.JSONDecodeError:
        return []


def get_secret(resource_id: str) -> str | None:
    """Fetch and decrypt secret for a given resource."""
    output = run_cli(["get", "resource", "--id", resource_id, "-j"])
    if not output:
        return None
    try:
        data = json.loads(output)
        secret = (
            data.get("password") or data.get("secret") or data.get("Password") or ""
        )
        return secret if secret else None
    except (json.JSONDecodeError, KeyError):
        return None


def evaluate_password(password: str | None, nombre: str, usuario: str) -> dict[str, Any]:
    """Evaluate password strength using zxcvbn."""
    import zxcvbn  # type: ignore[import-untyped]

    if not password:
        return {
            "score": -1,
            "label": "No password",
            "longitud": 0,
            "debil": True,
            "razon": "Empty or not decryptable",
            "sugerencias": [],
            "crack_time": "",
        }

    resultado = zxcvbn.zxcvbn(password, user_inputs=[nombre, usuario])
    score = resultado["score"]
    longitud = len(password)
    feedback = resultado.get("feedback", {})
    warning = feedback.get("warning", "")
    suggestions = feedback.get("suggestions", [])

    debil = score <= UMBRAL_DEBIL or longitud < LONGITUD_MINIMA

    razones = []
    if score <= UMBRAL_DEBIL:
        razones.append(f"zxcvbn score: {score}/4")
    if longitud < LONGITUD_MINIMA:
        razones.append(f"Length: {longitud} chars (min. {LONGITUD_MINIMA})")
    if warning:
        razones.append(warning)

    return {
        "score": score,
        "label": SCORE_LABELS.get(score, "Unknown"),
        "longitud": longitud,
        "debil": debil,
        "razon": " | ".join(razones) if razones else "",
        "sugerencias": suggestions,
        "crack_time": resultado.get("crack_times_display", {}).get(
            "offline_slow_hashing_1e4_per_second", ""
        ),
    }


def consultar_hibp_bulk(resultados: list[dict[str, Any]], delay: float = 0.7) -> int:
    """Check unique passwords against HIBP API using k-anonymity."""
    hibp_url = "https://api.pwnedpasswords.com/range/"
    headers = {"User-Agent": "passbolt-audit-script"}

    sha1_map: dict[str, list[int]] = defaultdict(list)
    for i, r in enumerate(resultados):
        pwd = r.get("_password_raw")
        if pwd:
            sha1 = hashlib.sha1(pwd.encode("utf-8")).hexdigest().upper()
            sha1_map[sha1].append(i)

    prefijo_map: dict[str, list[str]] = defaultdict(list)
    for sha1 in sha1_map:
        prefijo_map[sha1[:5]].append(sha1)

    total_requests = len(prefijo_map)
    pwned_encontradas = 0

    for req_num, (prefijo, sha1_list) in enumerate(prefijo_map.items(), 1):
        try:
            req = urllib.request.Request(hibp_url + prefijo, headers=headers)
            with urllib.request.urlopen(req, timeout=10) as resp:
                body = resp.read().decode("utf-8")

            hibp_hashes: dict[str, int] = {}
            for linea in body.splitlines():
                partes = linea.strip().split(":")
                if len(partes) == 2:
                    sufijo, count = partes
                    hibp_hashes[prefijo + sufijo] = int(count)

            for sha1 in sha1_list:
                count = hibp_hashes.get(sha1, 0)
                for idx in sha1_map[sha1]:
                    resultados[idx]["pwned"] = count > 0
                    resultados[idx]["pwned_count"] = count
                    if count > 0:
                        pwned_encontradas += 1
                        if not resultados[idx]["debil"]:
                            resultados[idx]["debil"] = True
                        razon = resultados[idx].get("razon", "")
                        nueva_razon = f"Compromised ({count:,} times in HIBP)"
                        resultados[idx]["razon"] = (razon + " | " + nueva_razon).lstrip(
                            " | "
                        )

        except urllib.error.HTTPError:
            for sha1 in sha1_list:
                for idx in sha1_map[sha1]:
                    resultados[idx].setdefault("pwned", None)
                    resultados[idx].setdefault("pwned_count", None)
        except Exception:  # noqa: BLE001
            for sha1 in sha1_list:
                for idx in sha1_map[sha1]:
                    resultados[idx].setdefault("pwned", None)
                    resultados[idx].setdefault("pwned_count", None)

        if req_num < total_requests:
            time.sleep(delay)

    for r in resultados:
        r.setdefault("pwned", None)
        r.setdefault("pwned_count", None)

    return pwned_encontradas


def detect_reused_passwords(resultados: list[dict[str, Any]]) -> tuple[int, int]:
    """Detect reused passwords across resources using SHA-256."""
    hash_map: dict[str, list[int]] = defaultdict(list)

    for i, r in enumerate(resultados):
        pwd = r.get("_password_raw")
        if pwd:
            h = hashlib.sha256(pwd.encode("utf-8")).hexdigest()
            hash_map[h].append(i)

    group_num = 1
    for h, indices in hash_map.items():
        if len(indices) > 1:
            for idx in indices:
                resultados[idx]["reutilizada"] = True
                resultados[idx]["grupo_reutilizacion"] = group_num
                resultados[idx]["veces_reutilizada"] = len(indices)
                if not resultados[idx]["debil"]:
                    resultados[idx]["debil"] = True
                    razon = resultados[idx].get("razon", "")
                    resultados[idx]["razon"] = (razon + " | Reused").lstrip(" | ")
            group_num += 1

    for r in resultados:
        r.setdefault("reutilizada", False)
        r.setdefault("grupo_reutilizacion", "")
        r.setdefault("veces_reutilizada", 1)

    total_reutilizadas = sum(1 for r in resultados if r["reutilizada"])
    grupos = group_num - 1
    return total_reutilizadas, grupos


def generate_csv_report(resultados: list[dict[str, Any]], path: str) -> None:
    """Write results to CSV file."""
    fields = [
        "id",
        "name",
        "username",
        "uri",
        "score",
        "strength",
        "length",
        "weak",
        "reason",
        "crack_time_offline",
        "suggestions",
        "reused",
        "reuse_group",
        "reuse_count",
        "pwned",
        "pwned_count",
    ]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for r in resultados:
            writer.writerow(
                {
                    "id": r["id"],
                    "name": r["nombre"],
                    "username": r["usuario"],
                    "uri": r.get("uri", ""),
                    "score": r["score"],
                    "strength": r["label"],
                    "length": r["longitud"],
                    "weak": "YES" if r["debil"] else "NO",
                    "reason": r["razon"],
                    "crack_time_offline": r.get("crack_time", ""),
                    "suggestions": " / ".join(r.get("sugerencias", [])),
                    "reused": "YES" if r["reutilizada"] else "NO",
                    "reuse_group": r["grupo_reutilizacion"],
                    "reuse_count": r["veces_reutilizada"]
                    if r["reutilizada"]
                    else "",
                    "pwned": "YES"
                    if r.get("pwned")
                    else ("ERROR" if r.get("pwned") is None else "NO"),
                    "pwned_count": r.get("pwned_count", "")
                    if r.get("pwned_count")
                    else "",
                }
            )


def print_summary(
    resultados: list[dict[str, Any]],
    total_reutilizadas: int,
    grupos_reutilizacion: int,
    total_pwned: int = 0,
) -> None:
    """Print terminal summary with statistics."""
    total = len(resultados)
    debiles = [r for r in resultados if r["debil"]]
    vacias = [r for r in resultados if r["score"] == -1]
    reutilizadas = [r for r in resultados if r["reutilizada"]]

    print(f"\n{'─' * 60}")
    print("  PASSBOLT AUDIT SUMMARY")
    print(f"{'─' * 60}")
    print(f"  Total resources audited  : {total}")
    print(f"  Weak passwords          : {len(debiles)}")
    print(
        f"  Reused passwords        : {total_reutilizadas} in {grupos_reutilizacion} groups"
    )
    print(f"  Compromised (HIBP)      : {total_pwned}")
    print(f"  No password / error     : {len(vacias)}")
    print(f"  Acceptable+ passwords  : {total - len(debiles)}")
    print(f"{'─' * 60}")

    if debiles:
        print("\n  TOP WEAK PASSWORDS:")
        for r in sorted(debiles, key=lambda x: x["score"])[:20]:
            print(
                f"  [{r['score']}/4] {r['nombre'][:35]:<35} "
                f"user:{r['usuario'][:20]:<20} "
                f"len:{r['longitud']:>3}  {r['razon']}"
            )
        if len(debiles) > 20:
            print(f"  ... and {len(debiles) - 20} more (see full CSV)")

    if reutilizadas:
        print("\n  REUSED PASSWORDS (first 10 groups):")
        grupos: dict[int, list[str]] = defaultdict(list)
        for r in reutilizadas:
            grupos[r["grupo_reutilizacion"]].append(r["nombre"])
        for gid, nombres in list(grupos.items())[:10]:
            nombres_str = ", ".join(n[:25] for n in nombres[:5])
            if len(nombres) > 5:
                nombres_str += f" (+{len(nombres) - 5} more)"
            print(f"  Group {gid:>3} ({len(nombres)} resources): {nombres_str}")
        if len(grupos) > 10:
            print(f"  ... and {len(grupos) - 10} more groups (see full CSV)")

    print("\n  SCORE DISTRIBUTION:")
    for s in range(-1, 5):
        count = sum(1 for r in resultados if r["score"] == s)
        if count == 0:
            continue
        label = SCORE_LABELS.get(s, "Error/Empty")
        barra = "█" * min(count, 50)
        print(f"  {s:>2} {label:<12} {barra} {count}")
