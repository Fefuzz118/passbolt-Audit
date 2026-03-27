"""CLI interface for Passbolt audit tool."""

import argparse
from datetime import datetime
from typing import Any

from passbolt_audit import core


def main() -> int:
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Passbolt CE password auditor - audit weak, reused, and compromised credentials"
    )
    parser.add_argument(
        "--server",
        "-s",
        required=True,
        help="Passbolt server URL (e.g., https://passbolt.dc.in.antel.net.uy)",
    )
    parser.add_argument(
        "--configure",
        "-c",
        action="store_true",
        help="Show go-passbolt-cli configuration instructions",
    )
    parser.add_argument(
        "--output",
        "-o",
        default=f"passbolt_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
        help="Output CSV file (default: passbolt_audit_DATE.csv)",
    )
    parser.add_argument(
        "--weak-only",
        action="store_true",
        help="Include only weak passwords in CSV",
    )
    parser.add_argument(
        "--reused-only",
        action="store_true",
        help="Include only reused passwords in CSV",
    )
    parser.add_argument(
        "--skip-hibp",
        action="store_true",
        help="Skip Have I Been Pwned query (use when no internet)",
    )
    parser.add_argument(
        "--limite",
        "-n",
        type=int,
        default=0,
        help="Limit to N resources (useful for testing, 0 = all)",
    )
    args = parser.parse_args()

    if args.configure:
        core.configure_passbolt(args.server, "", "")
        return 0

    print("\n━━━ Passbolt CE — Password Audit ━━━")
    print(f"  Start: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(
        f"  Weak threshold: score ≤ {core.UMBRAL_DEBIL} or length < {core.LONGITUD_MINIMA}\n"
    )

    resources = core.get_all_resources()
    if not resources:
        print("[ERROR] No resources obtained. Check CLI configuration.")
        print("         Did you run --configure first?")
        return 1

    if args.limite > 0:
        resources = resources[: args.limite]
        print(f"[!] Test mode: processing only {args.limite} resources.\n")

    resultados: list[dict[str, Any]] = []
    errores = 0
    total = len(resources)

    for i, res in enumerate(resources, 1):
        rid = res.get("id", "")
        nombre = res.get("name", res.get("Name", "Sin nombre"))
        usuario = res.get("username", res.get("Username", ""))
        uri = res.get("uri", res.get("Uri", ""))

        pct = int((i / total) * 40)
        barra = f"[{'█' * pct}{'░' * (40 - pct)}]"
        print(f"\r  {barra} {i}/{total} — {nombre[:30]:<30}", end="", flush=True)

        password = core.get_secret(rid)
        if password is None:
            errores += 1

        evaluacion = core.evaluate_password(password, nombre, usuario)
        evaluacion.update(
            {
                "id": rid,
                "nombre": nombre,
                "usuario": usuario,
                "uri": uri,
                "_password_raw": password or "",
            }
        )
        resultados.append(evaluacion)

    print()

    if errores > 0:
        print(f"\n[!] {errores} resources with decryption error.")

    print("[*] Detecting reused passwords...")
    total_reutilizadas, grupos_reutilizacion = core.detect_reused_passwords(resultados)

    total_pwned = 0
    if not args.skip_hibp:
        total_pwned = core.consultar_hibp_bulk(resultados)
        print(f"[*] HIBP: {total_pwned} compromised passwords found.")
    else:
        print("[!] HIBP query skipped (--skip-hibp).")
        for r in resultados:
            r.setdefault("pwned", None)
            r.setdefault("pwned_count", None)

    for r in resultados:
        r.pop("_password_raw", None)

    if args.reused_only:
        a_exportar = [r for r in resultados if r["reutilizada"]]
    elif args.weak_only:
        a_exportar = [r for r in resultados if r["debil"]]
    else:
        a_exportar = resultados

    core.print_summary(
        resultados, total_reutilizadas, grupos_reutilizacion, total_pwned
    )
    core.generate_csv_report(a_exportar, args.output)

    print(f"\n  Fin: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
