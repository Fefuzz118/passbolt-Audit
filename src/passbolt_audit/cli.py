"""CLI interface for Passbolt audit tool."""

import argparse
from datetime import datetime
from typing import Any

from passbolt_audit import core


def main() -> int:
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Auditoría de contraseñas débiles en Passbolt CE"
    )
    parser.add_argument(
        "--output",
        "-o",
        default=f"passbolt_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
        help="Archivo CSV de salida (default: passbolt_audit_FECHA.csv)",
    )
    parser.add_argument(
        "--solo-debiles",
        action="store_true",
        help="Incluir solo contraseñas débiles en el CSV",
    )
    parser.add_argument(
        "--solo-reutilizadas",
        action="store_true",
        help="Incluir solo contraseñas reutilizadas en el CSV",
    )
    parser.add_argument(
        "--skip-hibp",
        action="store_true",
        help="Omitir consulta a Have I Been Pwned (usar si no hay internet)",
    )
    parser.add_argument(
        "--limite",
        "-n",
        type=int,
        default=0,
        help="Limitar a N recursos (útil para pruebas, 0 = todos)",
    )
    args = parser.parse_args()

    print("\n━━━ Passbolt CE — Auditoría de Contraseñas ━━━")
    print(f"  Inicio: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(
        f"  Umbral débil: score ≤ {core.UMBRAL_DEBIL} o longitud < {core.LONGITUD_MINIMA}\n"
    )

    resources = core.get_all_resources()
    if not resources:
        print("[ERROR] No se obtuvieron recursos. Verificá la configuración del CLI.")
        return 1

    if args.limite > 0:
        resources = resources[: args.limite]
        print(f"[!] Modo prueba: procesando solo {args.limite} recursos.\n")

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

        evaluacion = core.evaluar_password(password, nombre, usuario)
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
        print(f"\n[!] {errores} recursos con error al descifrar.")

    print("[*] Detectando contraseñas reutilizadas...")
    total_reutilizadas, grupos_reutilizacion = core.detectar_reutilizadas(resultados)

    total_pwned = 0
    if not args.skip_hibp:
        total_pwned = core.consultar_hibp_bulk(resultados)
        print(f"[*] HIBP: {total_pwned} contraseñas comprometidas encontradas.")
    else:
        print("[!] Consulta HIBP omitida (--skip-hibp).")
        for r in resultados:
            r.setdefault("pwned", None)
            r.setdefault("pwned_count", None)

    for r in resultados:
        r.pop("_password_raw", None)

    if args.solo_reutilizadas:
        a_exportar = [r for r in resultados if r["reutilizada"]]
    elif args.solo_debiles:
        a_exportar = [r for r in resultados if r["debil"]]
    else:
        a_exportar = resultados

    core.imprimir_resumen(
        resultados, total_reutilizadas, grupos_reutilizacion, total_pwned
    )
    core.generar_reporte_csv(a_exportar, args.output)

    print(f"\n  Fin: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
