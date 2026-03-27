"""Passbolt CE password auditor for weak, reused, and compromised credentials."""

__version__ = "0.1.0.2"
__all__ = ["cli", "core"]

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .cli import main
    from .core import (
        LONGITUD_MINIMA,
        UMBRAL_DEBIL,
        configure_passbolt,
        consultar_hibp_bulk,
        detect_reused_passwords,
        evaluate_password,
        generate_csv_report,
        get_all_resources,
        get_secret,
        get_private_key_interactive,
        print_summary,
        save_private_key,
    )
