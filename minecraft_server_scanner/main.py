from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Optional

from PyQt6.QtCore import QTimer
from PyQt6.QtWidgets import QApplication

from . import __version__
from .models import ScanSettings
from .storage import ScannerDatabase
from .ui import MainWindow, apply_app_style


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=f"Minecraft Server Scanner {__version__}")
    parser.add_argument("--profile", help="Load a saved profile by name.")
    parser.add_argument("--target", help="Initial target spec: host, range, CIDR, or @file.")
    parser.add_argument("--ports", help="Initial port spec, for example 25565,19132-19133.")
    parser.add_argument("--edition", choices=["java", "bedrock", "both"], help="Initial edition mode.")
    parser.add_argument("--db", help="SQLite database path.")
    parser.add_argument("--autostart", action="store_true", help="Start scanning after launch.")
    parser.add_argument("--version", action="version", version=__version__)
    return parser


def main(argv: Optional[list] = None) -> int:
    args = build_parser().parse_args(argv)
    settings = ScanSettings()
    if args.target:
        settings.target_spec = args.target
    if args.ports:
        settings.ports = args.ports
    if args.edition:
        settings.edition = args.edition

    app = QApplication(sys.argv[:1])
    apply_app_style(app)
    db = ScannerDatabase(Path(args.db) if args.db else None)
    window = MainWindow(database=db, initial_settings=settings, profile_name=args.profile)
    window.show()
    if args.autostart:
        QTimer.singleShot(250, window.start_scan)
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())

