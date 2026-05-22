from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Iterable, List

from .models import ServerResult

EXPORT_FIELDS = [
    "host",
    "port",
    "edition",
    "version",
    "protocol",
    "players_online",
    "players_max",
    "latency_ms",
    "motd",
    "favicon_present",
    "discovered_at",
    "scan_run_id",
    "favorite",
    "notes",
]


def result_rows(results: Iterable[ServerResult]) -> List[dict]:
    return [result.to_export_dict() for result in results]


def export_results_csv(path: Path, results: Iterable[ServerResult]) -> None:
    rows = result_rows(results)
    with Path(path).open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=EXPORT_FIELDS)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def export_results_json(path: Path, results: Iterable[ServerResult]) -> None:
    with Path(path).open("w", encoding="utf-8") as handle:
        json.dump(result_rows(results), handle, ensure_ascii=False, indent=2)

