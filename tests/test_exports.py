import csv
import json
from pathlib import Path

from minecraft_server_scanner.exports import EXPORT_FIELDS, export_results_csv, export_results_json
from minecraft_server_scanner.models import ServerResult


def test_export_csv_and_json_include_v2_fields(tmp_path: Path):
    result = ServerResult(
        host="127.0.0.1",
        port=25565,
        edition="java",
        version="1.20.4",
        protocol=765,
        players_online=2,
        players_max=20,
        latency_ms=14.2,
        motd="Hello",
        favicon_present=True,
        scan_run_id=5,
        favorite=True,
        notes="note",
    )
    csv_path = tmp_path / "servers.csv"
    json_path = tmp_path / "servers.json"

    export_results_csv(csv_path, [result])
    export_results_json(json_path, [result])

    with csv_path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert rows[0]["edition"] == "java"
    assert list(rows[0].keys()) == EXPORT_FIELDS

    data = json.loads(json_path.read_text(encoding="utf-8"))
    assert data[0]["scan_run_id"] == 5
    assert data[0]["favorite"] is True

