from __future__ import annotations

import os
import sqlite3
from pathlib import Path
from typing import Iterable, List, Optional

from .models import MonitorAlert, ScanProfile, ScanRun, ScanSettings, ServerResult, utc_now

SCHEMA_VERSION = 2


def default_database_path() -> Path:
    if os.name == "nt":
        root = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
        return root / "MinecraftServerScanner" / "scanner.sqlite3"
    return Path.home() / ".minecraft_server_scanner" / "scanner.sqlite3"


class ScannerDatabase:
    def __init__(self, path: Optional[Path] = None):
        self.path = Path(path) if path else default_database_path()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.initialize()

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def initialize(self) -> None:
        with self.connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version INTEGER PRIMARY KEY,
                    applied_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS profiles (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    target_spec TEXT NOT NULL,
                    ports TEXT NOT NULL,
                    edition TEXT NOT NULL,
                    timeout REAL NOT NULL,
                    concurrency INTEGER NOT NULL,
                    retries INTEGER NOT NULL,
                    min_players INTEGER NOT NULL,
                    only_online INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS scan_runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    profile_id INTEGER,
                    started_at TEXT NOT NULL,
                    finished_at TEXT,
                    status TEXT NOT NULL,
                    target_spec TEXT NOT NULL,
                    ports TEXT NOT NULL,
                    edition TEXT NOT NULL,
                    timeout REAL NOT NULL,
                    concurrency INTEGER NOT NULL,
                    retries INTEGER NOT NULL,
                    min_players INTEGER NOT NULL,
                    only_online INTEGER NOT NULL,
                    total_targets INTEGER NOT NULL,
                    completed_targets INTEGER NOT NULL,
                    found_count INTEGER NOT NULL,
                    FOREIGN KEY(profile_id) REFERENCES profiles(id) ON DELETE SET NULL
                );

                CREATE TABLE IF NOT EXISTS server_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_run_id INTEGER NOT NULL,
                    host TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    edition TEXT NOT NULL,
                    version TEXT NOT NULL,
                    protocol INTEGER,
                    players_online INTEGER,
                    players_max INTEGER,
                    latency_ms REAL,
                    motd TEXT NOT NULL,
                    favicon_present INTEGER NOT NULL,
                    discovered_at TEXT NOT NULL,
                    favorite INTEGER NOT NULL DEFAULT 0,
                    notes TEXT NOT NULL DEFAULT '',
                    FOREIGN KEY(scan_run_id) REFERENCES scan_runs(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS monitor_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    profile_id INTEGER,
                    current_run_id INTEGER NOT NULL,
                    previous_run_id INTEGER,
                    event_type TEXT NOT NULL,
                    host TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    edition TEXT NOT NULL,
                    before_value TEXT NOT NULL,
                    after_value TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    acknowledged INTEGER NOT NULL DEFAULT 0,
                    FOREIGN KEY(profile_id) REFERENCES profiles(id) ON DELETE SET NULL,
                    FOREIGN KEY(current_run_id) REFERENCES scan_runs(id) ON DELETE CASCADE,
                    FOREIGN KEY(previous_run_id) REFERENCES scan_runs(id) ON DELETE SET NULL
                );
                """
            )
            conn.execute(
                "INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES(?, ?)",
                (1, utc_now()),
            )
            conn.execute(
                "INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES(?, ?)",
                (SCHEMA_VERSION, utc_now()),
            )

    def save_profile(self, profile: ScanProfile) -> ScanProfile:
        now = utc_now()
        if profile.id is None:
            profile.created_at = profile.created_at or now
            profile.updated_at = now
            with self.connect() as conn:
                cur = conn.execute(
                    """
                    INSERT INTO profiles(
                        name, target_spec, ports, edition, timeout, concurrency,
                        retries, min_players, only_online, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(name) DO UPDATE SET
                        target_spec=excluded.target_spec,
                        ports=excluded.ports,
                        edition=excluded.edition,
                        timeout=excluded.timeout,
                        concurrency=excluded.concurrency,
                        retries=excluded.retries,
                        min_players=excluded.min_players,
                        only_online=excluded.only_online,
                        updated_at=excluded.updated_at
                    """,
                    _profile_values(profile),
                )
                row = conn.execute("SELECT id FROM profiles WHERE name = ?", (profile.name,)).fetchone()
                profile.id = int(row["id"])
        else:
            profile.updated_at = now
            with self.connect() as conn:
                conn.execute(
                    """
                    UPDATE profiles SET
                        name=?, target_spec=?, ports=?, edition=?, timeout=?,
                        concurrency=?, retries=?, min_players=?, only_online=?,
                        updated_at=?
                    WHERE id=?
                    """,
                    (
                        profile.name,
                        profile.settings.target_spec,
                        profile.settings.ports,
                        profile.settings.edition,
                        profile.settings.timeout,
                        profile.settings.concurrency,
                        profile.settings.retries,
                        profile.settings.min_players,
                        int(profile.settings.only_online),
                        profile.updated_at,
                        profile.id,
                    ),
                )
        return profile

    def list_profiles(self) -> List[ScanProfile]:
        with self.connect() as conn:
            rows = conn.execute("SELECT * FROM profiles ORDER BY name").fetchall()
        return [_profile_from_row(row) for row in rows]

    def get_profile_by_name(self, name: str) -> Optional[ScanProfile]:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM profiles WHERE name = ?", (name,)).fetchone()
        return _profile_from_row(row) if row else None

    def delete_profile(self, profile_id: int) -> None:
        with self.connect() as conn:
            conn.execute("DELETE FROM profiles WHERE id = ?", (profile_id,))

    def create_scan_run(self, settings: ScanSettings, total_targets: int, profile_id: Optional[int] = None) -> ScanRun:
        run = ScanRun(settings=settings, profile_id=profile_id, total_targets=total_targets)
        with self.connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO scan_runs(
                    profile_id, started_at, finished_at, status, target_spec, ports,
                    edition, timeout, concurrency, retries, min_players, only_online,
                    total_targets, completed_targets, found_count
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run.profile_id,
                    run.started_at,
                    run.finished_at,
                    run.status,
                    settings.target_spec,
                    settings.ports,
                    settings.edition,
                    settings.timeout,
                    settings.concurrency,
                    settings.retries,
                    settings.min_players,
                    int(settings.only_online),
                    run.total_targets,
                    run.completed_targets,
                    run.found_count,
                ),
            )
            run.id = int(cur.lastrowid)
        return run

    def finish_scan_run(self, run_id: int, status: str, completed_targets: int, found_count: int) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                UPDATE scan_runs
                SET finished_at=?, status=?, completed_targets=?, found_count=?
                WHERE id=?
                """,
                (utc_now(), status, completed_targets, found_count, run_id),
            )

    def add_result(self, result: ServerResult) -> int:
        if result.scan_run_id is None:
            raise ValueError("Result must include scan_run_id before saving.")
        with self.connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO server_results(
                    scan_run_id, host, port, edition, version, protocol,
                    players_online, players_max, latency_ms, motd,
                    favicon_present, discovered_at, favorite, notes
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    result.scan_run_id,
                    result.host,
                    result.port,
                    result.edition,
                    result.version,
                    result.protocol,
                    result.players_online,
                    result.players_max,
                    result.latency_ms,
                    result.motd,
                    int(result.favicon_present),
                    result.discovered_at,
                    int(result.favorite),
                    result.notes,
                ),
            )
            return int(cur.lastrowid)

    def list_runs(self, limit: int = 200) -> List[ScanRun]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM scan_runs ORDER BY started_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [_run_from_row(row) for row in rows]

    def list_results(self, scan_run_id: Optional[int] = None) -> List[ServerResult]:
        sql = "SELECT * FROM server_results"
        params = ()
        if scan_run_id is not None:
            sql += " WHERE scan_run_id = ?"
            params = (scan_run_id,)
        sql += " ORDER BY discovered_at DESC, id DESC"
        with self.connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [_result_from_row(row) for row in rows]

    def update_result_flags(self, result_id: int, favorite: bool, notes: str) -> None:
        with self.connect() as conn:
            conn.execute(
                "UPDATE server_results SET favorite=?, notes=? WHERE id=?",
                (int(favorite), notes, result_id),
            )

    def import_server_results(self, label: str, results: Iterable[ServerResult]) -> tuple[int, int]:
        result_list = list(results)
        ports = sorted({result.port for result in result_list})
        editions = sorted({result.edition for result in result_list})
        settings = ScanSettings(
            target_spec=f"MCScans import: {label}",
            ports=",".join(str(port) for port in ports) or "25565",
            edition=editions[0] if len(editions) == 1 else "both",
            timeout=0.0,
            concurrency=1,
            retries=0,
        )
        run = self.create_scan_run(settings, total_targets=len(result_list))
        for result in result_list:
            result.scan_run_id = run.id
            self.add_result(result)
        self.finish_scan_run(int(run.id), "imported", len(result_list), len(result_list))
        return int(run.id), len(result_list)

    def add_monitor_alerts(self, alerts: Iterable[MonitorAlert]) -> List[MonitorAlert]:
        saved: List[MonitorAlert] = []
        with self.connect() as conn:
            for alert in alerts:
                cur = conn.execute(
                    """
                    INSERT INTO monitor_alerts(
                        profile_id, current_run_id, previous_run_id, event_type,
                        host, port, edition, before_value, after_value,
                        created_at, acknowledged
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        alert.profile_id,
                        alert.current_run_id,
                        alert.previous_run_id,
                        alert.event_type,
                        alert.host,
                        alert.port,
                        alert.edition,
                        alert.before_value,
                        alert.after_value,
                        alert.created_at,
                        int(alert.acknowledged),
                    ),
                )
                alert.id = int(cur.lastrowid)
                saved.append(alert)
        return saved

    def list_monitor_alerts(
        self,
        profile_id: Optional[int] = None,
        acknowledged: Optional[bool] = None,
        limit: int = 500,
    ) -> List[MonitorAlert]:
        clauses = []
        params: list = []
        if profile_id is not None:
            clauses.append("profile_id = ?")
            params.append(profile_id)
        if acknowledged is not None:
            clauses.append("acknowledged = ?")
            params.append(int(acknowledged))
        sql = "SELECT * FROM monitor_alerts"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY acknowledged ASC, created_at DESC, id DESC LIMIT ?"
        params.append(limit)
        with self.connect() as conn:
            rows = conn.execute(sql, tuple(params)).fetchall()
        return [_monitor_alert_from_row(row) for row in rows]

    def acknowledge_monitor_alert(self, alert_id: int) -> None:
        with self.connect() as conn:
            conn.execute("UPDATE monitor_alerts SET acknowledged = 1 WHERE id = ?", (alert_id,))

    def acknowledge_all_monitor_alerts(self, profile_id: Optional[int] = None) -> None:
        with self.connect() as conn:
            if profile_id is None:
                conn.execute("UPDATE monitor_alerts SET acknowledged = 1")
            else:
                conn.execute("UPDATE monitor_alerts SET acknowledged = 1 WHERE profile_id = ?", (profile_id,))


def _profile_values(profile: ScanProfile) -> tuple:
    settings = profile.settings
    return (
        profile.name,
        settings.target_spec,
        settings.ports,
        settings.edition,
        settings.timeout,
        settings.concurrency,
        settings.retries,
        settings.min_players,
        int(settings.only_online),
        profile.created_at,
        profile.updated_at,
    )


def _settings_from_row(row: sqlite3.Row) -> ScanSettings:
    return ScanSettings(
        target_spec=row["target_spec"],
        ports=row["ports"],
        edition=row["edition"],
        timeout=float(row["timeout"]),
        concurrency=int(row["concurrency"]),
        retries=int(row["retries"]),
        min_players=int(row["min_players"]),
        only_online=bool(row["only_online"]),
    )


def _profile_from_row(row: sqlite3.Row) -> ScanProfile:
    return ScanProfile(
        id=int(row["id"]),
        name=row["name"],
        settings=_settings_from_row(row),
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


def _run_from_row(row: sqlite3.Row) -> ScanRun:
    settings = _settings_from_row(row)
    return ScanRun(
        id=int(row["id"]),
        profile_id=row["profile_id"],
        started_at=row["started_at"],
        finished_at=row["finished_at"],
        status=row["status"],
        settings=settings,
        total_targets=int(row["total_targets"]),
        completed_targets=int(row["completed_targets"]),
        found_count=int(row["found_count"]),
    )


def _result_from_row(row: sqlite3.Row) -> ServerResult:
    result = ServerResult(
        host=row["host"],
        port=int(row["port"]),
        edition=row["edition"],
        version=row["version"],
        protocol=row["protocol"],
        players_online=row["players_online"],
        players_max=row["players_max"],
        latency_ms=row["latency_ms"],
        motd=row["motd"],
        favicon_present=bool(row["favicon_present"]),
        discovered_at=row["discovered_at"],
        scan_run_id=int(row["scan_run_id"]),
        favorite=bool(row["favorite"]),
        notes=row["notes"],
    )
    setattr(result, "id", int(row["id"]))
    return result


def _monitor_alert_from_row(row: sqlite3.Row) -> MonitorAlert:
    return MonitorAlert(
        id=int(row["id"]),
        profile_id=row["profile_id"],
        current_run_id=int(row["current_run_id"]),
        previous_run_id=row["previous_run_id"],
        event_type=row["event_type"],
        host=row["host"],
        port=int(row["port"]),
        edition=row["edition"],
        before_value=row["before_value"],
        after_value=row["after_value"],
        created_at=row["created_at"],
        acknowledged=bool(row["acknowledged"]),
    )
