from pathlib import Path

from minecraft_server_scanner.models import MonitorAlert, ScanProfile, ScanSettings, ServerResult
from minecraft_server_scanner.storage import ScannerDatabase


def test_sqlite_profiles_runs_and_results(tmp_path: Path):
    db = ScannerDatabase(tmp_path / "scanner.sqlite3")
    settings = ScanSettings(target_spec="127.0.0.1", ports="25565", edition="java")

    profile = db.save_profile(ScanProfile(name="Local", settings=settings))
    assert profile.id is not None
    assert db.get_profile_by_name("Local").settings.target_spec == "127.0.0.1"

    run = db.create_scan_run(settings, total_targets=1, profile_id=profile.id)
    result = ServerResult(
        scan_run_id=run.id,
        host="127.0.0.1",
        port=25565,
        edition="java",
        version="1.20.4",
        protocol=765,
        players_online=3,
        players_max=20,
        latency_ms=12.5,
        motd="Test",
        favicon_present=True,
    )
    result_id = db.add_result(result)
    db.update_result_flags(result_id, True, "favorite")
    db.finish_scan_run(run.id, "completed", 1, 1)

    runs = db.list_runs()
    results = db.list_results(run.id)
    assert runs[0].status == "completed"
    assert runs[0].settings.timeout == settings.timeout
    assert runs[0].settings.concurrency == settings.concurrency
    assert results[0].favorite is True
    assert results[0].notes == "favorite"


def test_monitor_alert_crud_and_acknowledgement(tmp_path: Path):
    db = ScannerDatabase(tmp_path / "scanner.sqlite3")
    settings = ScanSettings(target_spec="127.0.0.1", ports="25565", edition="java")
    profile = db.save_profile(ScanProfile(name="Local", settings=settings))
    run = db.create_scan_run(settings, total_targets=1, profile_id=profile.id)

    saved = db.add_monitor_alerts(
        [
            MonitorAlert(
                profile_id=profile.id,
                current_run_id=run.id,
                previous_run_id=None,
                event_type="new",
                host="127.0.0.1",
                port=25565,
                edition="java",
                after_value="1.20.4",
            )
        ]
    )

    assert saved[0].id is not None
    alerts = db.list_monitor_alerts()
    assert alerts[0].event_type == "new"
    assert alerts[0].acknowledged is False

    db.acknowledge_monitor_alert(alerts[0].id)
    assert db.list_monitor_alerts()[0].acknowledged is True

    db.add_monitor_alerts(
        [
            MonitorAlert(
                profile_id=profile.id,
                current_run_id=run.id,
                previous_run_id=None,
                event_type="offline",
                host="127.0.0.1",
                port=25565,
                edition="java",
                before_value="1.20.4",
            )
        ]
    )
    db.acknowledge_all_monitor_alerts(profile.id)
    assert all(alert.acknowledged for alert in db.list_monitor_alerts(profile_id=profile.id))


def test_import_server_results_creates_history_run(tmp_path: Path):
    db = ScannerDatabase(tmp_path / "scanner.sqlite3")
    run_id, count = db.import_server_results(
        "MCScans test",
        [
            ServerResult(
                host="203.0.113.10",
                port=25565,
                edition="java",
                version="1.21.4",
                players_online=2,
                players_max=20,
                motd="Imported",
            )
        ],
    )

    runs = db.list_runs()
    results = db.list_results(run_id)
    assert count == 1
    assert runs[0].status == "imported"
    assert runs[0].settings.target_spec == "MCScans import: MCScans test"
    assert results[0].host == "203.0.113.10"
