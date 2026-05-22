import os
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication

from minecraft_server_scanner.models import ScanProfile, ScanSettings
from minecraft_server_scanner.storage import ScannerDatabase
from minecraft_server_scanner.ui import MainWindow


def test_main_window_loads_v2_tabs(tmp_path: Path):
    app = QApplication.instance() or QApplication([])
    db = ScannerDatabase(tmp_path / "ui.sqlite3")
    window = MainWindow(database=db, initial_settings=ScanSettings(target_spec="127.0.0.1"))

    tab_names = [window.tabs.tabText(i) for i in range(window.tabs.count())]

    assert tab_names == ["Scan", "Results", "Monitor", "MCScans", "History", "Profiles", "Settings"]
    assert "2.2.0" in window.windowTitle()
    assert window.monitor_interval_combo.count() == 5
    assert window.monitor_alert_table.columnCount() == len(window.MONITOR_ALERT_COLUMNS)
    assert window.mcscans_table.columnCount() == len(window.MCSCANS_COLUMNS)
    assert window.mcscans_dataset_table.columnCount() == len(window.MCSCANS_DATASET_COLUMNS)
    assert window.mcscans_page_spin.value() == 1
    assert window.mcscans_prev_page_button.isEnabled() is False
    window.close()


def test_monitor_skips_when_scan_is_active(tmp_path: Path):
    app = QApplication.instance() or QApplication([])
    db = ScannerDatabase(tmp_path / "ui.sqlite3")
    profile = db.save_profile(
        ScanProfile(
            name="Local",
            settings=ScanSettings(target_spec="127.0.0.1", ports="25565", edition="java"),
        )
    )
    window = MainWindow(database=db)
    window.monitor_active_profile_id = profile.id
    window.monitor_state = "running"

    class ActiveWorker:
        def isRunning(self):
            return True

        def stop(self):
            pass

        def wait(self, _timeout):
            pass

    window.worker = ActiveWorker()

    assert window.start_monitor_cycle() is False
    assert window.monitor_next_scan_at is not None
    window.close()
