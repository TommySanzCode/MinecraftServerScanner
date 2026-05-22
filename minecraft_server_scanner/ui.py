from __future__ import annotations

import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional, Set

from PyQt6.QtCore import Qt, QThread, QTimer, pyqtSignal
from PyQt6.QtGui import QColor, QPalette
from PyQt6.QtWidgets import (
    QApplication,
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QPlainTextEdit,
    QProgressBar,
    QSpinBox,
    QDoubleSpinBox,
    QStatusBar,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from . import __version__
from .exports import export_results_csv, export_results_json
from .mcscans import McScansClient, McScansDataset, McScansDatasetFile, McScansServer, dataset_target_files
from .models import MonitorAlert, ScanProfile, ScanSettings, ServerResult
from .monitor import alerts_for_monitor_cycle, identities_for
from .scanner import ScanEngine
from .storage import ScannerDatabase
from .targets import PRIVATE_TARGET_WARNING, contains_public_targets, validate_scan_settings


class ScannerWorker(QThread):
    result_signal = pyqtSignal(object)
    progress_signal = pyqtSignal(int, int, int)
    log_signal = pyqtSignal(str)
    done_signal = pyqtSignal(int, int, int, str)
    error_signal = pyqtSignal(str)

    def __init__(self, db_path: Path, settings: ScanSettings, profile_id: Optional[int] = None):
        super().__init__()
        self.db_path = db_path
        self.settings = settings
        self.profile_id = profile_id
        self.cancel_event = threading.Event()

    def stop(self) -> None:
        self.cancel_event.set()

    def run(self) -> None:
        run_id = 0
        try:
            db = ScannerDatabase(self.db_path)
            engine = ScanEngine(self.settings)
            total = engine.total_jobs()
            run = db.create_scan_run(self.settings, total_targets=total, profile_id=self.profile_id)
            run_id = int(run.id or 0)

            def on_result(result: ServerResult) -> None:
                result.scan_run_id = run_id
                result_id = db.add_result(result)
                setattr(result, "id", result_id)
                self.result_signal.emit(result)

            summary = engine.scan(
                progress_callback=lambda done, count, found: self.progress_signal.emit(done, count, found),
                result_callback=on_result,
                log_callback=self.log_signal.emit,
                cancel_event=self.cancel_event,
            )
            status = "cancelled" if summary.cancelled else "completed"
            db.finish_scan_run(run_id, status, summary.completed_targets, summary.found_count)
            self.done_signal.emit(run_id, summary.completed_targets, summary.found_count, status)
        except Exception as exc:
            if run_id:
                ScannerDatabase(self.db_path).finish_scan_run(run_id, "failed", 0, 0)
            self.error_signal.emit(str(exc))


class McScansSearchWorker(QThread):
    result_signal = pyqtSignal(object)
    error_signal = pyqtSignal(str)

    def __init__(self, params: dict):
        super().__init__()
        self.params = params

    def run(self) -> None:
        try:
            self.result_signal.emit(McScansClient().search_servers(**self.params))
        except Exception as exc:
            self.error_signal.emit(str(exc))


class McScansDatasetsWorker(QThread):
    result_signal = pyqtSignal(object)
    error_signal = pyqtSignal(str)

    def run(self) -> None:
        try:
            self.result_signal.emit(McScansClient().list_datasets())
        except Exception as exc:
            self.error_signal.emit(str(exc))


class MainWindow(QMainWindow):
    RESULT_COLUMNS = [
        "Fav",
        "Host",
        "Port",
        "Edition",
        "Version",
        "Protocol",
        "Players",
        "Latency",
        "MOTD",
        "Notes",
    ]

    RUN_COLUMNS = ["ID", "Started", "Status", "Target", "Ports", "Edition", "Done", "Found"]
    PROFILE_COLUMNS = ["ID", "Name", "Target", "Ports", "Edition"]
    MONITOR_ALERT_COLUMNS = ["Ack", "Time", "Event", "Server", "Before", "After", "Run"]
    MONITOR_INTERVALS = [(1, 60), (5, 300), (15, 900), (30, 1800), (60, 3600)]
    MONITOR_RUN_ROLE = int(Qt.ItemDataRole.UserRole) + 1
    MCSCANS_COLUMNS = ["Host", "Port", "Edition", "Version", "Software", "Players", "Protocol", "Live", "Country", "MOTD"]
    MCSCANS_DATASET_COLUMNS = ["Dataset", "File", "Size", "Lines", "Modified", "URL"]
    MCSCANS_PAGE_SIZE = 20

    def __init__(
        self,
        database: ScannerDatabase,
        initial_settings: Optional[ScanSettings] = None,
        profile_name: Optional[str] = None,
    ):
        super().__init__()
        self.database = database
        self.worker: Optional[ScannerWorker] = None
        self.worker_mode: Optional[str] = None
        self.results: List[ServerResult] = []
        self.current_run_id: Optional[int] = None
        self.current_profile_id: Optional[int] = None
        self.monitor_state = "stopped"
        self.monitor_active_profile_id: Optional[int] = None
        self.monitor_previous_run_id: Optional[int] = None
        self.monitor_previous_results: List[ServerResult] = []
        self.monitor_current_results: List[ServerResult] = []
        self.monitor_known_identities: Set[str] = set()
        self.monitor_next_scan_at: Optional[datetime] = None
        self.monitor_alerts: List[MonitorAlert] = []
        self.mcscans_results: List[McScansServer] = []
        self.mcscans_dataset_files: List[McScansDatasetFile] = []
        self.mcscans_search_worker: Optional[McScansSearchWorker] = None
        self.mcscans_datasets_worker: Optional[McScansDatasetsWorker] = None
        self.mcscans_total_servers: Optional[int] = None
        self.mcscans_total_pages = 1

        self.setWindowTitle(f"Minecraft Server Scanner {__version__}")
        self.setMinimumSize(1120, 720)
        self._build_ui()
        self.refresh_profiles()
        self.refresh_history()
        self.refresh_monitor_alerts()
        self.monitor_timer = QTimer(self)
        self.monitor_timer.setInterval(1000)
        self.monitor_timer.timeout.connect(self.monitor_tick)
        self.monitor_timer.start()

        if profile_name:
            profile = self.database.get_profile_by_name(profile_name)
            if profile:
                self.apply_settings(profile.settings)
                self.current_profile_id = profile.id
        elif initial_settings:
            self.apply_settings(initial_settings)

    def _build_ui(self) -> None:
        root = QWidget()
        layout = QVBoxLayout(root)
        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_scan_tab(), "Scan")
        self.tabs.addTab(self._build_results_tab(), "Results")
        self.tabs.addTab(self._build_monitor_tab(), "Monitor")
        self.tabs.addTab(self._build_mcscans_tab(), "MCScans")
        self.tabs.addTab(self._build_history_tab(), "History")
        self.tabs.addTab(self._build_profiles_tab(), "Profiles")
        self.tabs.addTab(self._build_settings_tab(), "Settings")
        layout.addWidget(self.tabs)
        self.setCentralWidget(root)
        self.setStatusBar(QStatusBar())
        self.set_status("Ready")

    def _build_scan_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)

        grid = QGridLayout()
        grid.addWidget(QLabel("Targets"), 0, 0)
        self.target_input = QPlainTextEdit()
        self.target_input.setPlaceholderText("192.168.1.1-192.168.1.255, 192.168.1.0/24, play.example.net, or @targets.txt")
        self.target_input.setPlainText(ScanSettings().target_spec)
        grid.addWidget(self.target_input, 0, 1, 3, 4)

        self.import_targets_button = QPushButton("Import Target File")
        self.import_targets_button.clicked.connect(self.import_targets_file)
        grid.addWidget(self.import_targets_button, 0, 5)

        grid.addWidget(QLabel("Edition"), 3, 0)
        self.edition_combo = QComboBox()
        self.edition_combo.addItem("Java + Bedrock", "both")
        self.edition_combo.addItem("Java", "java")
        self.edition_combo.addItem("Bedrock", "bedrock")
        grid.addWidget(self.edition_combo, 3, 1)

        grid.addWidget(QLabel("Ports"), 3, 2)
        self.ports_input = QLineEdit(ScanSettings().ports)
        self.ports_input.setPlaceholderText("25565,19132-19133")
        grid.addWidget(self.ports_input, 3, 3, 1, 2)

        self.warning_label = QLabel("")
        self.warning_label.setStyleSheet("color: #ffcc66;")
        grid.addWidget(self.warning_label, 4, 1, 1, 5)

        grid.addWidget(QLabel("Timeout"), 5, 0)
        self.timeout_spin = QDoubleSpinBox()
        self.timeout_spin.setRange(0.25, 60.0)
        self.timeout_spin.setDecimals(2)
        self.timeout_spin.setSingleStep(0.25)
        self.timeout_spin.setValue(3.0)
        grid.addWidget(self.timeout_spin, 5, 1)

        grid.addWidget(QLabel("Concurrency"), 5, 2)
        self.concurrency_spin = QSpinBox()
        self.concurrency_spin.setRange(1, 512)
        self.concurrency_spin.setValue(64)
        grid.addWidget(self.concurrency_spin, 5, 3)

        grid.addWidget(QLabel("Retries"), 5, 4)
        self.retries_spin = QSpinBox()
        self.retries_spin.setRange(0, 10)
        self.retries_spin.setValue(0)
        grid.addWidget(self.retries_spin, 5, 5)

        grid.addWidget(QLabel("Min Players"), 6, 0)
        self.min_players_spin = QSpinBox()
        self.min_players_spin.setRange(0, 100000)
        self.min_players_spin.valueChanged.connect(self.refresh_results_table)
        grid.addWidget(self.min_players_spin, 6, 1)

        self.only_online_check = QCheckBox("Only Online")
        self.only_online_check.stateChanged.connect(self.refresh_results_table)
        grid.addWidget(self.only_online_check, 6, 2)

        self.targets_changed_connections()
        layout.addLayout(grid)

        controls = QHBoxLayout()
        self.profile_combo = QComboBox()
        controls.addWidget(QLabel("Profile"))
        controls.addWidget(self.profile_combo)

        self.load_profile_button = QPushButton("Load")
        self.load_profile_button.clicked.connect(self.load_selected_profile)
        controls.addWidget(self.load_profile_button)

        self.profile_name_input = QLineEdit()
        self.profile_name_input.setPlaceholderText("Profile name")
        controls.addWidget(self.profile_name_input)

        self.save_profile_button = QPushButton("Save Profile")
        self.save_profile_button.clicked.connect(self.save_current_profile)
        controls.addWidget(self.save_profile_button)
        controls.addStretch()
        layout.addLayout(controls)

        scan_controls = QHBoxLayout()
        self.start_button = QPushButton("Start Scan")
        self.start_button.clicked.connect(self.start_scan)
        scan_controls.addWidget(self.start_button)

        self.stop_button = QPushButton("Stop")
        self.stop_button.setEnabled(False)
        self.stop_button.clicked.connect(self.stop_scan)
        scan_controls.addWidget(self.stop_button)

        self.progress = QProgressBar()
        self.progress.setRange(0, 1)
        scan_controls.addWidget(self.progress, 1)
        layout.addLayout(scan_controls)

        self.log_view = QTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setMinimumHeight(160)
        layout.addWidget(QLabel("Scan Log"))
        layout.addWidget(self.log_view)
        return page

    def _build_results_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        controls = QHBoxLayout()

        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("Filter results by host, edition, version, MOTD, or notes")
        self.filter_input.textChanged.connect(self.refresh_results_table)
        controls.addWidget(self.filter_input)

        self.favorites_only_check = QCheckBox("Favorites")
        self.favorites_only_check.stateChanged.connect(self.refresh_results_table)
        controls.addWidget(self.favorites_only_check)

        self.copy_addresses_button = QPushButton("Copy Addresses")
        self.copy_addresses_button.clicked.connect(self.copy_addresses)
        controls.addWidget(self.copy_addresses_button)

        self.export_csv_button = QPushButton("Export CSV")
        self.export_csv_button.clicked.connect(self.export_current_csv)
        controls.addWidget(self.export_csv_button)

        self.export_json_button = QPushButton("Export JSON")
        self.export_json_button.clicked.connect(self.export_current_json)
        controls.addWidget(self.export_json_button)
        layout.addLayout(controls)

        self.results_table = QTableWidget(0, len(self.RESULT_COLUMNS))
        self.results_table.setHorizontalHeaderLabels(self.RESULT_COLUMNS)
        self.results_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.results_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.results_table.itemSelectionChanged.connect(self.load_selected_result_details)
        self.results_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.results_table.horizontalHeader().setSectionResizeMode(8, QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.results_table)

        details = QHBoxLayout()
        self.favorite_button = QPushButton("Toggle Favorite")
        self.favorite_button.clicked.connect(self.toggle_selected_favorite)
        details.addWidget(self.favorite_button)
        self.notes_input = QLineEdit()
        self.notes_input.setPlaceholderText("Notes for selected result")
        details.addWidget(self.notes_input, 1)
        self.save_notes_button = QPushButton("Save Notes")
        self.save_notes_button.clicked.connect(self.save_selected_notes)
        details.addWidget(self.save_notes_button)
        layout.addLayout(details)
        return page

    def _build_monitor_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)

        controls = QHBoxLayout()
        controls.addWidget(QLabel("Profile"))
        self.monitor_profile_combo = QComboBox()
        controls.addWidget(self.monitor_profile_combo, 1)

        controls.addWidget(QLabel("Interval"))
        self.monitor_interval_combo = QComboBox()
        for minutes, seconds in self.MONITOR_INTERVALS:
            self.monitor_interval_combo.addItem(f"{minutes} min", seconds)
        controls.addWidget(self.monitor_interval_combo)

        self.monitor_start_button = QPushButton("Start Monitor")
        self.monitor_start_button.clicked.connect(self.start_monitor)
        controls.addWidget(self.monitor_start_button)

        self.monitor_pause_button = QPushButton("Pause")
        self.monitor_pause_button.setEnabled(False)
        self.monitor_pause_button.clicked.connect(self.toggle_monitor_pause)
        controls.addWidget(self.monitor_pause_button)

        self.monitor_stop_button = QPushButton("Stop")
        self.monitor_stop_button.setEnabled(False)
        self.monitor_stop_button.clicked.connect(self.stop_monitor)
        controls.addWidget(self.monitor_stop_button)
        layout.addLayout(controls)

        status = QHBoxLayout()
        self.monitor_state_label = QLabel("State: stopped")
        status.addWidget(self.monitor_state_label)
        self.monitor_next_label = QLabel("Next run: --")
        status.addWidget(self.monitor_next_label)
        self.monitor_summary_label = QLabel("Baseline not captured")
        status.addWidget(self.monitor_summary_label, 1)
        layout.addLayout(status)

        self.monitor_progress = QProgressBar()
        self.monitor_progress.setRange(0, 1)
        layout.addWidget(self.monitor_progress)

        alert_controls = QHBoxLayout()
        self.monitor_ack_button = QPushButton("Acknowledge Selected")
        self.monitor_ack_button.clicked.connect(self.acknowledge_selected_monitor_alert)
        alert_controls.addWidget(self.monitor_ack_button)

        self.monitor_ack_all_button = QPushButton("Acknowledge All")
        self.monitor_ack_all_button.clicked.connect(self.acknowledge_all_monitor_alerts)
        alert_controls.addWidget(self.monitor_ack_all_button)

        self.monitor_load_run_button = QPushButton("Load Related Run")
        self.monitor_load_run_button.clicked.connect(self.load_monitor_alert_run)
        alert_controls.addWidget(self.monitor_load_run_button)

        self.monitor_copy_address_button = QPushButton("Copy Address")
        self.monitor_copy_address_button.clicked.connect(self.copy_monitor_alert_address)
        alert_controls.addWidget(self.monitor_copy_address_button)
        alert_controls.addStretch()
        layout.addLayout(alert_controls)

        self.monitor_alert_table = QTableWidget(0, len(self.MONITOR_ALERT_COLUMNS))
        self.monitor_alert_table.setHorizontalHeaderLabels(self.MONITOR_ALERT_COLUMNS)
        self.monitor_alert_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.monitor_alert_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.monitor_alert_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.monitor_alert_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.monitor_alert_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.monitor_alert_table)

        self.monitor_log_view = QTextEdit()
        self.monitor_log_view.setReadOnly(True)
        self.monitor_log_view.setMinimumHeight(120)
        layout.addWidget(QLabel("Monitor Log"))
        layout.addWidget(self.monitor_log_view)
        return page

    def _build_mcscans_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)

        search_grid = QGridLayout()
        search_grid.addWidget(QLabel("Query"), 0, 0)
        self.mcscans_query_input = QLineEdit()
        self.mcscans_query_input.setPlaceholderText("survival, pvp, hostname, software, version, or MOTD text")
        search_grid.addWidget(self.mcscans_query_input, 0, 1, 1, 3)

        search_grid.addWidget(QLabel("Edition"), 0, 4)
        self.mcscans_edition_combo = QComboBox()
        self.mcscans_edition_combo.addItems(["Java", "Bedrock", "Any"])
        search_grid.addWidget(self.mcscans_edition_combo, 0, 5)

        search_grid.addWidget(QLabel("Software"), 1, 0)
        self.mcscans_software_input = QLineEdit()
        self.mcscans_software_input.setPlaceholderText("Paper, Spigot, Forge...")
        search_grid.addWidget(self.mcscans_software_input, 1, 1)

        search_grid.addWidget(QLabel("Version"), 1, 2)
        self.mcscans_version_input = QLineEdit()
        self.mcscans_version_input.setPlaceholderText("1.21.4")
        search_grid.addWidget(self.mcscans_version_input, 1, 3)

        search_grid.addWidget(QLabel("Sort"), 1, 4)
        self.mcscans_sort_combo = QComboBox()
        self.mcscans_sort_combo.addItem("Default", "")
        self.mcscans_sort_combo.addItem("Players", "player")
        self.mcscans_sort_combo.addItem("Protocol", "proto")
        self.mcscans_sort_combo.addItem("Timestamp", "timestamp")
        search_grid.addWidget(self.mcscans_sort_combo, 1, 5)

        search_grid.addWidget(QLabel("Page"), 2, 0)
        self.mcscans_page_spin = QSpinBox()
        self.mcscans_page_spin.setRange(1, 1)
        self.mcscans_page_spin.setValue(1)
        search_grid.addWidget(self.mcscans_page_spin, 2, 1)

        self.mcscans_prev_page_button = QPushButton("Previous")
        self.mcscans_prev_page_button.clicked.connect(self.previous_mcscans_page)
        search_grid.addWidget(self.mcscans_prev_page_button, 2, 2)

        self.mcscans_next_page_button = QPushButton("Next")
        self.mcscans_next_page_button.clicked.connect(self.next_mcscans_page)
        search_grid.addWidget(self.mcscans_next_page_button, 2, 3)

        self.mcscans_live_check = QCheckBox("Live only")
        search_grid.addWidget(self.mcscans_live_check, 2, 4)

        self.mcscans_search_button = QPushButton("Search MCScans")
        self.mcscans_search_button.clicked.connect(self.search_mcscans)
        search_grid.addWidget(self.mcscans_search_button, 2, 5)

        self.mcscans_summary_label = QLabel("Search public MCScans data, then import results into local history or profiles.")
        search_grid.addWidget(self.mcscans_summary_label, 3, 1, 1, 5)
        layout.addLayout(search_grid)
        self.update_mcscans_pagination_controls()

        result_controls = QHBoxLayout()
        self.mcscans_import_selected_button = QPushButton("Import Selected")
        self.mcscans_import_selected_button.clicked.connect(self.import_selected_mcscans_results)
        result_controls.addWidget(self.mcscans_import_selected_button)

        self.mcscans_import_all_button = QPushButton("Import All Results")
        self.mcscans_import_all_button.clicked.connect(self.import_all_mcscans_results)
        result_controls.addWidget(self.mcscans_import_all_button)

        self.mcscans_copy_button = QPushButton("Copy Addresses")
        self.mcscans_copy_button.clicked.connect(self.copy_mcscans_addresses)
        result_controls.addWidget(self.mcscans_copy_button)

        self.mcscans_profile_name_input = QLineEdit()
        self.mcscans_profile_name_input.setPlaceholderText("Target profile name")
        result_controls.addWidget(self.mcscans_profile_name_input, 1)

        self.mcscans_profile_button = QPushButton("Create Target Profile")
        self.mcscans_profile_button.clicked.connect(self.create_mcscans_target_profile)
        result_controls.addWidget(self.mcscans_profile_button)
        layout.addLayout(result_controls)

        self.mcscans_table = QTableWidget(0, len(self.MCSCANS_COLUMNS))
        self.mcscans_table.setHorizontalHeaderLabels(self.MCSCANS_COLUMNS)
        self.mcscans_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.mcscans_table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.mcscans_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.mcscans_table.horizontalHeader().setSectionResizeMode(9, QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.mcscans_table)

        dataset_controls = QHBoxLayout()
        self.mcscans_dataset_refresh_button = QPushButton("Refresh Datasets")
        self.mcscans_dataset_refresh_button.clicked.connect(self.refresh_mcscans_datasets)
        dataset_controls.addWidget(self.mcscans_dataset_refresh_button)

        self.mcscans_copy_dataset_url_button = QPushButton("Copy Dataset URL")
        self.mcscans_copy_dataset_url_button.clicked.connect(self.copy_selected_mcscans_dataset_url)
        dataset_controls.addWidget(self.mcscans_copy_dataset_url_button)

        self.mcscans_copy_latest_zmap_button = QPushButton("Copy Latest Zmap URL")
        self.mcscans_copy_latest_zmap_button.clicked.connect(self.copy_latest_mcscans_zmap_url)
        dataset_controls.addWidget(self.mcscans_copy_latest_zmap_button)

        self.mcscans_dataset_summary_label = QLabel("Dataset files can be very large; URLs are copied for intentional downloads.")
        dataset_controls.addWidget(self.mcscans_dataset_summary_label, 1)
        layout.addLayout(dataset_controls)

        self.mcscans_dataset_table = QTableWidget(0, len(self.MCSCANS_DATASET_COLUMNS))
        self.mcscans_dataset_table.setHorizontalHeaderLabels(self.MCSCANS_DATASET_COLUMNS)
        self.mcscans_dataset_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.mcscans_dataset_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.mcscans_dataset_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.mcscans_dataset_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.mcscans_dataset_table)
        return page

    def _build_history_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        controls = QHBoxLayout()
        self.refresh_history_button = QPushButton("Refresh")
        self.refresh_history_button.clicked.connect(self.refresh_history)
        controls.addWidget(self.refresh_history_button)
        self.load_run_button = QPushButton("Load Selected Run")
        self.load_run_button.clicked.connect(self.load_selected_run)
        controls.addWidget(self.load_run_button)
        self.export_run_csv_button = QPushButton("Export Run CSV")
        self.export_run_csv_button.clicked.connect(lambda: self.export_selected_run("csv"))
        controls.addWidget(self.export_run_csv_button)
        self.export_run_json_button = QPushButton("Export Run JSON")
        self.export_run_json_button.clicked.connect(lambda: self.export_selected_run("json"))
        controls.addWidget(self.export_run_json_button)
        controls.addStretch()
        layout.addLayout(controls)

        self.history_table = QTableWidget(0, len(self.RUN_COLUMNS))
        self.history_table.setHorizontalHeaderLabels(self.RUN_COLUMNS)
        self.history_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.history_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.history_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.history_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.history_table)
        return page

    def _build_profiles_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        controls = QHBoxLayout()
        self.profile_refresh_button = QPushButton("Refresh")
        self.profile_refresh_button.clicked.connect(self.refresh_profiles)
        controls.addWidget(self.profile_refresh_button)
        self.profile_apply_button = QPushButton("Apply Selected")
        self.profile_apply_button.clicked.connect(self.apply_selected_profile_from_table)
        controls.addWidget(self.profile_apply_button)
        self.profile_delete_button = QPushButton("Delete Selected")
        self.profile_delete_button.clicked.connect(self.delete_selected_profile)
        controls.addWidget(self.profile_delete_button)
        self.profile_save_current_button = QPushButton("Save Current Scan Settings")
        self.profile_save_current_button.clicked.connect(self.save_current_profile)
        controls.addWidget(self.profile_save_current_button)
        controls.addStretch()
        layout.addLayout(controls)

        self.profiles_table = QTableWidget(0, len(self.PROFILE_COLUMNS))
        self.profiles_table.setHorizontalHeaderLabels(self.PROFILE_COLUMNS)
        self.profiles_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.profiles_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.profiles_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.profiles_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.profiles_table)
        return page

    def _build_settings_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.addWidget(QLabel(f"Version: {__version__}"))
        layout.addWidget(QLabel(f"Database: {self.database.path}"))
        layout.addWidget(QLabel("Public-range warning is shown before scans that include non-private IP ranges."))
        layout.addStretch()
        return page

    def targets_changed_connections(self) -> None:
        self.target_input.textChanged.connect(self.update_warning_label)
        self.ports_input.textChanged.connect(self.update_warning_label)
        self.edition_combo.currentIndexChanged.connect(self.update_warning_label)

    def collect_settings(self) -> ScanSettings:
        return ScanSettings(
            target_spec=self.target_input.toPlainText().strip(),
            ports=self.ports_input.text().strip(),
            edition=str(self.edition_combo.currentData()),
            timeout=float(self.timeout_spin.value()),
            concurrency=int(self.concurrency_spin.value()),
            retries=int(self.retries_spin.value()),
            min_players=int(self.min_players_spin.value()),
            only_online=self.only_online_check.isChecked(),
        )

    def apply_settings(self, settings: ScanSettings) -> None:
        self.target_input.setPlainText(settings.target_spec)
        self.ports_input.setText(settings.ports)
        idx = self.edition_combo.findData(settings.edition)
        if idx >= 0:
            self.edition_combo.setCurrentIndex(idx)
        self.timeout_spin.setValue(settings.timeout)
        self.concurrency_spin.setValue(settings.concurrency)
        self.retries_spin.setValue(settings.retries)
        self.min_players_spin.setValue(settings.min_players)
        self.only_online_check.setChecked(settings.only_online)
        self.update_warning_label()

    def import_targets_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Import Targets", "", "Text Files (*.txt);;All Files (*.*)")
        if path:
            existing = self.target_input.toPlainText().strip()
            suffix = f"@{path}"
            self.target_input.setPlainText(f"{existing}\n{suffix}" if existing else suffix)

    def update_warning_label(self) -> None:
        try:
            self.warning_label.setText(PRIVATE_TARGET_WARNING if contains_public_targets(self.target_input.toPlainText()) else "")
        except ValueError:
            self.warning_label.setText("")

    def start_scan(self) -> None:
        if self.worker and self.worker.isRunning():
            QMessageBox.information(self, "Scan Running", "A scan is already running.")
            return
        settings = self.collect_settings()
        try:
            validate_scan_settings(settings)
        except ValueError as exc:
            QMessageBox.warning(self, "Invalid Scan Settings", str(exc))
            return

        if contains_public_targets(settings.target_spec):
            response = QMessageBox.question(
                self,
                "Public Range Warning",
                PRIVATE_TARGET_WARNING + "\n\nContinue?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if response != QMessageBox.StandardButton.Yes:
                return

        self.results = []
        self.current_run_id = None
        self.refresh_results_table()
        self.log_view.clear()
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.progress.setValue(0)
        self.set_status("Scanning...")
        self.tabs.setCurrentIndex(0)

        self.worker = ScannerWorker(self.database.path, settings, self.current_profile_id)
        self.worker_mode = "manual"
        self.worker.result_signal.connect(self.handle_result)
        self.worker.progress_signal.connect(self.handle_progress)
        self.worker.log_signal.connect(self.append_log)
        self.worker.done_signal.connect(self.scan_done)
        self.worker.error_signal.connect(self.scan_error)
        self.worker.start()

    def stop_scan(self) -> None:
        if self.worker and self.worker.isRunning():
            self.worker.stop()
            self.stop_button.setEnabled(False)
            self.set_status("Stopping scan...")

    def handle_result(self, result: ServerResult) -> None:
        self.current_run_id = result.scan_run_id
        self.results.append(result)
        self.refresh_results_table()

    def handle_progress(self, completed: int, total: int, found: int) -> None:
        self.progress.setRange(0, max(total, 1))
        self.progress.setValue(min(completed, total))
        self.set_status(f"Scanned {completed}/{total}; found {found}.")

    def scan_done(self, run_id: int, completed: int, found: int, status: str) -> None:
        self.worker_mode = None
        self.current_run_id = run_id
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.refresh_history()
        self.set_status(f"Scan {status}: {completed} checked, {found} found.")
        self.tabs.setCurrentWidget(self.tabs.widget(1))

    def scan_error(self, message: str) -> None:
        self.worker_mode = None
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        QMessageBox.warning(self, "Scan Failed", message)
        self.set_status("Scan failed.")
        self.refresh_history()

    def append_log(self, message: str) -> None:
        self.log_view.append(message)

    def refresh_results_table(self) -> None:
        selected_id = self.selected_result_id()
        filtered = self.filtered_results()
        self.results_table.setRowCount(0)
        for result in filtered:
            row = self.results_table.rowCount()
            self.results_table.insertRow(row)
            result_id = getattr(result, "id", None)
            values = [
                "*" if result.favorite else "",
                result.host,
                str(result.port),
                result.edition,
                result.version,
                "" if result.protocol is None else str(result.protocol),
                result.players_display,
                "" if result.latency_ms is None else f"{result.latency_ms:.1f} ms",
                result.motd,
                result.notes,
            ]
            for col, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setData(Qt.ItemDataRole.UserRole, result_id)
                self.results_table.setItem(row, col, item)
        if selected_id is not None:
            self.select_result_id(selected_id)

    def filtered_results(self) -> List[ServerResult]:
        needle = self.filter_input.text().strip().lower() if hasattr(self, "filter_input") else ""
        min_players = self.min_players_spin.value() if hasattr(self, "min_players_spin") else 0
        only_online = self.only_online_check.isChecked() if hasattr(self, "only_online_check") else False
        favorites_only = self.favorites_only_check.isChecked() if hasattr(self, "favorites_only_check") else False
        matches: List[ServerResult] = []
        for result in self.results:
            online = result.players_online or 0
            if only_online and online <= 0:
                continue
            if online < min_players:
                continue
            if favorites_only and not result.favorite:
                continue
            haystack = " ".join(
                [result.host, result.edition, result.version, result.motd, result.notes]
            ).lower()
            if needle and needle not in haystack:
                continue
            matches.append(result)
        return matches

    def selected_result_id(self) -> Optional[int]:
        selected = self.results_table.selectedItems() if hasattr(self, "results_table") else []
        if not selected:
            return None
        value = selected[0].data(Qt.ItemDataRole.UserRole)
        return int(value) if value is not None else None

    def select_result_id(self, result_id: int) -> None:
        for row in range(self.results_table.rowCount()):
            item = self.results_table.item(row, 0)
            if item and item.data(Qt.ItemDataRole.UserRole) == result_id:
                self.results_table.selectRow(row)
                return

    def selected_result(self) -> Optional[ServerResult]:
        result_id = self.selected_result_id()
        if result_id is None:
            return None
        for result in self.results:
            if getattr(result, "id", None) == result_id:
                return result
        return None

    def load_selected_result_details(self) -> None:
        result = self.selected_result()
        if result:
            self.notes_input.setText(result.notes)

    def toggle_selected_favorite(self) -> None:
        result = self.selected_result()
        if not result:
            return
        result.favorite = not result.favorite
        result_id = getattr(result, "id", None)
        if result_id:
            self.database.update_result_flags(result_id, result.favorite, result.notes)
        self.refresh_results_table()

    def save_selected_notes(self) -> None:
        result = self.selected_result()
        if not result:
            return
        result.notes = self.notes_input.text()
        result_id = getattr(result, "id", None)
        if result_id:
            self.database.update_result_flags(result_id, result.favorite, result.notes)
        self.refresh_results_table()

    def copy_addresses(self) -> None:
        addresses = [result.address for result in self.filtered_results()]
        QApplication.clipboard().setText("\n".join(addresses))
        self.set_status(f"Copied {len(addresses)} address(es).")

    def export_current_csv(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Export Results CSV", "servers.csv", "CSV Files (*.csv)")
        if path:
            export_results_csv(Path(path), self.filtered_results())
            self.set_status(f"Exported CSV to {path}")

    def export_current_json(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Export Results JSON", "servers.json", "JSON Files (*.json)")
        if path:
            export_results_json(Path(path), self.filtered_results())
            self.set_status(f"Exported JSON to {path}")

    def refresh_history(self) -> None:
        if not hasattr(self, "history_table"):
            return
        runs = self.database.list_runs()
        self.history_table.setRowCount(0)
        for run in runs:
            row = self.history_table.rowCount()
            self.history_table.insertRow(row)
            values = [
                str(run.id or ""),
                run.started_at,
                run.status,
                run.settings.target_spec,
                run.settings.ports,
                run.settings.edition,
                f"{run.completed_targets}/{run.total_targets}",
                str(run.found_count),
            ]
            for col, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setData(Qt.ItemDataRole.UserRole, run.id)
                self.history_table.setItem(row, col, item)

    def start_monitor(self) -> None:
        profile = self.selected_monitor_profile()
        if profile is None:
            QMessageBox.warning(self, "Start Monitor", "Save or select a scan profile first.")
            return
        try:
            validate_scan_settings(profile.settings)
        except ValueError as exc:
            QMessageBox.warning(self, "Start Monitor", str(exc))
            return
        if contains_public_targets(profile.settings.target_spec):
            response = QMessageBox.question(
                self,
                "Public Range Warning",
                PRIVATE_TARGET_WARNING + "\n\nContinue monitoring this profile?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if response != QMessageBox.StandardButton.Yes:
                return

        self.monitor_active_profile_id = profile.id
        self.monitor_previous_run_id = None
        self.monitor_previous_results = []
        self.monitor_current_results = []
        self.monitor_known_identities = set()
        self.monitor_state = "running"
        self.monitor_summary_label.setText("Starting baseline scan...")
        self.append_monitor_log(f"Started monitor for profile {profile.name}.")
        self.update_monitor_controls()
        self.start_monitor_cycle()

    def toggle_monitor_pause(self) -> None:
        if self.monitor_state == "running":
            self.monitor_state = "paused"
            self.monitor_pause_button.setText("Resume")
            self.append_monitor_log("Monitor paused.")
        elif self.monitor_state == "paused":
            self.monitor_state = "running"
            self.monitor_pause_button.setText("Pause")
            self.schedule_next_monitor_run()
            self.append_monitor_log("Monitor resumed.")
        self.update_monitor_controls()

    def stop_monitor(self) -> None:
        if self.worker_mode == "monitor" and self.worker and self.worker.isRunning():
            self.worker.stop()
        self.monitor_state = "stopped"
        self.monitor_next_scan_at = None
        self.monitor_pause_button.setText("Pause")
        self.append_monitor_log("Monitor stopped.")
        self.update_monitor_controls()

    def start_monitor_cycle(self) -> bool:
        if self.monitor_state not in {"running", "scanning"}:
            return False
        if self.worker and self.worker.isRunning():
            self.append_monitor_log("Skipped monitor tick because a scan is already running.")
            self.schedule_next_monitor_run()
            return False

        profile = self.profile_by_id(int(self.monitor_active_profile_id or self.monitor_profile_combo.currentData() or 0))
        if profile is None:
            self.monitor_state = "stopped"
            self.update_monitor_controls()
            QMessageBox.warning(self, "Start Monitor", "Selected monitor profile no longer exists.")
            return False

        self.monitor_active_profile_id = profile.id
        self.monitor_current_results = []
        self.monitor_state = "scanning"
        self.monitor_next_scan_at = None
        self.monitor_progress.setRange(0, 1)
        self.monitor_progress.setValue(0)
        self.monitor_summary_label.setText("Scanning...")
        self.update_monitor_controls()
        self.append_monitor_log(f"Monitor scan started for {profile.name}.")

        self.worker = ScannerWorker(self.database.path, profile.settings, profile.id)
        self.worker_mode = "monitor"
        self.worker.result_signal.connect(self.handle_monitor_result)
        self.worker.progress_signal.connect(self.handle_monitor_progress)
        self.worker.log_signal.connect(self.append_monitor_log)
        self.worker.done_signal.connect(self.monitor_scan_done)
        self.worker.error_signal.connect(self.monitor_scan_error)
        self.worker.start()
        return True

    def handle_monitor_result(self, result: ServerResult) -> None:
        self.monitor_current_results.append(result)

    def handle_monitor_progress(self, completed: int, total: int, found: int) -> None:
        self.monitor_progress.setRange(0, max(total, 1))
        self.monitor_progress.setValue(min(completed, total))
        self.monitor_summary_label.setText(f"Scanning {completed}/{total}; found {found}.")

    def monitor_scan_done(self, run_id: int, completed: int, found: int, status: str) -> None:
        self.worker_mode = None
        current_results = self.database.list_results(run_id)
        self.results = current_results
        self.current_run_id = run_id
        self.refresh_results_table()
        self.refresh_history()

        if status == "completed":
            alerts = alerts_for_monitor_cycle(
                self.monitor_previous_results,
                current_results,
                profile_id=self.monitor_active_profile_id,
                previous_run_id=self.monitor_previous_run_id,
                current_run_id=run_id,
                known_identities=self.monitor_known_identities,
            )
            saved_alerts = self.database.add_monitor_alerts(alerts)
            if self.monitor_previous_run_id is None:
                self.monitor_summary_label.setText(f"Baseline captured: {found} server(s).")
                self.append_monitor_log(f"Baseline captured from run {run_id}; no alerts created.")
            else:
                self.monitor_summary_label.setText(f"Run {run_id}: {len(saved_alerts)} alert(s), {found} server(s).")
                self.append_monitor_log(f"Run {run_id} completed with {len(saved_alerts)} alert(s).")
            self.monitor_previous_run_id = run_id
            self.monitor_previous_results = current_results
            self.monitor_known_identities.update(identities_for(current_results))
            self.refresh_monitor_alerts()
        else:
            self.monitor_summary_label.setText(f"Monitor scan {status}: {completed} checked, {found} found.")
            self.append_monitor_log(f"Monitor scan {status}; comparison skipped.")

        if self.monitor_state == "scanning":
            self.monitor_state = "running"
            self.schedule_next_monitor_run()
        self.update_monitor_controls()

    def monitor_scan_error(self, message: str) -> None:
        self.worker_mode = None
        self.append_monitor_log(f"Monitor scan failed: {message}")
        if self.monitor_state == "scanning":
            self.monitor_state = "running"
            self.schedule_next_monitor_run()
        self.update_monitor_controls()

    def monitor_tick(self) -> None:
        if self.monitor_state == "running":
            if self.monitor_next_scan_at is None:
                self.schedule_next_monitor_run()
            remaining = int((self.monitor_next_scan_at - datetime.now()).total_seconds()) if self.monitor_next_scan_at else 0
            if remaining <= 0:
                self.start_monitor_cycle()
            else:
                self.monitor_next_label.setText(f"Next run: {self.format_seconds(remaining)}")
        elif self.monitor_state == "scanning":
            self.monitor_next_label.setText("Next run: scanning now")
        elif self.monitor_state == "paused":
            self.monitor_next_label.setText("Next run: paused")
        else:
            self.monitor_next_label.setText("Next run: --")
        self.monitor_state_label.setText(f"State: {self.monitor_state}")

    def schedule_next_monitor_run(self) -> None:
        seconds = int(self.monitor_interval_combo.currentData() or 300)
        self.monitor_next_scan_at = datetime.now() + timedelta(seconds=seconds)
        self.monitor_next_label.setText(f"Next run: {self.format_seconds(seconds)}")

    def update_monitor_controls(self) -> None:
        active = self.monitor_state != "stopped"
        self.monitor_start_button.setEnabled(not active)
        self.monitor_pause_button.setEnabled(self.monitor_state in {"running", "paused"})
        self.monitor_stop_button.setEnabled(active)
        self.monitor_profile_combo.setEnabled(not active)
        self.monitor_interval_combo.setEnabled(not active)
        self.monitor_state_label.setText(f"State: {self.monitor_state}")
        if self.monitor_state != "paused":
            self.monitor_pause_button.setText("Pause")

    def selected_monitor_profile(self) -> Optional[ScanProfile]:
        profile_id = self.monitor_profile_combo.currentData() if hasattr(self, "monitor_profile_combo") else None
        if profile_id is None:
            return None
        return self.profile_by_id(int(profile_id))

    def refresh_monitor_alerts(self) -> None:
        if not hasattr(self, "monitor_alert_table"):
            return
        self.monitor_alerts = self.database.list_monitor_alerts(limit=500)
        self.monitor_alert_table.setRowCount(0)
        for alert in self.monitor_alerts:
            row = self.monitor_alert_table.rowCount()
            self.monitor_alert_table.insertRow(row)
            values = [
                "yes" if alert.acknowledged else "",
                alert.created_at,
                alert.event_type,
                f"{alert.host}:{alert.port} ({alert.edition})",
                alert.before_value,
                alert.after_value,
                str(alert.current_run_id),
            ]
            for col, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setData(Qt.ItemDataRole.UserRole, alert.id)
                item.setData(self.MONITOR_RUN_ROLE, alert.current_run_id)
                self.monitor_alert_table.setItem(row, col, item)

    def selected_monitor_alert(self) -> Optional[MonitorAlert]:
        selected = self.monitor_alert_table.selectedItems() if hasattr(self, "monitor_alert_table") else []
        if not selected:
            return None
        alert_id = selected[0].data(Qt.ItemDataRole.UserRole)
        for alert in self.monitor_alerts:
            if alert.id == alert_id:
                return alert
        return None

    def acknowledge_selected_monitor_alert(self) -> None:
        alert = self.selected_monitor_alert()
        if alert and alert.id is not None:
            self.database.acknowledge_monitor_alert(alert.id)
            self.refresh_monitor_alerts()
            self.set_status("Monitor alert acknowledged.")

    def acknowledge_all_monitor_alerts(self) -> None:
        self.database.acknowledge_all_monitor_alerts()
        self.refresh_monitor_alerts()
        self.set_status("All monitor alerts acknowledged.")

    def load_monitor_alert_run(self) -> None:
        alert = self.selected_monitor_alert()
        if not alert:
            return
        self.results = self.database.list_results(alert.current_run_id)
        self.current_run_id = alert.current_run_id
        self.refresh_results_table()
        self.tabs.setCurrentWidget(self.tabs.widget(1))
        self.set_status(f"Loaded monitor run {alert.current_run_id}.")

    def copy_monitor_alert_address(self) -> None:
        alert = self.selected_monitor_alert()
        if not alert:
            return
        QApplication.clipboard().setText(alert.address)
        self.set_status(f"Copied {alert.address}.")

    def append_monitor_log(self, message: str) -> None:
        if hasattr(self, "monitor_log_view"):
            self.monitor_log_view.append(message)

    @staticmethod
    def format_seconds(total_seconds: int) -> str:
        minutes, seconds = divmod(max(0, total_seconds), 60)
        if minutes:
            return f"{minutes}m {seconds:02d}s"
        return f"{seconds}s"

    def search_mcscans(self) -> None:
        if self.mcscans_search_worker and self.mcscans_search_worker.isRunning():
            self.set_status("MCScans search is already running.")
            return
        params = {
            "query": self.mcscans_query_input.text().strip(),
            "edition": self.mcscans_edition_combo.currentText(),
            "software": self.mcscans_software_input.text().strip(),
            "version": self.mcscans_version_input.text().strip(),
            "sort": str(self.mcscans_sort_combo.currentData() or ""),
            "live": True if self.mcscans_live_check.isChecked() else None,
            "page": self.mcscans_page_spin.value(),
        }
        self.mcscans_search_button.setEnabled(False)
        self.mcscans_prev_page_button.setEnabled(False)
        self.mcscans_next_page_button.setEnabled(False)
        self.mcscans_summary_label.setText("Searching MCScans...")
        self.mcscans_search_worker = McScansSearchWorker(params)
        self.mcscans_search_worker.result_signal.connect(self.handle_mcscans_results)
        self.mcscans_search_worker.error_signal.connect(self.handle_mcscans_error)
        self.mcscans_search_worker.finished.connect(self.finish_mcscans_search)
        self.mcscans_search_worker.start()

    def handle_mcscans_results(self, search_result) -> None:
        self.mcscans_results = search_result.servers
        self.mcscans_total_servers = search_result.total_servers
        if self.mcscans_total_servers is None:
            self.mcscans_total_pages = max(1, self.mcscans_page_spin.value())
        else:
            self.mcscans_total_pages = max(
                1,
                (self.mcscans_total_servers + search_result.page_size - 1) // search_result.page_size,
            )
        self.mcscans_page_spin.setRange(1, max(self.mcscans_total_pages, search_result.page))
        self.mcscans_page_spin.setValue(search_result.page)
        self.refresh_mcscans_results_table()
        total = "unknown" if search_result.total_servers is None else f"{search_result.total_servers:,}"
        suffix = " More results available via cursor." if search_result.has_more else ""
        self.mcscans_summary_label.setText(
            f"Page {search_result.page:,} of {self.mcscans_total_pages:,}; "
            f"showing {len(self.mcscans_results)} result(s) at {search_result.page_size} per page; "
            f"total reported: {total}.{suffix}"
        )
        self.set_status("MCScans search completed.")

    def handle_mcscans_error(self, message: str) -> None:
        self.mcscans_summary_label.setText(f"MCScans error: {message}")
        QMessageBox.warning(self, "MCScans", message)

    def finish_mcscans_search(self) -> None:
        self.mcscans_search_button.setEnabled(True)
        self.update_mcscans_pagination_controls()

    def previous_mcscans_page(self) -> None:
        if self.mcscans_page_spin.value() <= 1:
            return
        self.mcscans_page_spin.setValue(self.mcscans_page_spin.value() - 1)
        self.search_mcscans()

    def next_mcscans_page(self) -> None:
        if self.mcscans_total_servers is not None and self.mcscans_page_spin.value() >= self.mcscans_total_pages:
            return
        self.mcscans_page_spin.setValue(self.mcscans_page_spin.value() + 1)
        self.search_mcscans()

    def update_mcscans_pagination_controls(self) -> None:
        if not hasattr(self, "mcscans_prev_page_button"):
            return
        current_page = self.mcscans_page_spin.value()
        searching = bool(self.mcscans_search_worker and self.mcscans_search_worker.isRunning())
        self.mcscans_prev_page_button.setEnabled(not searching and current_page > 1)
        has_next = current_page < self.mcscans_total_pages if self.mcscans_total_servers is not None else bool(self.mcscans_results)
        self.mcscans_next_page_button.setEnabled(not searching and has_next)

    def refresh_mcscans_results_table(self) -> None:
        self.mcscans_table.setRowCount(0)
        for index, server in enumerate(self.mcscans_results):
            row = self.mcscans_table.rowCount()
            self.mcscans_table.insertRow(row)
            values = [
                server.host,
                str(server.port),
                server.edition,
                server.version,
                server.software,
                f"{server.players_online if server.players_online is not None else ''}/{server.players_max if server.players_max is not None else ''}".strip("/"),
                "" if server.protocol is None else str(server.protocol),
                "" if server.is_live is None else ("yes" if server.is_live else "no"),
                server.country,
                server.motd_normalized or server.motd,
            ]
            for col, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setData(Qt.ItemDataRole.UserRole, index)
                self.mcscans_table.setItem(row, col, item)

    def selected_mcscans_servers(self) -> List[McScansServer]:
        selected_rows = sorted({item.row() for item in self.mcscans_table.selectedItems()})
        servers: List[McScansServer] = []
        for row in selected_rows:
            item = self.mcscans_table.item(row, 0)
            if item is None:
                continue
            index = item.data(Qt.ItemDataRole.UserRole)
            if index is not None and 0 <= int(index) < len(self.mcscans_results):
                servers.append(self.mcscans_results[int(index)])
        return servers

    def import_selected_mcscans_results(self) -> None:
        self.import_mcscans_servers(self.selected_mcscans_servers(), "selected")

    def import_all_mcscans_results(self) -> None:
        self.import_mcscans_servers(self.mcscans_results, "search results")

    def import_mcscans_servers(self, servers: List[McScansServer], label: str) -> None:
        if not servers:
            QMessageBox.information(self, "MCScans Import", "No MCScans results selected.")
            return
        run_id, count = self.database.import_server_results(f"MCScans {label}", [server.to_server_result() for server in servers])
        self.results = self.database.list_results(run_id)
        self.current_run_id = run_id
        self.refresh_results_table()
        self.refresh_history()
        self.tabs.setCurrentWidget(self.tabs.widget(1))
        self.set_status(f"Imported {count} MCScans result(s) into run {run_id}.")

    def copy_mcscans_addresses(self) -> None:
        servers = self.selected_mcscans_servers() or self.mcscans_results
        QApplication.clipboard().setText("\n".join(server.address for server in servers))
        self.set_status(f"Copied {len(servers)} MCScans address(es).")

    def create_mcscans_target_profile(self) -> None:
        servers = self.selected_mcscans_servers() or self.mcscans_results
        if not servers:
            QMessageBox.information(self, "MCScans Profile", "Search or select MCScans results first.")
            return
        name = self.mcscans_profile_name_input.text().strip() or "MCScans Targets"
        target_spec = "\n".join(server.host for server in servers)
        ports = ",".join(str(port) for port in sorted({server.port for server in servers}))
        editions = sorted({server.edition for server in servers})
        edition = editions[0] if len(editions) == 1 else "both"
        profile = self.database.save_profile(
            ScanProfile(
                name=name,
                settings=ScanSettings(
                    target_spec=target_spec,
                    ports=ports or "25565",
                    edition=edition,
                    timeout=3.0,
                    concurrency=64,
                    retries=0,
                ),
            )
        )
        self.refresh_profiles()
        self.set_status(f"Created profile {profile.name} from {len(servers)} MCScans target(s).")

    def refresh_mcscans_datasets(self) -> None:
        if self.mcscans_datasets_worker and self.mcscans_datasets_worker.isRunning():
            self.set_status("MCScans dataset refresh is already running.")
            return
        self.mcscans_dataset_refresh_button.setEnabled(False)
        self.mcscans_dataset_summary_label.setText("Loading MCScans datasets...")
        self.mcscans_datasets_worker = McScansDatasetsWorker()
        self.mcscans_datasets_worker.result_signal.connect(self.handle_mcscans_datasets)
        self.mcscans_datasets_worker.error_signal.connect(self.handle_mcscans_error)
        self.mcscans_datasets_worker.finished.connect(lambda: self.mcscans_dataset_refresh_button.setEnabled(True))
        self.mcscans_datasets_worker.start()

    def handle_mcscans_datasets(self, datasets: List[McScansDataset]) -> None:
        self.mcscans_dataset_files = [file for dataset in datasets for file in dataset.files]
        self.refresh_mcscans_dataset_table()
        zmap_count = len(dataset_target_files(datasets))
        self.mcscans_dataset_summary_label.setText(
            f"Loaded {len(datasets)} dataset(s), {len(self.mcscans_dataset_files)} file(s), {zmap_count} target-list file(s)."
        )
        self.set_status("MCScans datasets loaded.")

    def refresh_mcscans_dataset_table(self) -> None:
        self.mcscans_dataset_table.setRowCount(0)
        for index, file in enumerate(self.mcscans_dataset_files):
            row = self.mcscans_dataset_table.rowCount()
            self.mcscans_dataset_table.insertRow(row)
            values = [
                file.dataset_id,
                file.name,
                self.format_bytes(file.size),
                "" if file.lines is None else f"{file.lines:,}",
                file.modified_at,
                file.download_url,
            ]
            for col, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setData(Qt.ItemDataRole.UserRole, index)
                self.mcscans_dataset_table.setItem(row, col, item)

    def selected_mcscans_dataset_file(self) -> Optional[McScansDatasetFile]:
        selected = self.mcscans_dataset_table.selectedItems()
        if not selected:
            return None
        index = selected[0].data(Qt.ItemDataRole.UserRole)
        if index is None:
            return None
        index = int(index)
        if 0 <= index < len(self.mcscans_dataset_files):
            return self.mcscans_dataset_files[index]
        return None

    def copy_selected_mcscans_dataset_url(self) -> None:
        file = self.selected_mcscans_dataset_file()
        if not file:
            QMessageBox.information(self, "MCScans Datasets", "Select a dataset file first.")
            return
        QApplication.clipboard().setText(file.download_url)
        self.set_status(f"Copied {file.name} URL.")

    def copy_latest_mcscans_zmap_url(self) -> None:
        files = [file for file in self.mcscans_dataset_files if "zmap" in file.name.lower()]
        if not files:
            QMessageBox.information(self, "MCScans Datasets", "Refresh datasets first.")
            return
        QApplication.clipboard().setText(files[0].download_url)
        self.set_status(f"Copied latest zmap URL: {files[0].name}.")

    @staticmethod
    def format_bytes(size: int) -> str:
        value = float(size)
        for unit in ("B", "KB", "MB", "GB"):
            if value < 1024 or unit == "GB":
                return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
            value /= 1024
        return f"{size} B"

    def selected_run_id(self) -> Optional[int]:
        selected = self.history_table.selectedItems() if hasattr(self, "history_table") else []
        if not selected:
            return None
        value = selected[0].data(Qt.ItemDataRole.UserRole)
        return int(value) if value is not None else None

    def load_selected_run(self) -> None:
        run_id = self.selected_run_id()
        if run_id is None:
            return
        self.results = self.database.list_results(run_id)
        self.current_run_id = run_id
        self.refresh_results_table()
        self.tabs.setCurrentWidget(self.tabs.widget(1))
        self.set_status(f"Loaded scan run {run_id}.")

    def export_selected_run(self, kind: str) -> None:
        run_id = self.selected_run_id()
        if run_id is None:
            return
        results = self.database.list_results(run_id)
        if kind == "csv":
            path, _ = QFileDialog.getSaveFileName(self, "Export Run CSV", f"scan-{run_id}.csv", "CSV Files (*.csv)")
            if path:
                export_results_csv(Path(path), results)
        else:
            path, _ = QFileDialog.getSaveFileName(self, "Export Run JSON", f"scan-{run_id}.json", "JSON Files (*.json)")
            if path:
                export_results_json(Path(path), results)
        if path:
            self.set_status(f"Exported run {run_id} to {path}")

    def refresh_profiles(self) -> None:
        profiles = self.database.list_profiles()
        if hasattr(self, "profile_combo"):
            current = self.profile_combo.currentData()
            self.profile_combo.clear()
            for profile in profiles:
                self.profile_combo.addItem(profile.name, profile.id)
            if current is not None:
                idx = self.profile_combo.findData(current)
                if idx >= 0:
                    self.profile_combo.setCurrentIndex(idx)

        if hasattr(self, "monitor_profile_combo"):
            current = self.monitor_profile_combo.currentData()
            self.monitor_profile_combo.clear()
            for profile in profiles:
                self.monitor_profile_combo.addItem(profile.name, profile.id)
            if current is not None:
                idx = self.monitor_profile_combo.findData(current)
                if idx >= 0:
                    self.monitor_profile_combo.setCurrentIndex(idx)

        if hasattr(self, "profiles_table"):
            self.profiles_table.setRowCount(0)
            for profile in profiles:
                row = self.profiles_table.rowCount()
                self.profiles_table.insertRow(row)
                values = [
                    str(profile.id or ""),
                    profile.name,
                    profile.settings.target_spec,
                    profile.settings.ports,
                    profile.settings.edition,
                ]
                for col, value in enumerate(values):
                    item = QTableWidgetItem(value)
                    item.setData(Qt.ItemDataRole.UserRole, profile.id)
                    self.profiles_table.setItem(row, col, item)

    def selected_profile_id_from_table(self) -> Optional[int]:
        selected = self.profiles_table.selectedItems() if hasattr(self, "profiles_table") else []
        if not selected:
            return None
        value = selected[0].data(Qt.ItemDataRole.UserRole)
        return int(value) if value is not None else None

    def load_selected_profile(self) -> None:
        profile_id = self.profile_combo.currentData()
        if profile_id is None:
            return
        profile = self.profile_by_id(int(profile_id))
        if profile:
            self.apply_profile(profile)

    def apply_selected_profile_from_table(self) -> None:
        profile_id = self.selected_profile_id_from_table()
        if profile_id is None:
            return
        profile = self.profile_by_id(profile_id)
        if profile:
            self.apply_profile(profile)
            self.tabs.setCurrentIndex(0)

    def apply_profile(self, profile: ScanProfile) -> None:
        self.current_profile_id = profile.id
        self.profile_name_input.setText(profile.name)
        self.apply_settings(profile.settings)
        self.set_status(f"Loaded profile {profile.name}.")

    def profile_by_id(self, profile_id: int) -> Optional[ScanProfile]:
        for profile in self.database.list_profiles():
            if profile.id == profile_id:
                return profile
        return None

    def save_current_profile(self) -> None:
        name = self.profile_name_input.text().strip()
        if not name:
            QMessageBox.warning(self, "Save Profile", "Enter a profile name.")
            return
        settings = self.collect_settings()
        try:
            validate_scan_settings(settings)
        except ValueError as exc:
            QMessageBox.warning(self, "Save Profile", str(exc))
            return
        profile = ScanProfile(name=name, settings=settings, id=self.current_profile_id)
        saved = self.database.save_profile(profile)
        self.current_profile_id = saved.id
        self.refresh_profiles()
        self.set_status(f"Saved profile {saved.name}.")

    def delete_selected_profile(self) -> None:
        profile_id = self.selected_profile_id_from_table()
        if profile_id is None:
            return
        self.database.delete_profile(profile_id)
        if self.current_profile_id == profile_id:
            self.current_profile_id = None
        self.refresh_profiles()
        self.set_status("Deleted profile.")

    def set_status(self, message: str) -> None:
        self.statusBar().showMessage(message)

    def closeEvent(self, event) -> None:
        if hasattr(self, "monitor_timer"):
            self.monitor_timer.stop()
        if self.worker and self.worker.isRunning():
            self.worker.stop()
            self.worker.wait(3000)
        if self.mcscans_search_worker and self.mcscans_search_worker.isRunning():
            self.mcscans_search_worker.wait(3000)
        if self.mcscans_datasets_worker and self.mcscans_datasets_worker.isRunning():
            self.mcscans_datasets_worker.wait(3000)
        event.accept()


def apply_app_style(app: QApplication) -> None:
    app.setStyle("Fusion")
    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window, QColor(27, 29, 33))
    palette.setColor(QPalette.ColorRole.WindowText, QColor(238, 240, 243))
    palette.setColor(QPalette.ColorRole.Base, QColor(18, 20, 24))
    palette.setColor(QPalette.ColorRole.AlternateBase, QColor(35, 38, 44))
    palette.setColor(QPalette.ColorRole.Text, QColor(238, 240, 243))
    palette.setColor(QPalette.ColorRole.Button, QColor(43, 47, 54))
    palette.setColor(QPalette.ColorRole.ButtonText, QColor(238, 240, 243))
    palette.setColor(QPalette.ColorRole.Highlight, QColor(70, 130, 95))
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor(255, 255, 255))
    app.setPalette(palette)
    app.setStyleSheet(
        """
        QWidget { font-size: 12px; }
        QLineEdit, QPlainTextEdit, QTextEdit, QSpinBox, QDoubleSpinBox, QComboBox {
            padding: 5px;
            border: 1px solid #3b4048;
            border-radius: 4px;
            background: #121418;
            color: #eef0f3;
        }
        QPushButton {
            padding: 7px 12px;
            border: 1px solid #454b54;
            border-radius: 4px;
            background: #2b2f36;
            color: #eef0f3;
        }
        QPushButton:hover { background: #363b43; }
        QPushButton:disabled { color: #8a9099; background: #24272d; }
        QTableWidget {
            gridline-color: #343941;
            background: #121418;
            alternate-background-color: #181b20;
        }
        QHeaderView::section {
            padding: 5px;
            border: 0;
            border-right: 1px solid #343941;
            border-bottom: 1px solid #343941;
            background: #23272e;
        }
        QTabWidget::pane { border: 1px solid #343941; }
        QTabBar::tab {
            padding: 8px 12px;
            background: #23272e;
            border: 1px solid #343941;
            border-bottom: 0;
        }
        QTabBar::tab:selected { background: #2f483a; }
        """
    )
