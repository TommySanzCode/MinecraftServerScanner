import sys
import os
import socket
import threading
import queue
from datetime import datetime
from mcstatus import JavaServer
from PyQt6.QtWidgets import (QApplication, QMainWindow, QVBoxLayout, QHBoxLayout,
                            QPushButton, QListWidget, QLabel, QWidget, QLineEdit,
                            QSpinBox, QProgressBar, QMessageBox, QListWidgetItem, QTextEdit,
                            QMenu, QAbstractItemView, QFileDialog, QCheckBox, QComboBox)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer, QUrl, QProcess
from PyQt6.QtGui import QPalette, QColor, QKeySequence, QDesktopServices
from concurrent.futures import ThreadPoolExecutor, as_completed

class ScannerThread(QThread):
    update_signal = pyqtSignal(dict)
    progress_signal = pyqtSignal(int)
    log_signal = pyqtSignal(str)
    finished_signal = pyqtSignal()

    def __init__(self, ip_range, start_port, end_port, timeout=2, concurrency=64, ports_list=None):
        super().__init__()
        self.ip_range = ip_range
        self.start_port = start_port
        self.end_port = end_port
        self.timeout = timeout
        self.concurrency = concurrency
        self.ports_list = ports_list  # optional explicit list of ports
        self.running = True

    def run(self):
        targets = []
        for ip in self.generate_ips():
            if self.ports_list:
                for port in self.ports_list:
                    targets.append((ip, port))
            else:
                for port in range(self.start_port, self.end_port + 1):
                    targets.append((ip, port))

        processed = 0
        found_count = 0
        closed_count = 0
        total_targets = len(targets)

        def probe(ip, port):
            # Fast TCP check before expensive query for numeric IPv4 only.
            # For hostnames, skip precheck so SRV resolution can work.
            try:
                is_ipv4 = all(part.isdigit() and 0 <= int(part) <= 255 for part in ip.split('.') if part)
                if is_ipv4:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.settimeout(self.timeout)
                        if s.connect_ex((ip, port)) != 0:
                            return ('closed', ip, port)

                server = JavaServer.lookup(f"{ip}:{port}", timeout=self.timeout)
                status = server.status()
                motd_val = status.description
                if isinstance(motd_val, dict):
                    motd_val = motd_val.get('text', str(motd_val))

                return {
                    'ip': ip,
                    'port': port,
                    'version': status.version.name,
                    'players': f"{status.players.online}/{status.players.max}",
                    'ping': status.latency,
                    'motd': motd_val
                }
            except Exception as e:
                return ('error', f"{ip}:{port} - {type(e).__name__}: {e}")

        with ThreadPoolExecutor(max_workers=max(1, self.concurrency)) as executor:
            future_to_target = {executor.submit(probe, ip, port): (ip, port) for (ip, port) in targets}
            for future in as_completed(future_to_target):
                if not self.running:
                    break
                result = future.result()
                if isinstance(result, dict):
                    self.update_signal.emit(result)
                    self.log_signal.emit(f"FOUND {result['ip']}:{result['port']} - {result['version']} {result['players']} {result['ping']:.1f}ms")
                    found_count += 1
                elif isinstance(result, tuple) and result and result[0] == 'error':
                    self.log_signal.emit(f"ERROR {result[1]}")
                elif isinstance(result, tuple) and result and result[0] == 'closed':
                    closed_count += 1
                processed += 1
                self.progress_signal.emit(processed)
                # Periodic summary every 50 processed (and at end)
                if processed % 50 == 0 or processed == total_targets:
                    self.log_signal.emit(f"SCANNED {processed}/{total_targets} - found {found_count}, closed/filtered {closed_count}")

        self.finished_signal.emit()

    def stop(self):
        self.running = False

    def generate_ips(self):
        if '-' in self.ip_range:
            start, end = self.ip_range.split('-')
            return self.ip_range_generator(start.strip(), end.strip())
        else:
            return [self.ip_range]

    def ip_range_generator(self, start_ip, end_ip):
        start = list(map(int, start_ip.split('.')))
        end = list(map(int, end_ip.split('.')))
        temp = start.copy()
        
        while temp <= end:
            yield '.'.join(map(str, temp))
            
            temp[3] += 1
            for i in (3, 2, 1):
                if temp[i] == 256:
                    temp[i] = 0
                    temp[i-1] += 1

    def stop(self):
        self.running = False

class MinecraftScanner(QMainWindow):
    def __init__(self, autostart: bool = False, ip_range: str | None = None, port_start: int | None = None, port_end: int | None = None):
        super().__init__()
        self.scanner_thread = None
        self.all_servers = []  # store all found servers for filtering/export
        self.setup_ui()
        self.setWindowTitle("Minecraft Server Scanner")
        self.setMinimumSize(800, 600)
        # Apply provided defaults
        if ip_range:
            self.ip_input.setText(ip_range)
        if isinstance(port_start, int):
            self.port_start.setValue(port_start)
        if isinstance(port_end, int):
            self.port_end.setValue(port_end)
        # Optionally start scanning shortly after UI shows
        if autostart:
            QTimer.singleShot(200, self.start_scan)

    def setup_ui(self):
        # Main widget and layout
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout(main_widget)

        # IP Range Input
        ip_layout = QHBoxLayout()
        ip_layout.addWidget(QLabel("IP Range:"))
        self.ip_input = QLineEdit("192.168.1.1-192.168.1.255")
        self.ip_input.setPlaceholderText("e.g., 192.168.1.1 or 192.168.1.1-192.168.1.255")
        ip_layout.addWidget(self.ip_input)
        layout.addLayout(ip_layout)

        # Port Presets / Range / Timeout / Threads
        port_layout = QHBoxLayout()
        port_layout.addWidget(QLabel("Port Preset:"))
        self.port_preset = QComboBox()
        self.port_preset.addItems([
            "Minecraft Java (25565)",
            "Bedrock (19132,19133)",
            "Common (25500-25700)",
            "All (1024-65535)",
            "Custom"
        ])
        port_layout.addWidget(self.port_preset)

        port_layout.addSpacing(8)
        port_layout.addWidget(QLabel("Range:"))
        
        self.port_start = QSpinBox()
        self.port_start.setRange(1, 65535)
        self.port_start.setValue(25565)
        port_layout.addWidget(self.port_start)
        
        port_layout.addWidget(QLabel("to"))
        
        self.port_end = QSpinBox()
        self.port_end.setRange(1, 65535)
        self.port_end.setValue(25565)
        port_layout.addWidget(self.port_end)

        port_layout.addSpacing(8)
        port_layout.addWidget(QLabel("Custom:"))
        self.custom_ports = QLineEdit()
        self.custom_ports.setPlaceholderText("e.g. 25565,19132-19133,25500-25700")
        port_layout.addWidget(self.custom_ports)
        
        port_layout.addSpacing(12)
        port_layout.addWidget(QLabel("Timeout (s):"))
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(1, 30)
        self.timeout_spin.setValue(3)
        port_layout.addWidget(self.timeout_spin)

        port_layout.addSpacing(12)
        port_layout.addWidget(QLabel("Threads:"))
        self.threads_spin = QSpinBox()
        self.threads_spin.setRange(1, 256)
        self.threads_spin.setValue(64)
        port_layout.addWidget(self.threads_spin)
        
        port_layout.addStretch()
        layout.addLayout(port_layout)

        # React to preset changes to update range/custom UI
        self.port_preset.currentIndexChanged.connect(self.on_preset_change)
        self.on_preset_change()

        # Filters Row
        filters_layout = QHBoxLayout()
        filters_layout.addWidget(QLabel("Min Players:"))
        self.min_players_spin = QSpinBox()
        self.min_players_spin.setRange(0, 100000)
        self.min_players_spin.setValue(0)
        filters_layout.addWidget(self.min_players_spin)

        self.only_online_check = QCheckBox("Only Online (>0)")
        self.only_online_check.setChecked(False)
        filters_layout.addWidget(self.only_online_check)

        filters_layout.addStretch()
        layout.addLayout(filters_layout)
        # Refresh results when filters change
        self.min_players_spin.valueChanged.connect(self.refresh_results)
        self.only_online_check.stateChanged.connect(self.refresh_results)

        # Buttons
        button_layout = QHBoxLayout()
        
        self.scan_button = QPushButton("Start Scan")
        self.scan_button.clicked.connect(self.toggle_scan)
        button_layout.addWidget(self.scan_button)
        
        self.clear_button = QPushButton("Clear Results")
        self.clear_button.clicked.connect(self.clear_results)
        button_layout.addWidget(self.clear_button)

        self.copy_all_button = QPushButton("Copy All Addresses")
        self.copy_all_button.clicked.connect(self.copy_all_addresses)
        button_layout.addWidget(self.copy_all_button)

        self.export_csv_button = QPushButton("Export CSV")
        self.export_csv_button.clicked.connect(self.export_csv)
        button_layout.addWidget(self.export_csv_button)

        self.export_json_button = QPushButton("Export JSON")
        self.export_json_button.clicked.connect(self.export_json)
        button_layout.addWidget(self.export_json_button)

        self.export_targets_button = QPushButton("Export Targets")
        self.export_targets_button.clicked.connect(self.export_targets)
        button_layout.addWidget(self.export_targets_button)

        self.generate_cmds_button = QPushButton("Generate Commands")
        self.generate_cmds_button.clicked.connect(self.generate_external_commands)
        button_layout.addWidget(self.generate_cmds_button)

        self.test_button = QPushButton("Test Known Server")
        self.test_button.clicked.connect(self.test_known_server)
        button_layout.addWidget(self.test_button)
        
        layout.addLayout(button_layout)

        # Clear Logs button row (below the results controls)
        logs_button_layout = QHBoxLayout()
        self.clear_logs_button = QPushButton("Clear Logs")
        self.clear_logs_button.clicked.connect(self.clear_logs)
        logs_button_layout.addWidget(self.clear_logs_button)
        logs_button_layout.addStretch()
        layout.addLayout(logs_button_layout)

        # Progress Bar
        self.progress = QProgressBar()
        self.progress.setVisible(False)
        self.progress.setMinimum(0)
        self.progress.setValue(0)
        layout.addWidget(self.progress)

        # Results Table
        self.results_list = QListWidget()
        self.results_list.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.results_list.setStyleSheet("""
            QListWidget {
                background-color: #151515;
                color: #ffffff;
            }
            QListWidget::item {
                border-bottom: 1px solid #333;
                padding: 6px;
            }
            QListWidget::item:hover {
                background-color: #232323; /* keep contrast; do not white out */
                color: #ffffff;
            }
            QListWidget::item:selected { background-color: #2e3a2e; color: #ffffff; }
        """)
        # Context menu for copy actions
        self.results_list.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.results_list.customContextMenuRequested.connect(self.show_results_context_menu)
        layout.addWidget(self.results_list)

        # Log Panel
        self.log_view = QTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setStyleSheet("QTextEdit { font-family: Consolas, monospace; font-size: 11px; }")
        layout.addWidget(QLabel("Log:"))
        layout.addWidget(self.log_view)

        # Status Bar
        self.status_bar = self.statusBar()
        self.update_status("Ready")

    def toggle_scan(self):
        if self.scanner_thread and self.scanner_thread.isRunning():
            self.scan_button.setText("Stopping Scan...")
            self.scan_button.setEnabled(False)
            self.update_status("Stopping scan...")
            self.scanner_thread.stop()
        else:
            self.start_scan()

    def start_scan(self):
        ip_range = self.ip_input.text().strip()
        start_port = self.port_start.value()
        end_port = self.port_end.value()

        if not ip_range:
            QMessageBox.warning(self, "Error", "Please enter an IP range")
            return

        if start_port > end_port:
            QMessageBox.warning(self, "Error", "Start port cannot be greater than end port")
            return

        self.results_list.clear()
        self.all_servers = []
        self.scan_button.setText("Stop Scan")
        # Configure progress bar range
        total_ips = self.count_ips(ip_range)
        # Resolve ports based on preset/custom
        ports_list = self.resolve_ports_list(start_port, end_port)
        if not ports_list:
            QMessageBox.warning(self, "Error", "No ports resolved from the selected preset/custom range.")
            return
        total_ports = max(1, len(ports_list))
        total_targets = total_ips * total_ports
        self.total_targets = max(1, total_targets)
        self.progress.setRange(0, self.total_targets)
        self.progress.setValue(0)
        self.progress.setVisible(True)
        self.update_status(f"Scanning 0/{self.total_targets} targets...")

        self.scanner_thread = ScannerThread(
            ip_range,
            start_port,
            end_port,
            timeout=self.timeout_spin.value(),
            concurrency=self.threads_spin.value(),
            ports_list=ports_list
        )
        self.scanner_thread.update_signal.connect(self.add_server)
        self.scanner_thread.progress_signal.connect(self.update_progress)
        self.scanner_thread.log_signal.connect(self.append_log)
        self.scanner_thread.finished_signal.connect(self.scan_finished)
        self.scanner_thread.start()

    def expand_ips(self, ip_range: str):
        # Returns a generator over IPs in range, or single host (can be hostname)
        if '-' not in ip_range:
            yield ip_range.strip()
            return
        start, end = ip_range.split('-')
        start = start.strip()
        end = end.strip()
        try:
            s_parts = list(map(int, start.split('.')))
            e_parts = list(map(int, end.split('.')))
        except Exception:
            # Fallback: treat as single host if parsing fails
            yield ip_range.strip()
            return
        cur = s_parts[:]
        while cur <= e_parts:
            yield '.'.join(map(str, cur))
            cur[3] += 1
            for i in (3, 2, 1):
                if cur[i] == 256:
                    cur[i] = 0
                    cur[i-1] += 1

    def export_targets(self):
        ip_range = self.ip_input.text().strip()
        if not ip_range:
            QMessageBox.warning(self, "Export Targets", "Please enter an IP range.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export Targets", "targets.txt", "Text Files (*.txt)")
        if not path:
            return
        try:
            count = 0
            with open(path, 'w', encoding='utf-8') as f:
                for ip in self.expand_ips(ip_range):
                    f.write(ip + "\n")
                    count += 1
            self.update_status(f"Exported {count} target(s) to {path}")
        except Exception as e:
            QMessageBox.warning(self, "Export Targets", f"Failed to write targets: {e}")

    def generate_external_commands(self):
        ip_range = self.ip_input.text().strip()
        start_port = self.port_start.value()
        end_port = self.port_end.value()
        ports_list = self.resolve_ports_list(start_port, end_port)
        if not ip_range or not ports_list:
            QMessageBox.warning(self, "Generate Commands", "Please set an IP range and at least one port.")
            return
        ports_csv = ','.join(map(str, ports_list))
        targets_hint = "targets.txt"
        out_masscan = "masscan.json"
        out_nmap = "nmap.xml"
        out_csv = "mcscan.csv"
        # masscan
        masscan_cmd = (
            f"masscan -p{ports_csv} -iL {targets_hint} --rate 10000 --output-format json -oJ {out_masscan}"
        )
        # nmap
        nmap_cmd = (
            f"nmap -Pn -p {ports_csv} -iL {targets_hint} -oX {out_nmap}"
        )
        # PowerShell bulk mcstatus to CSV
        ps_cmd = (
            "powershell -NoProfile -Command \"$out='" + out_csv + "'; 'ip,port,version,online,max,ping_ms,motd' | Out-File -Encoding UTF8 $out; "
            "$t=Get-Content '" + targets_hint + "'; "
            "$ports=@(" + ','.join(str(p) for p in ports_list[:32]) + "); "
            "foreach($h in $t){ foreach($p in $ports){ try { $o=$(mcstatus $h:$p status); "
            "$ver=($o | Select-String 'version').Line.Split(':')[-1].Trim(); "
            "$ply=($o | Select-String 'players: ').Line.Split(':')[-1].Trim(); "
            "$lat=($o | Select-String 'latency').Line.Split(':')[-1].Trim(); "
            "$motd=($o | Select-String 'description').Line.Substring(12).Trim(); "
            "$on=$ply.Split('/')[0]; $mx=$ply.Split('/')[1]; "
            "\"$h,$p,$ver,$on,$mx,$lat,\"\"\"$motd\"\"\"\" | Out-File -Append -Encoding UTF8 $out } catch {} } }\""
        )
        text = (
            "Export targets first (Export Targets) to a file named targets.txt, then run one of the following:\n\n"
            "masscan:\n" + masscan_cmd + "\n\n"
            "nmap:\n" + nmap_cmd + "\n\n"
            "PowerShell + mcstatus to CSV (Windows):\n" + ps_cmd + "\n"
        )
        # Show and copy
        QApplication.clipboard().setText(text)
        QMessageBox.information(self, "External Commands", text)

    def on_preset_change(self):
        text = self.port_preset.currentText()
        # Enable/disable custom entry
        custom = (text == "Custom")
        self.custom_ports.setEnabled(custom)
        # Update range spinner defaults for presets
        if text == "Minecraft Java (25565)":
            self.port_start.setValue(25565)
            self.port_end.setValue(25565)
            self.custom_ports.setText("")
        elif text == "Bedrock (19132,19133)":
            self.port_start.setValue(19132)
            self.port_end.setValue(19133)
            self.custom_ports.setText("")
        elif text == "Common (25500-25700)":
            self.port_start.setValue(25500)
            self.port_end.setValue(25700)
            self.custom_ports.setText("")
        elif text == "All (1024-65535)":
            self.port_start.setValue(1024)
            self.port_end.setValue(65535)
            self.custom_ports.setText("")
        elif text == "Custom":
            # Leave current range, allow text entry
            if not self.custom_ports.text():
                self.custom_ports.setText("25565")

    def resolve_ports_list(self, start_port: int, end_port: int) -> list[int]:
        text = self.port_preset.currentText()
        ports: list[int] = []
        if text == "Minecraft Java (25565)":
            ports = [25565]
        elif text == "Bedrock (19132,19133)":
            ports = [19132, 19133]
        elif text == "Common (25500-25700)":
            ports = list(range(25500, 25701))
        elif text == "All (1024-65535)":
            ports = list(range(1024, 65536))
        elif text == "Custom":
            ports = self.parse_ports_spec(self.custom_ports.text().strip())
        else:
            ports = list(range(start_port, end_port + 1))
        # Deduplicate and sort, clip to valid range
        ports = sorted({p for p in ports if isinstance(p, int) and 1 <= p <= 65535})
        return ports

    def parse_ports_spec(self, spec: str) -> list[int]:
        if not spec:
            return []
        result: set[int] = set()
        for token in spec.split(','):
            token = token.strip()
            if not token:
                continue
            if '-' in token:
                try:
                    a, b = token.split('-', 1)
                    a = int(a.strip())
                    b = int(b.strip())
                    if a > b:
                        a, b = b, a
                    for p in range(max(1, a), min(65535, b) + 1):
                        result.add(p)
                except ValueError:
                    continue
            else:
                try:
                    p = int(token)
                    if 1 <= p <= 65535:
                        result.add(p)
                except ValueError:
                    continue
        return sorted(result)

    def scan_finished(self):
        self.scan_button.setText("Start Scan")
        self.scan_button.setEnabled(True)
        # Complete the progress bar
        self.progress.setValue(self.progress.maximum())
        self.progress.setVisible(False)
        found = self.results_list.count()
        self.update_status(f"Scan completed. Found {found} servers.")
        if found == 0:
            QMessageBox.information(self, "No Results", "No Java Edition servers were found for the given range and ports.\n\nTips:\n- Verify the IP range and port(s).\n- Increase Timeout (s).\n- Ensure servers are Java Edition (TCP 25565).\n- Try the Test Known Server button.")

    def add_server(self, server_info):
        # Store and apply filter before showing
        self.all_servers.append(server_info)
        if self.passes_filter(server_info):
            self._add_server_to_list(server_info)
        self.update_status(f"Found server at {server_info['ip']}:{server_info['port']}")
        self.append_log(f"FOUND {server_info['ip']}:{server_info['port']} - {server_info['version']} {server_info['players']} {server_info['ping']:.1f}ms")

    def _add_server_to_list(self, server_info):
        item = QListWidgetItem()
        widget = QWidget()
        layout = QVBoxLayout()

        info_layout = QHBoxLayout()
        info_layout.addWidget(QLabel(f"<b>{server_info['ip']}:{server_info['port']}</b>"))
        info_layout.addStretch()
        info_layout.addWidget(QLabel(f"Players: {server_info['players']}"))
        info_layout.addWidget(QLabel(f"Ping: {server_info['ping']:.1f}ms"))

        version_label = QLabel(f"Version: {server_info['version']}")
        motd_label = QLabel(f"MOTD: {server_info['motd']}")
        motd_label.setWordWrap(True)

        layout.addLayout(info_layout)
        layout.addWidget(version_label)
        layout.addWidget(motd_label)

        widget.setLayout(layout)
        item.setSizeHint(widget.sizeHint())
        item.setData(Qt.ItemDataRole.UserRole, server_info)
        self.results_list.addItem(item)
        self.results_list.setItemWidget(item, widget)

    def passes_filter(self, server_info) -> bool:
        try:
            players_str = server_info.get('players', '0/0')
            online = int(str(players_str).split('/')[0])
        except Exception:
            online = 0
        # Only Online filter
        if self.only_online_check.isChecked() and online <= 0:
            return False
        # Min players filter
        if online < self.min_players_spin.value():
            return False
        return True

    def refresh_results(self):
        self.results_list.clear()
        for s in self.all_servers:
            if self.passes_filter(s):
                self._add_server_to_list(s)

    def copy_all_addresses(self):
        # Copy all server host:port from current filtered view
        lines = []
        # Prefer current filtered list as shown
        for i in range(self.results_list.count()):
            it = self.results_list.item(i)
            info = it.data(Qt.ItemDataRole.UserRole) or {}
            lines.append(f"{info.get('ip','')}:{info.get('port','')}")
        # If nothing is displayed but we have data, fall back to all_servers
        if not lines and self.all_servers:
            for info in self.all_servers:
                lines.append(f"{info.get('ip','')}:{info.get('port','')}")
        if lines:
            QApplication.clipboard().setText("\n".join(lines))
            self.update_status(f"Copied {len(lines)} address(es) to clipboard")
        else:
            self.update_status("No addresses to copy")

    def export_csv(self):
        # Export current filtered results to CSV
        if self.results_list.count() == 0 and not self.all_servers:
            QMessageBox.information(self, "Export CSV", "No results to export.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export Servers to CSV", "servers.csv", "CSV Files (*.csv)")
        if not path:
            return
        try:
            import csv
            with open(path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(["ip", "port", "version", "players", "ping_ms", "motd"])
                # Write filtered view if available, else all_servers
                if self.results_list.count() > 0:
                    for i in range(self.results_list.count()):
                        it = self.results_list.item(i)
                        info = it.data(Qt.ItemDataRole.UserRole) or {}
                        writer.writerow([
                            info.get('ip',''),
                            info.get('port',''),
                            info.get('version',''),
                            info.get('players',''),
                            f"{info.get('ping','')}",
                            str(info.get('motd','')).replace('\n',' ').replace('\r',' ')
                        ])
                else:
                    for info in self.all_servers:
                        writer.writerow([
                            info.get('ip',''),
                            info.get('port',''),
                            info.get('version',''),
                            info.get('players',''),
                            f"{info.get('ping','')}",
                            str(info.get('motd','')).replace('\n',' ').replace('\r',' ')
                        ])
            self.update_status(f"Exported CSV to {path}")
        except Exception as e:
            QMessageBox.warning(self, "Export CSV", f"Failed to write CSV: {e}")

    def show_results_context_menu(self, pos):
        menu = QMenu(self)
        copy_addr = menu.addAction("Copy IP:Port")
        open_mc = menu.addAction("Open in Minecraft (Java)")
        test_known = menu.addAction("Test Known Server")
        show_details = menu.addAction("Show Details")
        export_single = menu.addAction("Export Selected (JSON)")
        menu.addSeparator()
        copy_row = menu.addAction("Copy Full Row")
        action = menu.exec(self.results_list.mapToGlobal(pos))
        if not action:
            return
        items = self.results_list.selectedItems()
        if not items:
            return
        # Use first selected item for single-item actions
        first = items[0]
        info_first = first.data(Qt.ItemDataRole.UserRole) or {}
        hostport_first = f"{info_first.get('ip','')}:{info_first.get('port','')}"

        if action == copy_addr:
            lines = [f"{(it.data(Qt.ItemDataRole.UserRole) or {}).get('ip','')}:{(it.data(Qt.ItemDataRole.UserRole) or {}).get('port','')}" for it in items]
            QApplication.clipboard().setText("\n".join(lines))
            return
        if action == open_mc:
            self.open_in_minecraft_java(info_first)
            return
        if action == test_known:
            self.test_known_server()
            return
        if action == show_details:
            self.show_details_dialog(info_first)
            return
        if action == export_single:
            self.export_single_json(info_first)
            return
        # Copy full rows
        lines = []
        for it in items:
            info = it.data(Qt.ItemDataRole.UserRole) or {}
            hostport = f"{info.get('ip','')}:{info.get('port','')}"
            line = f"{hostport} | Version: {info.get('version','')} | Players: {info.get('players','')} | Ping: {info.get('ping',''):.1f}ms | MOTD: {info.get('motd','')}"
            lines.append(line)
        QApplication.clipboard().setText("\n".join(lines))

    def keyPressEvent(self, event):
        # Support Ctrl+C to copy address of selected results when list has focus
        if event.matches(QKeySequence.StandardKey.Copy) and self.results_list.hasFocus():
            items = self.results_list.selectedItems()
            if items:
                lines = []
                for it in items:
                    info = it.data(Qt.ItemDataRole.UserRole) or {}
                    lines.append(f"{info.get('ip','')}:{info.get('port','')}")
                QApplication.clipboard().setText("\n".join(lines))
                return
        super().keyPressEvent(event)

    def open_in_minecraft_java(self, server_info: dict):
        host = server_info.get('ip', '')
        port = server_info.get('port', '')
        if not host or not port:
            self.update_status("Invalid server info to open")
            return
        # Always copy address for quick paste into Java client's Direct Connect
        addr = f"{host}:{port}"
        QApplication.clipboard().setText(addr)
        # Try to start the Java launcher if present
        candidates = [
            os.path.join(os.environ.get('ProgramFiles(x86)', ''), 'Minecraft Launcher', 'MinecraftLauncher.exe'),
            os.path.join(os.environ.get('ProgramFiles', ''), 'Minecraft Launcher', 'MinecraftLauncher.exe'),
        ]
        launched = False
        for exe in candidates:
            if exe and os.path.isfile(exe):
                if QProcess.startDetached(exe):
                    launched = True
                    break
        if launched:
            QMessageBox.information(self, "Open in Minecraft (Java)", "Java launcher opened. The server address has been copied to your clipboard. In the game: Multiplayer → Direct Connect → Paste.")
            self.update_status(f"Launched Java launcher; address copied: {addr}")
        else:
            QMessageBox.information(self, "Open in Minecraft (Java)", "Couldn't locate the Java launcher automatically. The server address has been copied to your clipboard. Open Minecraft Java manually, then Multiplayer → Direct Connect → Paste.")
            self.update_status(f"Address copied (Java): {addr}")

    def show_details_dialog(self, info: dict):
        hostport = f"{info.get('ip','')}:{info.get('port','')}"
        text = (
            f"Address: {hostport}\n"
            f"Version: {info.get('version','')}\n"
            f"Players: {info.get('players','')}\n"
            f"Ping: {info.get('ping','')} ms\n"
            f"MOTD: {info.get('motd','')}\n"
        )
        QMessageBox.information(self, "Server Details", text)

    def export_single_json(self, info: dict):
        import json
        host = info.get('ip','')
        port = info.get('port','')
        default = f"{host}-{port}.json" if host and port else "server.json"
        path, _ = QFileDialog.getSaveFileName(self, "Export Server to JSON", default, "JSON Files (*.json)")
        if not path:
            return
        try:
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(info, f, ensure_ascii=False, indent=2)
            self.update_status(f"Exported JSON to {path}")
        except Exception as e:
            QMessageBox.warning(self, "Export JSON", f"Failed to write JSON: {e}")

    def export_json(self):
        import json
        # Gather current filtered results
        data = []
        for i in range(self.results_list.count()):
            it = self.results_list.item(i)
            info = it.data(Qt.ItemDataRole.UserRole) or {}
            data.append(info)
        if not data and self.all_servers:
            data = list(self.all_servers)
        if not data:
            QMessageBox.information(self, "Export JSON", "No results to export.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export Servers to JSON", "servers.json", "JSON Files (*.json)")
        if not path:
            return
        try:
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            self.update_status(f"Exported JSON to {path}")
        except Exception as e:
            QMessageBox.warning(self, "Export JSON", f"Failed to write JSON: {e}")

    def clear_results(self):
        self.results_list.clear()
        self.update_status("Results cleared")

    def clear_logs(self):
        if hasattr(self, 'log_view'):
            self.log_view.clear()
        self.update_status("Logs cleared")

    def update_status(self, message):
        self.status_bar.showMessage(f"{datetime.now().strftime('%H:%M:%S')} - {message}")

    def update_progress(self, value: int):
        # Clamp value to range
        clamped = min(value, self.progress.maximum())
        self.progress.setValue(clamped)
        # Live status update with counts
        total = self.progress.maximum()
        self.update_status(f"Scanning {clamped}/{total} targets...")

    def test_known_server(self):
        # Quick single-target scan against a popular public server to validate UI/display
        self.ip_input.setText("mc.hypixel.net")
        self.port_start.setValue(25565)
        self.port_end.setValue(25565)
        self.start_scan()

    def count_ips(self, ip_range: str) -> int:
        if '-' not in ip_range:
            return 1
        start, end = ip_range.split('-')
        start = start.strip()
        end = end.strip()
        try:
            s_parts = list(map(int, start.split('.')))
            e_parts = list(map(int, end.split('.')))
            s_val = (s_parts[0]<<24) | (s_parts[1]<<16) | (s_parts[2]<<8) | s_parts[3]
            e_val = (e_parts[0]<<24) | (e_parts[1]<<16) | (e_parts[2]<<8) | e_parts[3]
            if e_val < s_val:
                return 0
            return (e_val - s_val + 1)
        except Exception:
            return 0

    def append_log(self, message: str):
        self.log_view.append(message)

    def closeEvent(self, event):
        if self.scanner_thread and self.scanner_thread.isRunning():
            self.scanner_thread.stop()
            self.scanner_thread.wait()
        event.accept()

def main():
    app = QApplication(sys.argv)
    app.setStyle('Fusion')

    # Dark palette
    dark_palette = QPalette()
    dark_palette.setColor(QPalette.ColorRole.Window, QColor(30, 30, 30))
    dark_palette.setColor(QPalette.ColorRole.WindowText, QColor(240, 240, 240))
    dark_palette.setColor(QPalette.ColorRole.Base, QColor(22, 22, 22))
    dark_palette.setColor(QPalette.ColorRole.AlternateBase, QColor(44, 44, 44))
    dark_palette.setColor(QPalette.ColorRole.ToolTipBase, QColor(240, 240, 240))
    dark_palette.setColor(QPalette.ColorRole.ToolTipText, QColor(30, 30, 30))
    dark_palette.setColor(QPalette.ColorRole.Text, QColor(240, 240, 240))
    dark_palette.setColor(QPalette.ColorRole.Button, QColor(45, 45, 45))
    dark_palette.setColor(QPalette.ColorRole.ButtonText, QColor(240, 240, 240))
    dark_palette.setColor(QPalette.ColorRole.BrightText, QColor(255, 0, 0))
    dark_palette.setColor(QPalette.ColorRole.Highlight, QColor(76, 175, 80))
    dark_palette.setColor(QPalette.ColorRole.HighlightedText, QColor(0, 0, 0))
    app.setPalette(dark_palette)

    # Dark stylesheet
    app.setStyleSheet("""
        QMainWindow { background-color: #1e1e1e; }
        QLabel { color: #f0f0f0; }
        QStatusBar { color: #f0f0f0; }
        QPushButton {
            background-color: #2d2d2d;
            color: #ffffff;
            border: 1px solid #3a3a3a;
            padding: 8px 16px;
            border-radius: 4px;
        }
        QPushButton:hover { background-color: #3a3a3a; }
        QPushButton:disabled { background-color: #2a2a2a; color: #888888; }
        QLineEdit, QSpinBox, QTextEdit {
            padding: 6px;
            border: 1px solid #3a3a3a;
            border-radius: 4px;
            background-color: #151515;
            color: #ffffff;
            selection-background-color: #4CAF50;
            selection-color: #000000;
        }
        QListWidget {
            border: 1px solid #3a3a3a;
            border-radius: 4px;
            background-color: #151515;
            color: #ffffff;
        }
        QListWidget::item { border-bottom: 1px solid #333; padding: 6px; }
        QListWidget::item:hover { background-color: #232323; }
        QProgressBar { border: 1px solid #3a3a3a; border-radius: 4px; background: #151515; color: #ffffff; text-align: center; }
        QProgressBar::chunk { background-color: #4CAF50; }
    """)

    # Parse simple CLI flags: --autostart, --ip=..., --ports=A-B
    argv = sys.argv[1:]
    autostart = any(a == "--autostart" for a in argv)
    ip_arg = next((a.split('=', 1)[1] for a in argv if a.startswith('--ip=')), None)
    ports_arg = next((a.split('=', 1)[1] for a in argv if a.startswith('--ports=')), None)
    p_start = p_end = None
    if ports_arg:
        try:
            parts = ports_arg.split('-')
            if len(parts) == 2:
                p_start = int(parts[0])
                p_end = int(parts[1])
            else:
                # single port
                p_start = p_end = int(parts[0])
        except ValueError:
            p_start = p_end = None
    
    window = MinecraftScanner(autostart=autostart, ip_range=ip_arg, port_start=p_start, port_end=p_end)
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
