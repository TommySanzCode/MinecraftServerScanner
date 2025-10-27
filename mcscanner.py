import sys
import socket
import concurrent.futures
from PyQt6.QtWidgets import (QApplication, QMainWindow, QVBoxLayout, QWidget, QPushButton,
                             QTextEdit, QLineEdit, QLabel, QHBoxLayout, QProgressBar, QTableWidget,
                             QTableWidgetItem, QHeaderView, QMessageBox)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from mcstatus import JavaServer

class ServerScanner(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Minecraft Server Scanner")
        self.setMinimumSize(800, 600)
        
        # Main widget and layout
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout()
        
        # Input section
        input_layout = QHBoxLayout()
        self.ip_range_start = QLineEdit("192.168.1.1")
        self.ip_range_end = QLineEdit("192.168.1.255")
        self.port = QLineEdit("25565")
        self.port.setFixedWidth(80)
        
        input_layout.addWidget(QLabel("IP Range:"))
        input_layout.addWidget(self.ip_range_start)
        input_layout.addWidget(QLabel("to"))
        input_layout.addWidget(self.ip_range_end)
        input_layout.addWidget(QLabel("Port:"))
        input_layout.addWidget(self.port)
        
        # Buttons
        self.scan_button = QPushButton("Start Scan")
        self.scan_button.clicked.connect(self.start_scan)
        self.stop_button = QPushButton("Stop")
        self.stop_button.setEnabled(False)
        self.stop_button.clicked.connect(self.stop_scan)
        
        # Progress
        self.progress = QProgressBar()
        self.progress.setValue(0)
        
        # Results table
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(4)
        self.results_table.setHorizontalHeaderLabels(["IP Address", "Port", "Version", "Players"])
        self.results_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        
        # Log
        self.log = QTextEdit()
        self.log.setReadOnly(True)
        
        # Add widgets to layout
        layout.addLayout(input_layout)
        
        button_layout = QHBoxLayout()
        button_layout.addWidget(self.scan_button)
        button_layout.addWidget(self.stop_button)
        layout.addLayout(button_layout)
        
        layout.addWidget(QLabel("Progress:"))
        layout.addWidget(self.progress)
        layout.addWidget(QLabel("Found Servers:"))
        layout.addWidget(self.results_table)
        layout.addWidget(QLabel("Log:"))
        layout.addWidget(self.log)
        
        main_widget.setLayout(layout)
        
        # Thread control
        self.scan_thread = None
        self.scanning = False
        self.found_servers = []
    
    def log_message(self, message):
        self.log.append(f"[INFO] {message}")
    
    def start_scan(self):
        if self.scanning:
            return
            
        try:
            start_ip = self.ip_range_start.text().strip()
            end_ip = self.ip_range_end.text().strip()
            port = int(self.port.text().strip())
            
            self.scanning = True
            self.scan_button.setEnabled(False)
            self.stop_button.setEnabled(True)
            self.results_table.setRowCount(0)
            self.found_servers = []
            self.log.clear()
            
            self.scan_thread = ScanThread(start_ip, end_ip, port)
            self.scan_thread.status_update.connect(self.update_status)
            self.scan_thread.server_found.connect(self.add_server)
            self.scan_thread.finished.connect(self.scan_finished)
            self.scan_thread.start()
            
            self.log_message(f"Starting scan from {start_ip} to {end_ip} on port {port}")
            
        except ValueError as e:
            QMessageBox.critical(self, "Error", "Please enter valid IP addresses and port number.")
            self.scanning = False
            self.scan_button.setEnabled(True)
            self.stop_button.setEnabled(False)
    
    def stop_scan(self):
        if self.scan_thread and self.scanning:
            self.scan_thread.stop()
            self.scanning = False
            self.scan_button.setEnabled(True)
            self.stop_button.setEnabled(False)
            self.log_message("Scan stopped by user.")
    
    def scan_finished(self):
        self.scanning = False
        self.scan_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.log_message(f"Scan completed. Found {len(self.found_servers)} Minecraft servers.")
    
    def update_status(self, current, total):
        self.progress.setMaximum(total)
        self.progress.setValue(current)
    
    def add_server(self, server_info):
        row = self.results_table.rowCount()
        self.results_table.insertRow(row)
        
        ip_item = QTableWidgetItem(server_info['ip'])
        port_item = QTableWidgetItem(str(server_info['port']))
        version_item = QTableWidgetItem(server_info.get('version', 'Unknown'))
        players_item = QTableWidgetItem(server_info.get('players', 'N/A'))
        
        # Make items non-editable
        for item in [ip_item, port_item, version_item, players_item]:
            item.setFlags(item.flags() ^ Qt.ItemFlag.ItemIsEditable)
        
        self.results_table.setItem(row, 0, ip_item)
        self.results_table.setItem(row, 1, port_item)
        self.results_table.setItem(row, 2, version_item)
        self.results_table.setItem(row, 3, players_item)
        
        self.found_servers.append(server_info)
        self.log_message(f"Found server at {server_info['ip']}:{server_info['port']}")


class ScanThread(QThread):
    status_update = pyqtSignal(int, int)  # current, total
    server_found = pyqtSignal(dict)  # server info
    
    def __init__(self, start_ip, end_ip, port):
        super().__init__()
        self.start_ip = start_ip
        self.end_ip = end_ip
        self.port = port
        self._stop = False
    
    def stop(self):
        self._stop = True
    
    def ip_to_int(self, ip):
        return int(ipaddress.IPv4Address(ip))
    
    def int_to_ip(self, num):
        return str(ipaddress.IPv4Address(num))
    
    def run(self):
        try:
            import ipaddress
            
            start = self.ip_to_int(self.start_ip)
            end = self.ip_to_int(self.end_ip)
            total = end - start + 1
            
            if total <= 0 or total > 65536:  # Limit to a reasonable range
                self.log_message("Invalid IP range")
                return
                
            with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
                futures = []
                
                for i in range(start, end + 1):
                    if self._stop:
                        break
                        
                    ip = self.int_to_ip(i)
                    futures.append(executor.submit(self.check_server, ip, self.port))
                    
                    # Update progress every 10 IPs
                    if i % 10 == 0:
                        self.status_update.emit(i - start, total)
                
                # Wait for all futures to complete
                for future in concurrent.futures.as_completed(futures):
                    if self._stop:
                        break
                    result = future.result()
                    if result:
                        self.server_found.emit(result)
                
                self.status_update.emit(total, total)
                
        except Exception as e:
            print(f"Error in scan thread: {e}")
    
    def check_server(self, ip, port):
        try:
            # First check if the port is open with a quick socket connection
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            sock.close()
            
            if result == 0:  # Port is open
                try:
                    server = JavaServer.lookup(f"{ip}:{port}", timeout=2)
                    status = server.status()
                    
                    return {
                        'ip': ip,
                        'port': port,
                        'version': status.version.name,
                        'players': f"{status.players.online}/{status.players.max}"
                    }
                except Exception as e:
                    # Port is open but not a Minecraft server or timed out
                    return None
            return None
            
        except Exception as e:
            return None


def main():
    app = QApplication(sys.argv)
    app.setStyle('Fusion')  # Modern look
    
    window = ServerScanner()
    window.show()
    
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
