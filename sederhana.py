#!/usr/bin/env python3

from scapy.all import *
import subprocess
import re
from manuf import manuf

def get_default_gateway_linux():
    """Mendapatkan gateway default di Linux."""
    try:
        result = subprocess.run(['ip', 'route'], capture_output=True, text=True)
        for line in result.stdout.splitlines():
            if line.startswith('default'):
                parts = line.split()
                gateway = parts[2]  # Biasanya di posisi ke-3
                iface = parts[4]    # Interface, misal: wlan0
                return gateway, iface
    except Exception as e:
        print(f"[!] Gagal mendapatkan gateway: {e}")
    return None, None

def get_local_ip_and_network(gateway_iface):
    """Mendapatkan IP lokal dan subnet network dari interface yang digunakan."""
    try:
        result = subprocess.run(['ip', 'addr', 'show', gateway_iface], capture_output=True, text=True)
        for line in result.stdout.splitlines():
            if 'inet ' in line:
                ip_net = line.strip().split()[1]  # Contoh: 192.168.1.100/24
                return ip_net
    except Exception as e:
        print(f"[!] Gagal mendapatkan IP lokal: {e}")
    return None

def arp_scan(network):
    """Melakukan ARP scan di jaringan lokal."""
    print(f"[*] Memindai jaringan: {network} ...")
    # Buat ARP request untuk seluruh subnet
    arp = ARP(pdst=network)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    # Kirim dan terima respons (timeout 2 detik)
    result = srp(packet, timeout=2, verbose=0)[0]

    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return devices

def main():
    print("📡 Memindai Jaringan Lokal (WiFi/LAN) ...\n")

    # 1. Dapatkan gateway dan interface
    gateway, iface = get_default_gateway_linux()
    if not gateway:
        print("[!] Tidak dapat menemukan gateway. Pastikan terhubung ke jaringan.")
        return

    print(f"[+] Gateway: {gateway}")
    print(f"[+] Interface: {iface}")

    # 2. Dapatkan IP lokal dan network (misal: 192.168.1.100/24)
    local_ip_net = get_local_ip_and_network(iface)
    if not local_ip_net:
        print("[!] Tidak dapat menemukan alamat IP lokal.")
        return

    print(f"[+] Alamat IP lokal Anda: {local_ip_net}")

    # 3. Lakukan ARP scan
    devices = arp_scan(local_ip_net)

    # 4. Tampilkan hasil
    print("\n" + "="*60)
    print("        PERANGKAT YANG TERDETEKSI DI JARINGAN")
    print("="*60)
    print(f"{'IP Address':<20} {'MAC Address':<20} {'Vendor (Partial)'}")
    print("-"*60)

    p = manuf.MacParser()


    for device in devices:
        ip = device['ip']
        mac = device['mac']
        # Ambil vendor dari 3 byte pertama MAC (OUI)
        vendor_full = p.get_manuf(mac)  # atau p.get_comment(mac)
        print(f"{ip:<20} {mac:<20} {vendor_full}")

    print(f"\n[+] Total perangkat ditemukan: {len(devices)}")

if __name__ == "__main__":
    # Pastikan dijalankan sebagai root
    if os.geteuid() != 0:
        print("[!] Jalankan script ini sebagai root (sudo).")
        exit(1)

    main()