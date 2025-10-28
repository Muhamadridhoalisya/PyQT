from scapy.all import getmanuf

def get_vendor_scapy(mac_address):
    vendor = getmanuf(mac_address)
    return vendor if vendor else "Unknown"

# Contoh penggunaan
mac = "00:1A:2B:3C:4D:5E"
vendor = get_vendor_scapy(mac)
print(f"Vendor: {vendor}")