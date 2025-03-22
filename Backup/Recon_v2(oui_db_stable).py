import socket
import threading
from scapy.all import ARP, Ether, srp

# Load OUI database from oui.txt
def load_oui_database(file_path="oui.txt"):
    """
    Loads the OUI database from a text file and maps MAC prefixes to manufacturers.
    """
    oui_dict = {}
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            for line in file:
                if "(hex)" in line:  # Check for the correct formatting
                    parts = line.split("\t")
                    if len(parts) > 1:
                        mac_prefix = parts[0].strip().replace("-", ":").upper()[:8]  # Ensure format matches scanned MAC
                        vendor_name = parts[-1].strip()
                        oui_dict[mac_prefix] = vendor_name
    except FileNotFoundError:
        print("Error: OUI file not found! Download it from IEEE and place it in the script folder.")
    except Exception as e:
        print(f"Error loading OUI database: {e}")
    return oui_dict

# Identify vendor from MAC address
def get_device_vendor(mac_address, oui_database):
    """
    Finds the manufacturer/vendor of a device based on its MAC address using a local OUI database.
    :param mac_address: The MAC address to lookup.
    :param oui_database: Dictionary of MAC prefixes to manufacturers.
    :return: Vendor name if found, else "Unknown Device".
    """
    mac_prefix = mac_address.upper()[:8]  # Get the first 3 octets
    return oui_database.get(mac_prefix, "Unknown Device")

# Scan network to find active devices
def scan_network(network, oui_database):
    """
    Scans the network to discover active devices and identifies their manufacturers.
    :param network: The subnet to scan (e.g., "192.168.1.0/24").
    """
    print(f"Scanning network {network}...")
    
    arp = ARP(pdst=network)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    result = srp(packet, timeout=2, verbose=False)[0]

    devices = []
    for _, received in result:
        mac_address = received.hwsrc
        vendor = get_device_vendor(mac_address, oui_database)
        devices.append({"ip": received.psrc, "mac": mac_address, "vendor": vendor})

    print("Discovered devices:")
    for device in devices:
        print(f"IP: {device['ip']}, MAC: {device['mac']}, Vendor: {device['vendor']}")

    return devices

# Scan ports on a device
def scan_ports(ip):
    """
    Scans ports on a specific device to find open ports.
    :param ip: The IP address of the target device.
    """
    print(f"Scanning ports on {ip}...")
    open_ports = []

    def scan_port(port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
        except Exception:
            pass

    threads = []
    for port in range(1, 1025):  # Scan ports 1-1024
        t = threading.Thread(target=scan_port, args=(port,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    print(f"Open ports on {ip}: {open_ports}")
    return open_ports

# Save results to file
def save_results_to_file(devices):
    """
    Saves the scan results to a file.
    :param devices: List of devices with their IP, MAC, vendor, and open ports.
    """
    filename = "scan_results.txt"
    with open(filename, "w") as file:
        for device in devices:
            file.write(f"Device IP: {device['ip']}, MAC: {device['mac']}, Vendor: {device['vendor']}, Open Ports: {device.get('open_ports', [])}\n")
    print(f"Scan results saved to {filename}")

# Main function
def main():
    network = input("Enter the network range to scan (e.g., 192.168.1.0/24): ")
    oui_data = load_oui_database()
    # print(f"Loaded {len(oui_data)} OUI entries.")
    # test_mac = "3C:7C:3F"  # Example MAC prefix
    # print(f"Vendor for {test_mac}: {oui_data.get(test_mac, 'Unknown Device')}")
    
    devices = scan_network(network, oui_data)

    for device in devices:
        ip = device['ip']
        open_ports = scan_ports(ip)
        device['open_ports'] = open_ports
        print(f"Device {ip} has open ports: {open_ports}")

    save_results_to_file(devices)

if __name__ == "__main__":
    main()
