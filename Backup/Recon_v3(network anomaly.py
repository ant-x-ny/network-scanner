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
                if "(hex)" in line:  # Ensure correct formatting
                    parts = line.split("\t")
                    if len(parts) > 1:
                        mac_prefix = parts[0].strip().replace("-", ":").upper()[:8]
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
    """
    mac_prefix = mac_address.upper()[:8]
    return oui_database.get(mac_prefix, "Unknown Device")

# Scan network to find active devices
def scan_network(network, oui_database):
    """
    Scans the network to discover active devices and identifies their manufacturers.
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

# Detect anomalies in the network
def detect_anomalies(devices):
    """
    Identifies potential anomalies in the network based on unknown devices and unusual open ports.
    """
    common_malicious_ports = {23, 1080, 4444, 5555, 6667, 8080, 4443}  # Ports used by malware/botnets
    anomalies = []

    print("\nAnalyzing network for anomalies...\n")
    for device in devices:
        ip = device['ip']
        mac = device['mac']
        vendor = device['vendor']
        open_ports = device.get('open_ports', [])

        # Flag unknown devices
        if vendor == "Unknown Device":
            anomalies.append(f"⚠️ Unknown Device Detected - IP: {ip}, MAC: {mac}")

        # Flag devices with multiple open ports
        if len(open_ports) > 10:
            anomalies.append(f"⚠️ Device {ip} has unusually high open ports: {open_ports}")

        # Flag suspicious ports
        for port in open_ports:
            if port in common_malicious_ports:
                anomalies.append(f"⚠️ Suspicious Port {port} open on {ip}")

    if anomalies:
        print("\n⚠️ Potential Anomalies Found:\n")
        for anomaly in anomalies:
            print(anomaly)
    else:
        print("\n✅ No anomalies detected in the network.")

    return anomalies

# Save results to file
def save_results_to_file(devices, anomalies):
    """
    Saves the scan results and detected anomalies to a file.
    """
    filename = "scan_results.txt"
    with open(filename, "w") as file:
        for device in devices:
            file.write(f"Device IP: {device['ip']}, MAC: {device['mac']}, Vendor: {device['vendor']}, Open Ports: {device.get('open_ports', [])}\n")

        if anomalies:
            file.write("\nDetected Anomalies:\n")
            for anomaly in anomalies:
                file.write(anomaly + "\n")

    print(f"\n📁 Scan results and anomalies saved to {filename}")

# Main function
def main():
    network = input("Enter the network range to scan (e.g., 192.168.1.0/24): ")
    oui_data = load_oui_database()
    
    devices = scan_network(network, oui_data)

    for device in devices:
        ip = device['ip']
        open_ports = scan_ports(ip)
        device['open_ports'] = open_ports
        print(f"Device {ip} has open ports: {open_ports}")

    anomalies = detect_anomalies(devices)
    save_results_to_file(devices, anomalies)

if __name__ == "__main__":
    main()
