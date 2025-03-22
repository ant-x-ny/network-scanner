import socket
from scapy.all import ARP, Ether, srp
import threading

def scan_network(network):
    """
    Scans the network to discover active devices.
    :param network: The subnet to scan (e.g., "192.168.1.0/24").
    """
    print(f"Scanning network {network}...")
    
    # Create ARP request
    arp = ARP(pdst=network)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    # Send the packet and receive the response
    result = srp(packet, timeout=2, verbose=False)[0]

    # Parse the results
    devices = []
    for _, received in result:
        devices.append({"ip": received.psrc, "mac": received.hwsrc})

    print("Discovered devices:")
    for device in devices:
        print(f"IP: {device['ip']}, MAC: {device['mac']}" )

    return devices

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
        except Exception as e:
            pass

    # Create threads for port scanning
    threads = []
    for port in range(1, 1025):  # Scan ports 1-1024
        t = threading.Thread(target=scan_port, args=(port,))
        threads.append(t)
        t.start()

    # Wait for all threads to complete
    for t in threads:
        t.join()

    print(f"Open ports on {ip}: {open_ports}")
    return open_ports

def save_results_to_file(devices):
    """
    Saves the scan results to a file.
    :param devices: List of devices with their IP, MAC, and open ports.
    """
    filename = "scan_results.txt"
    with open(filename, "w") as file:
        for device in devices:
            file.write(f"Device IP: {device['ip']}, MAC: {device['mac']}, Open Ports: {device.get('open_ports', [])}\n")
    print(f"Scan results saved to {filename}")

def main():
    network = input("Enter the network range to scan (e.g., 192.168.1.0/24): ")
    devices = scan_network(network)

    for device in devices:
        ip = device['ip']
        open_ports = scan_ports(ip)
        device['open_ports'] = open_ports
        print(f"Device {ip} has open ports: {open_ports}")

    save_results_to_file(devices)

if __name__ == "__main__":
    main()
