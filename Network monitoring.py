# Networking and Packet Manipulation
from scapy.all import ARP, wrpcap, Ether, srp, sr1, sniff, IP, TCP, UDP, ICMP  # Network scanning and packet sniffing modules
import scapy.all as scapy  # Full Scapy module for additional functionalities
import socket  # Used for checking port status and banner grabbing
import ipaddress  # IP address manipulation and validation

# System and Utility Modules
import os  # OS-level operations like executing commands
import time  # Used for measuring latency or response times
import logging  # Logging system events and debugging information
import json  # Save and manage scan results in JSON format
import random  # Generate random values where needed

# Progress and Visualization
from tqdm import tqdm  # Progress bar for operations
import matplotlib.pyplot as plt  # Visualization of network topology
import networkx as nx  # Network graph representation and analysis

# Terminal Output Enhancement
from termcolor import colored  # Colorized terminal text output

# Cryptography and Security
from Cryptodome.Cipher import AES  # AES encryption and decryption
from Cryptodome.Util.Padding import pad, unpad  # Padding for AES encryption
import base64  # Encoding and decoding data in Base64 format

# Email Notification
from email.mime.text import MIMEText  # Email message formatting
import smtplib  # Sending email notifications

# Configurations
SECRET_KEY = b"MySecureKey12345"  # Change for security
LOG_FILE = "network_scanner.log"
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
EMAIL_SENDER = "Kanikaim2003@gmail.com"
EMAIL_RECEIVER = "alert_receiver@gmail.com"
EMAIL_PASSWORD = "your_email_password"

#Logging & Security System 
class Logger:
    def encrypt_log(data): #Handles secure logging using AES encryption and Base64 encoding.
        cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv=b"0123456789abcdef")
        encrypted = cipher.encrypt(pad(data.encode(), AES.block_size))
        return base64.b64encode(cipher.iv + encrypted).decode()

    def decrypt_log(data):
        raw = base64.b64decode(data)
        iv = raw[:16]
        cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv=iv)
        return unpad(cipher.decrypt(raw[16:]), AES.block_size).decode()

    # Secure Logging Configuration
    logging.basicConfig(level=logging.INFO)
    log_file = "network_scanner.log" #Stores encrypted logs in "network_scanner.log".
    def log_secure(message):
        encrypted_message = Logger.encrypt_log(message)
        with open(LOG_FILE, "a") as f:
            f.write(encrypted_message + "\n")

#Email Alert System
class AlertSystem: #Sends email alerts when open ports are detected.
    """Handles real-time email alerts."""
    @staticmethod
    def send_alert(subject, body):
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = EMAIL_SENDER
        msg["To"] = EMAIL_RECEIVER
        try:
            server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
            server.starttls()
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            server.sendmail(EMAIL_SENDER, EMAIL_RECEIVER, msg.as_string())
            server.quit()
            print(colored("[ALERT SENT] Anomaly detected and reported via email!", "yellow"))
        except Exception as e:
            print(colored(f"[ALERT FAILED] {e}", "red"))

class TrafficMonitor:
    """Monitors network traffic for anomalies."""
    seen_traffic = {}

class LoggingConfig:
    """Configures logging settings for the application."""
    @staticmethod
    def setup_logging():
        logging.basicConfig(
            filename=LOG_FILE,  # Save logs to this file
            level=logging.INFO,  # Log only INFO level and above
            format="%(asctime)s - %(levelname)s - %(message)s",  # Log format
            datefmt="%Y-%m-%d %H:%M:%S"  # Date format
        )
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)  # Show only INFO+ logs
        console_formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
        console_handler.setFormatter(console_formatter)
        logging.getLogger().addHandler(console_handler)
        logging.info("Network Scanner Started")

#Network Scanning 
class NetworkScanner:
    """Performs network scanning operations."""
    @staticmethod
    def is_valid_ip(ip): #IP discovery
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def stealth_scan(target, ports): #stealth scanning
        if not NetworkScanner.is_valid_ip(target):
            print(colored("Invalid IP address.", "red"))
            return
        
        print(colored(f"Performing SYN scan on {target}...", "cyan"))
        results = {}
        alert_triggered = False
        for port in tqdm(ports, desc="Scanning Ports", unit="port"):
            time.sleep(random.uniform(0.5, 2))  # Random delay for stealth
            pkt = IP(dst=target)/TCP(dport=port, flags="S")
            resp = sr1(pkt, timeout=1, verbose=0)
            
            if resp and resp.haslayer(TCP):
                if resp.getlayer(TCP).flags == 0x12:
                    results[port] = "Open"
                    sr1(IP(dst=target)/TCP(dport=port, flags="R"), timeout=1, verbose=0)  # Send RST to close connection
                    alert_triggered = True
                else:
                    results[port] = "Closed"
            else:
                results[port] = "Filtered"
        
        Logger.log_secure(json.dumps(results))
        print(json.dumps(results, indent=4))
        
        if alert_triggered:
            AlertSystem.send_alert("[ALERT] Open Port Detected!", f"An open port has been detected on {target}:\n{json.dumps(results, indent=4)}")

    @staticmethod
    def detect_os(ip): #OS detection
        """Detect OS based on TCP/IP fingerprinting using TTL & TCP Window Size."""
        try:
            response = sr1(IP(dst=ip)/TCP(dport=80, flags="S"), timeout=1, verbose=0)
            if response:
                ttl = response.ttl  # Extract Time-To-Live (TTL)
                window_size = response[TCP].window  # Extract TCP window size
                os_type = "Unknown"
                if ttl <= 64:
                    os_type = "Linux/Unix"
                elif ttl <= 128:
                    os_type = "Windows"
                if os_type == "Windows" and window_size in [65535, 64240, 8192]:
                    os_type = "Windows (XP/7/10/Server)"
                elif os_type == "Linux/Unix" and window_size in [5840, 14600, 29200]:
                    os_type = "Linux (Ubuntu/Debian/Fedora)"
                logging.info(f"Detected OS for {ip}: {os_type} (TTL={ttl}, Win={window_size})")
                return os_type
            else:
                logging.warning(f"Could not detect OS for {ip}. No response received.")
                return "Unknown"
        except Exception as e:
            logging.error(f"Error detecting OS for {ip}: {e}")
            return "Unknown"

#Port Scanning & Banner Grabbing
def scan_ip_range(ip_range):
    logging.info(f"Starting IP scan on range: {ip_range}")
    arp = ARP(pdst=ip_range)  # Create ARP request
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")  # Create Ethernet frame
    packet = ether / arp  # Combine Ethernet and ARP
    result = srp(packet, timeout=2, verbose=False)[0]  # Send packet and receive responses

    active_hosts = []  # Store active hosts
    print(colored(f"Starting scan for IP range: {ip_range}", 'cyan', attrs=['bold']))

    start_time = time.time()

    # Use tqdm for progress bar
    for sent, received in tqdm(result, desc="Scanning Hosts", unit="host"):
        os_type = NetworkScanner.detect_os(received.psrc)  # Call OS detection method from class

        host_info = {
            'ip': received.psrc,
            'mac': received.hwsrc,
            'os': os_type,  # OS detection result
            'latency': None
        }

        start_latency = time.time()
        logging.info(f"Host {received.psrc} is up (MAC: {received.hwsrc}, OS: {os_type})")
        try:
            socket.create_connection((received.psrc, 80), timeout=1)  # Check reachability via port 80
            latency = round((time.time() - start_latency) * 1000, 4)
            host_info['latency'] = f"{latency} ms"
            print(colored(f"Host {received.psrc} is up (Latency: {latency} ms) [MAC: {received.hwsrc}, OS: {os_type}]", 'yellow'))
            active_hosts.append(host_info)
        except socket.timeout:
            print(colored(f"Host {received.psrc} is down or not responding (Timeout)", 'red'))
        except socket.error as e:
            print(colored(f"Socket error for {received.psrc}: {e}", 'red'))

    end_time = time.time()
    elapsed_time = round(end_time - start_time, 2)

    print(colored(f"\nScan complete: {len(active_hosts)} host(s) up, {len(result) - len(active_hosts)} down, scanned in {elapsed_time} seconds", 'green', attrs=['bold']))
    logging.info(f"IP scan completed. {len(active_hosts)} hosts found.")
    return active_hosts

def port_scan_menu():
    while True:
        print(colored("\nPort Scanning Menu:", 'cyan', attrs=['bold', 'underline']))
        print(colored("1. Scan specific ports (e.g., 22, 80, 443)", 'yellow'))
        print(colored("2. Scan a range of ports (e.g., 21-100)", 'yellow'))
        print(colored("3. Scan all ports (1-65535)", 'yellow'))
        print(colored("4. Exit", 'yellow'))

        choice = input(colored("Choose an option (1, 2, 3, 4): ", 'cyan'))

        if choice == '1':
            ports = list(map(int, input(colored("Enter specific ports separated by commas: ", 'yellow')).split(',')))
            if all(0 <= port <= 65535 for port in ports):
                return ports
            else:
                print(colored("Invalid port number. Please ensure ports are in the range 0-65535.", 'red'))
        elif choice == '2':
            port_range = input(colored("Enter port range (e.g., 21-100): ", 'yellow'))
            try:
                start_port, end_port = map(int, port_range.split('-'))
                if 0 <= start_port <= 65535 and 0 <= end_port <= 65535:
                    ports = list(range(start_port, end_port + 1))
                    return ports
                else:
                    print(colored("Invalid port range. Please ensure ports are in the range 0-65535.", 'red'))
            except ValueError:
                print(colored("Invalid range format. Please use 'start-end'.", 'red'))
        elif choice == '3':
            ports = list(range(1, 65536))
            return ports
        elif choice == '4':
            print(colored("Exiting the port scan menu.", 'red'))
            return None
        else:
            print(colored("Invalid choice. Please try again.", 'red'))

def save_report(devices, filename="network_scan_report.json"):
    try:
        with open(filename, 'w') as file:
            json.dump(devices, file, indent=4)
        print(colored(f"Report saved as {filename}", 'green', attrs=['bold']))
    except Exception as e:
        print(colored(f"Failed to save report: {e}", 'red'))

# Packet Sniffing Function
captured_packets = []  # Stores packets in memory
PCAP_FILENAME = "captured_traffic.pcap"  # Default PCAP file name

seen_traffic = {}
#Packet Sniffing & Traffic Analysis
def packet_sniffer(packet, monitored_ports):
    global captured_packets, seen_traffic 

    if packet.haslayer(IP):  # Capture only IP packets
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        ip_pair = (ip_src, ip_dst)

        current_time = time.time()
        if ip_pair in seen_traffic:
            last_seen_time = seen_traffic[ip_pair]
            if current_time - last_seen_time < 1:
                return  # Skip duplicate packets

        # Classify packet type
        if packet.haslayer(TCP):
            if packet[TCP].dport in monitored_ports:
                print(colored(f"Suspicious TCP Traffic: {ip_src} -> {ip_dst} (Port {packet[TCP].dport})", 'cyan'))
        elif packet.haslayer(UDP):
            if packet[UDP].dport in monitored_ports:
                print(colored(f"Suspicious UDP Traffic: {ip_src} -> {ip_dst} (Port {packet[UDP].dport})", 'magenta'))
        elif packet.haslayer(ICMP):
            print(colored(f"ICMP Ping: {ip_src} -> {ip_dst}", 'blue'))

        seen_traffic[ip_pair] = current_time

        # Store the packet in memory
        captured_packets.append(packet)

        # Save to PCAP every 50 packets to prevent memory overflow
        if len(captured_packets) >= 50:
            save_pcap(PCAP_FILENAME)

def detect_os_from_packet(packet):
    """Detect OS from a captured packet using TTL & TCP window size."""
    if packet.haslayer(IP) and packet.haslayer(TCP):
        ttl = packet[IP].ttl
        window_size = packet[TCP].window

        if ttl <= 64:
            os_type = "Linux/Unix"
        elif ttl <= 128:
            os_type = "Windows"
        else:
            os_type = "Unknown"

        # More OS fingerprinting based on TCP window size
        if os_type == "Windows" and window_size in [65535, 64240, 8192]:
            os_type = "Windows (XP/7/10/Server)"
        elif os_type == "Linux/Unix" and window_size in [5840, 14600, 29200]:
            os_type = "Linux (Ubuntu/Debian/Fedora)"

        print(colored(f"Detected OS: {os_type} (TTL={ttl}, Win={window_size})", 'cyan'))
        return os_type
    return "Unknown"

def save_pcap(filename):
    """Saves captured packets to a PCAP file for Wireshark analysis."""
    global captured_packets

    if captured_packets:
        if os.path.exists(filename):
            # Append to existing PCAP file
            wrpcap(filename, captured_packets, append=True)
        else:
            # Create a new PCAP file
            wrpcap(filename, captured_packets)
        
        print(colored(f"Saved {len(captured_packets)} packets to {filename}", 'green'))
        
        # Clear in-memory packet storage after saving
        captured_packets = []

def start_packet_sniffing(interface="eth0", monitored_ports=[]):
    """Starts packet sniffing on a specified network interface."""
    print(colored(f"Starting packet sniffing on {interface} for monitored ports {monitored_ports}...", 'cyan'))
    sniff(iface=interface, prn=lambda pkt: packet_sniffer(pkt, monitored_ports), store=0)

def get_available_interfaces():
    interfaces = scapy.get_if_list()
    return interfaces

def choose_interface():
    interfaces = get_available_interfaces()
    print(colored("Available interfaces:", 'cyan'))
    for i, iface in enumerate(interfaces, start=1):
        print(colored(f"{i}. {iface}", 'yellow'))

    interface_name = input(colored("Enter the network interface name (e.g., en0, wlan0): ", 'cyan')).strip()
    if interface_name in interfaces:
        return interface_name
    else:
        print(colored("Invalid interface name, exiting...", 'red'))
        return None

def select_ports():
    while True:
        print(colored("\nChoose port scan option:", 'cyan', attrs=['bold']))
        print(colored("1. Scan specific ports (e.g., 22, 80, 443)", 'yellow'))
        print(colored("2. Scan a range of ports (e.g., 21-100)", 'yellow'))
        print(colored("3. Exit", 'yellow'))

        choice = input(colored("Choose an option (1, 2, 3): ", 'cyan'))

        if choice == '1':
            ports = list(map(int, input(colored("Enter specific ports separated by commas: ", 'yellow')).split(',')))
            if all(0 <= port <= 65535 for port in ports):
                return ports
            else:
                print(colored("Invalid port number. Please ensure ports are in the range 0-65535.", 'red'))
        elif choice == '2':
            port_range = input(colored("Enter port range (e.g., 21-100): ", 'yellow'))
            try:
                start_port, end_port = map(int, port_range.split('-'))
                if 0 <= start_port <= 65535 and 0 <= end_port <= 65535:
                    ports = list(range(start_port, end_port + 1))
                    return ports
                else:
                    print(colored("Invalid port range. Please ensure ports are in the range 0-65535.", 'red'))
            except ValueError:
                print(colored("Invalid range format. Please use 'start-end'.", 'red'))
        elif choice == '3':
            print(colored("Exiting the port selection.", 'red'))
            return []
        else:
            print(colored("Invalid choice. Please try again.", 'red'))

#Network Visualization (Graphing Network Topology)
def build_network_graph(devices):
    G = nx.Graph()

    for device in devices:
        device_type = device.get('type', 'unknown')  
        G.add_node(device['ip'], label=f"{device['ip']} [MAC: {device['mac']}]", type=device_type)

    for i, device1 in enumerate(devices):
        for device2 in devices[i+1:]:
            common_ports = set(device1.get('open_ports', [])) & set(device2.get('open_ports', []))
            if common_ports:
                G.add_edge(device1['ip'], device2['ip'], weight=len(common_ports), label=f"Ports: {common_ports}")

    return G

def plot_network_graph(G):
    plt.figure(figsize=(14, 10))

    pos = nx.kamada_kawai_layout(G)

    # Assign node colors based on device type
    node_colors = {
        "router": "red",
        "server": "green",
        "client": "blue",
        "unknown": "gray"
    }
    node_sizes = {
        "router": 5000,  # Larger for routers
        "server": 4000,
        "client": 3000,
        "unknown": 2500
    }

    # Get node attributes
    node_labels = nx.get_node_attributes(G, 'label')
    node_types = nx.get_node_attributes(G, 'type')

    # Assign colors and sizes dynamically
    colors = [node_colors.get(node_types[n], "gray") for n in G.nodes]
    sizes = [node_sizes.get(node_types[n], 2500) for n in G.nodes]

    # Draw network graph
    nx.draw(G, pos, with_labels=True, labels=node_labels, node_size=sizes, node_color=colors, 
            font_size=10, font_weight='bold', edge_color='gray')

    # Draw edge labels (common ports)
    edge_labels = nx.get_edge_attributes(G, 'label')
    nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels, font_size=8)

    plt.title("Enhanced Network Topology Map", fontsize=14, fontweight='bold')
    plt.show()

def save_network_graph(G, filename="network_topology.png"):
    plt.figure(figsize=(14, 10))
    pos = nx.kamada_kawai_layout(G)

    node_labels = nx.get_node_attributes(G, 'label')
    node_types = nx.get_node_attributes(G, 'type')

    node_colors = {
        "router": "red",
        "server": "green",
        "client": "blue",
        "unknown": "gray"
    }
    node_sizes = {
        "router": 5000,
        "server": 4000,
        "client": 3000,
        "unknown": 2500
    }

    colors = [node_colors.get(node_types[n], "gray") for n in G.nodes]
    sizes = [node_sizes.get(node_types[n], 2500) for n in G.nodes]

    nx.draw(G, pos, with_labels=True, labels=node_labels, node_size=sizes, node_color=colors, 
            font_size=10, font_weight='bold', edge_color='gray')

    edge_labels = nx.get_edge_attributes(G, 'label')
    nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels, font_size=8)

    plt.title("Enhanced Network Topology Map")
    plt.savefig(filename)
    print(colored(f"Network topology saved as {filename}", 'green'))

# --- Added Functions for Port Scanning ---

def scan_ports(ip, ports):
    """Scans the specified IP for open ports from the provided list."""
    open_ports = []

    logging.info(f"Starting port scan on {ip} for {len(ports)} ports.")

    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        try:
            if sock.connect_ex((ip, port)) == 0:
                open_ports.append(port)
                logging.info(f"Port {port} is open on {ip}")
            sock.close()
        except Exception as e:
            logging.error(f"Error scanning port {port} on {ip}: {str(e)}")
            sock.close()

    if open_ports:
        logging.info(f"Port scan complete. Open ports on {ip}: {open_ports}")
    else:
        logging.info(f"No open ports found on {ip}")

    return open_ports


def get_service_banner(ip, port):
    """Attempts to retrieve the service banner from the specified IP and port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        sock.connect((ip, port))
        banner = sock.recv(1024).decode().strip()
        sock.close()
        return banner if banner else "No Banner"
    except Exception:
        return "No Banner"

# --- Main Code Section ---
if __name__ == "__main__":
    target_ip = input("Enter target IP: ")
    ports_to_scan = [22, 80, 443, 8080, 3306]
    NetworkScanner.stealth_scan(target_ip, ports_to_scan)
    
    print(colored("Network Scanner with Packet Sniffer", 'cyan', attrs=['bold', 'underline']))

    ip_range = input(colored("Enter the IP range (e.g., 192.168.0.1/24): ", 'yellow')).strip()
    active_hosts = scan_ip_range(ip_range)  # Check which devices are online.

    if active_hosts:
        print(colored("\nActive hosts found:", 'cyan', attrs=['bold']))
        for host in active_hosts:
            print(colored(f"IP: {host['ip']} [MAC: {host['mac']}] (Latency: {host['latency']})", 'yellow'))

        # Main Network Scanner Menu
        while True:
            print(colored("\nNetwork Scanner Menu:", 'cyan', attrs=['bold', 'underline']))
            print(colored("1. Port Scanning", 'yellow'))
            print(colored("2. Packet Sniffing", 'yellow'))
            print(colored("3. Network Topology", 'yellow'))
            print(colored("4. Exit", 'yellow'))

            choice = input(colored("Choose an option (1, 2, 3, 4): ", 'cyan'))

            if choice == '1':  # Port Scanning
                ports_to_scan = port_scan_menu()
                if ports_to_scan:
                    for device in active_hosts:
                        print(colored(f"\nScanning {device['ip']} [MAC: {device['mac']}] for ports {ports_to_scan}", 'yellow', attrs=['bold']))
            
                        # Perform the port scan
                        open_ports = scan_ports(device['ip'], ports_to_scan)
                        device['open_ports'] = open_ports
                        device['services'] = {
                            port: get_service_banner(device['ip'], port) for port in open_ports
                        }
                        if open_ports:
                            print(colored(f"\nOpen ports on {device['ip']}:", 'green', attrs=['bold']))
                            for port in open_ports:
                                banner = device['services'][port]
                                print(colored(f"  - Port {port} is open; Service: {banner}", 'green'))
                        else:
                            print(colored(f"\nNo open ports found on {device['ip']} for the scanned list: {ports_to_scan}", 'red'))

            elif choice == '2':
                interface = choose_interface()
                if interface:
                    monitored_ports = select_ports()
                    if monitored_ports:
                        start_packet_sniffing(interface, monitored_ports)

            elif choice == '3':
                G = build_network_graph(active_hosts)
                plot_network_graph(G)
                save_network_graph(G)

            elif choice == '4':
                print(colored("Exiting Network Scanner Menu.", 'red'))
                break
            else:
                print(colored("Invalid choice. Please try again.", 'red'))
    else:
        print(colored("No active hosts found. Exiting.", 'red'))
