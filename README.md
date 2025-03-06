# 📡 Network Monitoring & Packet Analyzer

## 🌟 Overview
This **Network Monitoring & Packet Analyzer** is a **Python-based** cybersecurity tool designed to:

✔ **Scan networks** for active hosts & open ports  
✔ **Analyze network traffic** using packet sniffing  
✔ **Detect running services** via banner grabbing  
✔ **Visualize network topology** with graphs  
✔ **Send real-time alerts** for anomalies  
✔ **Encrypt logs** for secure storage  

---

## 🛠️ Tools & Libraries
This project is built using the following tools and libraries:

| **Library**  | **Purpose** |
|-------------|------------|
| `Scapy` | Packet sniffing & network scanning |
| `Socket` | Port scanning & banner grabbing |
| `NetworkX` | Network topology visualization |
| `Matplotlib` | Graph plotting |
| `Cryptodome` | AES encryption for log security |
| `tqdm` | Progress bar for scans |
| `smtplib` | Email alert system |
| `ipaddress` | IP address validation |
| `os` | System operations |
| `time` | Measuring response times |
| `logging` | Logging system events |
| `json` | Storing scan results |
| `random` | Randomized operations |
| `termcolor` | Colorized CLI output |
| `base64` | Encoding & decoding encrypted logs |
| `email.mime.text` | Formatting email messages |

---

## 🔍 Detailed Breakdown

### **1️⃣ Network Scanning**
#### **What this part is about?**
This section scans a given IP range to identify active devices on the network.

#### **Main logic:**
- Uses **ARP scanning** to detect devices.
- Sends **ARP requests** and listens for responses.
- Collects and displays **IP and MAC addresses** of active hosts.

```python
from scapy.all import ARP, Ether, srp

def scan_ip_range(ip_range):
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result = srp(packet, timeout=2, verbose=False)[0]
    
    active_hosts = []
    for sent, received in result:
        active_hosts.append({'ip': received.psrc, 'mac': received.hwsrc})
    
    return active_hosts
```

#### **Outcome:**
- Successfully lists all active devices in the network.
- Provides a clear mapping of **IP addresses to MAC addresses**.

💡 **Output Example:**
```
Scanning network...
Active Hosts Found:
192.168.1.10 - MAC: 00:1A:2B:3C:4D:5E
192.168.1.12 - MAC: 00:1A:2B:3C:4D:5F
```

---

### **2️⃣ Port Scanning & Banner Grabbing**
#### **What this part is about?**
This section scans a device for **open ports** and identifies services running on them.

#### **Main logic:**
- Uses **TCP socket connections** to check if ports are open.
- Sends **a small payload** to trigger banner responses.
- Captures and displays **service information** running on open ports.

```python
import socket

def scan_ports(ip, ports):
    open_ports = {}
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            if sock.connect_ex((ip, port)) == 0:
                sock.send(b'\n')  # Trigger banner response
                banner = sock.recv(1024).decode().strip()
                open_ports[port] = banner if banner else "Unknown Service"
            sock.close()
        except:
            pass
    return open_ports
```

#### **Outcome:**
- Detects **which ports are open** on a target machine.
- Identifies **what services are running** on those ports.

💡 **Output Example:**
```
Scanning 192.168.1.10...
Open Ports:
- 22: OpenSSH 7.9
- 80: Apache HTTP Server
- 3306: MySQL Database
```

---

### **3️⃣ Packet Sniffing**
#### **What this part is about?**
This section **monitors live network traffic** and analyzes packets.

#### **Main logic:**
- Uses **Scapy’s `sniff()` function** to capture packets.
- Extracts **source & destination IP addresses**.
- Identifies **TCP, UDP, and ICMP traffic**.

```python
from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    if packet.haslayer(IP):
        print(f"Packet: {packet[IP].src} -> {packet[IP].dst}")
    if packet.haslayer(TCP):
        print(f"TCP Packet: {packet[TCP].sport} -> {packet[TCP].dport}")
    if packet.haslayer(UDP):
        print(f"UDP Packet: {packet[UDP].sport} -> {packet[UDP].dport}")

sniff(prn=packet_callback, store=False)
```

#### **Outcome:**
- Captures **real-time network traffic**.
- Identifies **which devices are communicating**.

💡 **Output Example:**
```
Packet: 192.168.1.10 -> 8.8.8.8
TCP Packet: 50542 -> 443 (HTTPS Request)
```

---

## 📌 Installation & Usage
### **Install Dependencies:**
```bash
pip install scapy tqdm networkx matplotlib pycryptodome termcolor
```

### **Run the Program:**
```bash
python network_monitor.py
```

---


