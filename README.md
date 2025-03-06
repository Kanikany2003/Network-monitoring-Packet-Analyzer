# Network Monitoring & Packet Analyzer

## Overview
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

---

## 🔍 Detailed Breakdown

### **1️⃣ Network Scanning**
📌 **Finds active devices & detects open ports**

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

💡 **Output Example:**
```
Scanning network...
Active Hosts Found:
192.168.1.10 - MAC: 00:1A:2B:3C:4D:5E
192.168.1.12 - MAC: 00:1A:2B:3C:4D:5F
```

---

### **2️⃣ Port Scanning & Banner Grabbing**
📌 **Identifies open ports and services running on them**

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
📌 **Monitors network traffic for suspicious activity**

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

💡 **Output Example:**
```
Packet: 192.168.1.10 -> 8.8.8.8
TCP Packet: 50542 -> 443 (HTTPS Request)
```

---

### **4️⃣ Network Visualization**
📌 **Generates a network topology graph**

```python
import networkx as nx
import matplotlib.pyplot as plt

def plot_network_graph(devices):
    G = nx.Graph()
    for device in devices:
        G.add_node(device['ip'], label=f"{device['ip']} [MAC: {device['mac']}")
    nx.draw(G, with_labels=True, node_color='skyblue', node_size=2000, font_size=10)
    plt.show()
```

💡 **Graph Example:**
![Network Topology](https://user-images.githubusercontent.com/example/network-graph.png)

---

### **5️⃣ Secure Logging (AES Encryption)**
📌 **Encrypts scan logs to prevent tampering**

```python
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
import base64

SECRET_KEY = b"MySecureKey12345"

def encrypt_log(data):
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv=b"0123456789abcdef")
    encrypted = cipher.encrypt(pad(data.encode(), AES.block_size))
    return base64.b64encode(cipher.iv + encrypted).decode()
```

💡 **Output Example (Encrypted Log):**
```
U2FsdGVkX1+abx....
```

---

### **6️⃣ Real-Time Email Alerts**
📌 **Notifies admins when anomalies are detected**

```python
import smtplib
from email.mime.text import MIMEText

def send_alert(subject, body):
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = "your_email@gmail.com"
    msg["To"] = "admin@gmail.com"
    server = smtplib.SMTP("smtp.gmail.com", 587)
    server.starttls()
    server.login("your_email@gmail.com", "your_password")
    server.sendmail("your_email@gmail.com", "admin@gmail.com", msg.as_string())
    server.quit()
```

💡 **Alert Example:**
```
[ALERT] Suspicious Activity Detected!
An unauthorized IP 192.168.1.50 is scanning ports.
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

## 📜 License
This project is **open-source** under the **MIT License**. Feel free to contribute and improve! 😊
