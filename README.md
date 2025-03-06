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

### **1️⃣ Logging & Security System (Logger Class)**
#### **What this part is about?**
Handles **secure logging** by encrypting logs to prevent tampering.

#### **Main logic:**
- Uses **AES encryption** to encrypt logs.
- Stores logs in a secure format.
- Ensures only authorized access.

```python
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
import base64

def encrypt_log(data):
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv=b"0123456789abcdef")
    encrypted = cipher.encrypt(pad(data.encode(), AES.block_size))
    return base64.b64encode(cipher.iv + encrypted).decode()
```

#### **Outcome:**
- Logs remain **encrypted and secure**.
- Prevents **unauthorized access or tampering**.

---

### **2️⃣ Email Alert System (AlertSystem Class)**
#### **What this part is about?**
Sends **real-time email alerts** when anomalies are detected.

#### **Main logic:**
- Uses **SMTP** to send emails.
- Notifies **security teams or admins**.
- Provides **instant response to threats**.

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

#### **Outcome:**
- Sends **instant alerts** upon detecting suspicious activity.
- Notifies **admins/security teams** in real time.

---

### **3️⃣ Network Scanning (NetworkScanner Class)**
#### **What this part is about?**
Scans **networks for active hosts and open ports**.

#### **Main logic:**
- Uses **ARP scanning** to find devices.
- Performs **SYN scans** to detect **open ports**.
- Identifies **running services & operating systems**.

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
- **Finds active hosts & their MAC addresses**.
- Identifies **open ports & running services**.

---

### **4️⃣ Packet Sniffing & Traffic Analysis**
#### **What this part is about?**
Monitors **live network traffic** and detects suspicious activity.

#### **Main logic:**
- Captures **real-time network packets**.
- Detects **TCP, UDP, and ICMP traffic**.
- Identifies **potential anomalies**.

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
- **Detects & classifies traffic in real time**.
- Helps **analyze potential network threats**.

---

### **5️⃣ Network Visualization (Graphing Network Topology)**
#### **What this part is about?**
Visualizes **network topology using graphs**.

#### **Main logic:**
- Uses **NetworkX & Matplotlib** to draw network structures.
- Represents **devices & their connections**.

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

#### **Outcome:**
- Provides **a clear visualization of the network**.
- Helps **understand network topology & device connectivity**.

---

### **6️⃣ User Interface & Menu System**
#### **What this part is about?**
Allows **users to select features** interactively.

#### **Main logic:**
- Displays **a menu-driven interface**.
- Lets users **choose network scanning, sniffing, or visualization**.

```python
print("\nNetwork Scanner Menu:")
print("1. Port Scanning")
print("2. Packet Sniffing")
print("3. Network Topology")
print("4. Exit")
choice = input("Choose an option: ")
```

#### **Outcome:**
- Makes **navigation easy & user-friendly**.
- Provides a **clear menu to choose operations**.

---

