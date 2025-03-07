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

**Example Encrypted Log Output:**
```
U2FsdGVkX1+abx....
```

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

**Example Alert Message:**
```
[ALERT] Suspicious Activity Detected!
An unauthorized IP 192.168.1.50 is scanning ports.
```

---

### **3️⃣ Stealth scanner (NetworkScanner Class)**
#### **What this part is about?**
Focuses on **stealth scanning (SYN scan) and OS detection.**

#### **Main logic:**
- Performs **SYN scans** to detect **open ports**.
- Performs **stealthy reconnaissance** on a specific target.
- Uses **randomized delays** and **logs alerts**.

```python
from scapy.all import ARP, Ether, srp

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

    Logger.log_secure(json.dumps(results))
    print(json.dumps(results, indent=4))
```

#### **Outcome:**
- **Finds open/closed/filtered** ports on a target IP.
- Uses **stealthy SYN scanning** (doesn't establish a full connection).
- **Identifies OS fingerprinting** based on TTL and TCP window size.
- **Generates alerts** if open ports are found.
- Saves results **securely in logs** (AES encrypted).

**Example Output:**
```
Enter target IP: 192.168.X.X
Performing SYN scan on 192.168.X.X...
Scanning Ports: 100%|██████████████████████████████████████| 5/5 [00:07<00:00,  1.48s/port]
{
    "22": "Closed",
    "80": "Open",
    "443": "Closed",
    "8080": "Closed",
    "3306": "Closed"
}
```

---

### **3️⃣ Network Discovery**
#### **What this part is about?**
Scans **networks for active hosts and open ports**.

#### **Main logic:**
- Focuses on **ARP-based host discovery** and **port scanning**.
- Performs **full network scanning over a range of IPs**.
- Includes **latency measurement** and **packet sniffing**.
- 
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
- **Finds active devices** on a network (via ARP scanning).
- **Scans open ports** on discovered hosts.
- **Measures latency** of responding hosts.

**Example Output:**
```
Starting IP scan on range: 192.168.X.X/24
Host 192.168.1.X is up (Latency: 3.9351 ms) [MAC: 3c:XX:XX:XX:XX:XX, OS: Linux (Ubuntu/Debian/Fedora)]

Scanning 192.168.1.X [MAC: 3c:XX:XX:XX:XX:XX] for ports [23, 80]
INFO:root:Starting port scan on 192.168.1.X for 2 ports.
INFO:root:Port 23 is open on 192.168.1.X
INFO:root:Port 80 is open on 192.168.1.X
INFO:root:Port scan complete. Open ports on 192.168.1.X: [23, 80]

Open ports on 192.168.0.1:
  - Port 23 is open; Service: No Banner
  - Port 80 is open; Service: No Banner
```

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
**Example Output:**
```
Enter the network interface name (e.g., en0, wlan0): en0

Choose port scan option:
1. Scan specific ports (e.g., 22, 80, 443)
2. Scan a range of ports (e.g., 21-100)
3. Exit
Choose an option (1, 2, 3): 1
```
```
Starting packet sniffing on en0 for monitored ports [22, 23, 80]...
Suspicious TCP Traffic: 192.168.1.X -> 17.123.XX.XXX (Port 80)
Suspicious TCP Traffic: 1192.168.1.X -> 17.123.XX.XXX (Port 80)
Saved 50 packets to captured_traffic.pcap
```

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

**Example Output:**
```
1️⃣ Port Scanning Menu:
1. Scan specific ports (e.g., 22, 80, 443)
2. Scan a range of ports (e.g., 21-100)
3. Scan all ports (1-65535)
4. Exit
Choose an option (1, 2, 3, 4):
```
```
2️⃣Choose an option (1, 2, 3, 4): 2
Available interfaces:
1. lo0
2. gif0
3. stf0
4. anpi1
5. anpi0
6. en3
7. en4
8. en1
9. en2
10. bridge0
11. ap1
12. en0
13. awdl0
14. llw0
15. utun0
16. utun1
17. utun2
18. utun3
19. utun4
20. utun5
21. utun6
22. utun7
23. vmenet0
24. bridge100
25. vmenet1
26. bridge101
Enter the network interface name (e.g., en0, wlan0): 
```
```
Choose port scan option:
1. Scan specific ports (e.g., 22, 80, 443)
2. Scan a range of ports (e.g., 21-100)
3. Exit
Choose an option (1, 2, 3):
```
---

