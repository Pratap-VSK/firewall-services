# 🛡️ byte3: SaaS Monolithic Active WAF

A real-time, monolithic Active Web Application Firewall (WAF) and Intrusion Prevention System (IPS) built entirely in Python. CloudFire automatically sniffs network traffic, detects flood attacks (DDoS/Ping floods), and permanently blocks malicious IPs at the OS level using Windows Defender Firewall. 

It features an embedded SQLite database and a sleek, multi-page dark-theme dashboard served via FastAPI—all running from a single `app.py` file.

## 🚀 Key Features

* **Zero-Config Monolithic Architecture:** The packet sniffer, API, database, and frontend UI are entirely contained within a single Python script.
* **Active Threat Neutralization:** Doesn't just alert—it actively executes OS-level commands (`netsh`) to block malicious IPs in real-time.
* **Raw Socket Sniffing:** Uses pure Python `socket` libraries to inspect inbound packets without relying on external packet-capture drivers like Wireshark/Npcap.
* **Real-Time Dashboard:** A responsive HTML/JS dashboard that auto-refreshes every 1.5 seconds to show traffic stats and blocklists.
* **Advanced System Logging:** A dedicated Terminal-style `/logs` interface to audit system events, blocking actions, and raw inbound requests.
* **Smart Rate Limiting:** Configurable sliding-window packet tracking to differentiate between normal traffic and malicious floods.

## 🛠️ Tech Stack

* **Core Engine:** Python 3 (Raw Sockets, Threading, Subprocess)
* **Backend API:** FastAPI, Uvicorn
* **Database:** SQLite3 (Embedded)
* **Frontend:** HTML5, CSS3, Vanilla JavaScript (Embedded in Python)
* **OS Integration:** Windows Defender Firewall (`netsh advfirewall`)

## ⚙️ Prerequisites

1. **Windows Operating System** (The blocking module specifically uses Windows Firewall commands).
2. **Administrator Privileges** (Required to bind raw sockets and modify firewall rules).
3. **Python 3.8+**

## 📥 Installation

1. Clone the repository:
```
bash
git clone [https://github.com/yourusername/CloudFire-WAF.git](https://github.com/yourusername/CloudFire-WAF.git)
cd CloudFire-WAF
```
install the required API dependencies:
```
Bash
pip install fastapi uvicorn
```
🚀 Usage & Deployment
Open your terminal or command prompt As Administrator.

Run the application:
```
Bash
python firewall.py
```
The system will automatically initialize the database, start the background sniffer thread, and open the dashboard in your default web browser at http://127.0.0.1:8000.

🎯 How to Test the Defense Engine
To verify that the active blocking works, you can simulate a flood attack from another device on the same network (e.g., your smartphone using Termux, or another laptop).

Find your machine's local IP address (shown in the terminal when you start CloudFire).

From the second device, execute a ping flood:
```
Linux/Android: ping -f <YOUR_IP>

Windows: ping -t -l 65500 <YOUR_IP> (and run multiple instances)
```
The Result: Within 3 seconds, CloudFire will detect the anomaly, log the threat, execute the block command, and the attacking device will immediately receive "Request timed out" errors indefinitely.

⚠️ Disclaimer
This tool is designed for educational purposes, portfolio demonstration, and authorized network testing only. The author is not responsible for any misuse, unintended network lockouts, or damage caused by deploying this script in uncontrolled environments. Do not use this software on systems you do not own or have explicit permission to monitor and alter.
