import socket
import struct
import time
import subprocess
import os
import sqlite3
import threading
import webbrowser
import platform
import uvicorn
from collections import defaultdict
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware

# --- CONFIGURATION ---
DB_PATH = 'firewall.db'
MAX_PACKETS = 20
TIME_WINDOW = 3
WHITELIST = ['127.0.0.1']

packet_tracker = defaultdict(list)
blocked_ips = set()

# ================= 1. DATABASE & LOGGING LOGIC =================
def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute('''CREATE TABLE IF NOT EXISTS traffic_logs (id INTEGER PRIMARY KEY, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, source_ip TEXT, protocol TEXT, packet_size INTEGER)''')
    conn.execute('''CREATE TABLE IF NOT EXISTS blocked_ips (id INTEGER PRIMARY KEY, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, ip_address TEXT, reason TEXT)''')
    conn.execute('''CREATE TABLE IF NOT EXISTS system_logs (id INTEGER PRIMARY KEY, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, level TEXT, message TEXT)''')
    conn.commit()
    conn.close()

def log_system_event(level, message):
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("INSERT INTO system_logs (level, message) VALUES (?, ?)", (level, message))
        conn.commit()
        conn.close()
    except Exception: pass

def log_traffic(ip, proto, size):
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("INSERT INTO traffic_logs (source_ip, protocol, packet_size) VALUES (?, ?, ?)", (ip, proto, size))
        conn.commit()
        conn.close()
    except Exception: pass

def execute_block(ip, reason):
    if ip in blocked_ips or ip in WHITELIST: return
    print(f"\n[!] THREAT DETECTED: BLOCKING IP {ip}")
    log_system_event("CRITICAL", f"Attack detected from {ip}. Reason: {reason}. Initiating OS block.")
    
    cmd = f'netsh advfirewall firewall add rule name="SaaS_Block_{ip}" dir=in action=block remoteip={ip}'
    subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    blocked_ips.add(ip)
    
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("INSERT INTO blocked_ips (ip_address, reason) VALUES (?, ?)", (ip, reason))
        conn.commit()
        conn.close()
        log_system_event("SUCCESS", f"IP {ip} successfully blocked in Windows Defender Firewall.")
    except Exception: pass

# ================= 2. CORE ENGINE (SNIFFER THREAD) =================
def start_engine():
    local_ip = socket.gethostbyname(socket.gethostname())
    if local_ip not in WHITELIST: WHITELIST.append(local_ip)
    
    log_system_event("INFO", f"Firewall Core Engine started on {local_ip}")
    log_system_event("INFO", f"OS Info: {platform.system()} {platform.release()}")
    
    try:
        sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        sniffer.bind((local_ip, 0))
        sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        print(f"[*] Core Engine Sniffing on {local_ip}...")
    except PermissionError:
        print("\n[!] ERROR: You MUST run this script as Administrator!")
        log_system_event("ERROR", "Failed to start sniffer. Admin privileges required.")
        os._exit(1)

    while True:
        try:
            raw_data, _ = sniffer.recvfrom(65535)
            ip_header = raw_data[0:20]
            iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
            src_ip = socket.inet_ntoa(iph[8])
            proto = "TCP" if iph[6] == 6 else ("UDP" if iph[6] == 17 else ("ICMP" if iph[6] == 1 else "OTHER"))
            
            if src_ip not in blocked_ips and src_ip not in WHITELIST:
                log_traffic(src_ip, proto, len(raw_data))
                curr_time = time.time()
                packet_tracker[src_ip].append(curr_time)
                packet_tracker[src_ip] = [t for t in packet_tracker[src_ip] if curr_time - t <= TIME_WINDOW]
                
                # Check for attack
                if len(packet_tracker[src_ip]) > MAX_PACKETS:
                    execute_block(src_ip, "DDoS / Ping Flood Detected (Rate Limit Exceeded)")
        except Exception: pass

# ================= 3. FASTAPI & FRONTEND DASHBOARD =================
app = FastAPI(title="SaaS Firewall")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

def query_db(query, fetchall=True):
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(query)
        res = cursor.fetchall() if fetchall else cursor.fetchone()
        conn.close()
        return res
    except Exception: return [] if fetchall else (0,)

# --- PAGE 1: MAIN DASHBOARD ---
@app.get("/")
def serve_dashboard():
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>byte3 Dashboard</title>
        <style>
            body { background: #0f172a; color: #f8fafc; font-family: 'Segoe UI', Tahoma, sans-serif; padding: 20px; margin: 0; }
            .header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #334155; padding-bottom: 15px; }
            .status { color: #10b981; font-weight: bold; }
            .btn { background: #3b82f6; color: white; padding: 10px 15px; text-decoration: none; border-radius: 5px; font-weight: bold; transition: 0.3s; }
            .btn:hover { background: #2563eb; }
            .stats-grid { display: flex; gap: 20px; margin: 20px 0; }
            .card { background: #1e293b; padding: 20px; flex: 1; border-left: 4px solid #3b82f6; border-radius: 8px; }
            .card h3 { margin: 0 0 10px 0; color: #94a3b8; }
            .card h1 { margin: 0; font-size: 2.5em; }
            .threat-card { border-left-color: #ef4444; }
            .tables-grid { display: flex; gap: 20px; }
            .table-box { background: #1e293b; padding: 20px; flex: 1; border-radius: 8px; height: 350px; overflow-y: auto;}
            table { width: 100%; border-collapse: collapse; margin-top: 10px; }
            th, td { padding: 10px; text-align: left; border-bottom: 1px solid #334155; font-size: 0.9em; }
            th { color: #94a3b8; position: sticky; top: 0; background: #1e293b; }
            .badge { background: #ef4444; color: white; padding: 4px 8px; border-radius: 4px; font-size: 0.85em;}
        </style>
    </head>
    <body>
        <div class="header">
            <div>
                <h2 style="margin:0;">🛡️Byte3 SaaS WAF</h2>
                <span class="status">● Defense Engine Active</span>
            </div>
            <a href="/logs" class="btn" target="_blank">📄 View System Logs</a>
        </div>
        <div class="stats-grid">
            <div class="card"><h3>Traffic Monitored</h3><h1 id="req-count">0</h1></div>
            <div class="card threat-card"><h3>Threats Blocked</h3><h1 id="block-count">0</h1></div>
        </div>
        <div class="tables-grid">
            <div class="table-box">
                <h3 style="margin-top:0;">Live Traffic Monitor</h3>
                <table><thead><tr><th>Time</th><th>Source IP</th><th>Protocol</th></tr></thead><tbody id="traffic-table"></tbody></table>
            </div>
            <div class="table-box">
                <h3 style="margin-top:0;">Firewall Blocklist</h3>
                <table><thead><tr><th>Time</th><th>Attacker IP</th><th>Reason</th></tr></thead><tbody id="block-table"></tbody></table>
            </div>
        </div>
        <script>
            async function updateDashboard() {
                try {
                    const stats = await (await fetch('/api/stats')).json();
                    document.getElementById('req-count').innerText = stats.requests;
                    document.getElementById('block-count').innerText = stats.blocked;

                    const traffic = await (await fetch('/api/traffic')).json();
                    document.getElementById('traffic-table').innerHTML = traffic.map(r => 
                        `<tr><td style="color:#94a3b8;">${r.time.split(' ')[1]}</td><td>${r.ip}</td><td>${r.protocol}</td></tr>`
                    ).join('');

                    const blocked = await (await fetch('/api/blocked')).json();
                    document.getElementById('block-table').innerHTML = blocked.map(r => 
                        `<tr><td style="color:#94a3b8;">${r.time.split(' ')[1]}</td><td><span class="badge">${r.ip}</span></td><td>${r.reason}</td></tr>`
                    ).join('');
                } catch (e) { }
            }
            setInterval(updateDashboard, 1500);
            updateDashboard();
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)

# --- PAGE 2: DETAILED LOGS PAGE ---
@app.get("/logs")
def serve_logs_page():
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>System & Traffic Logs - byte3</title>
        <style>
            body { background: #000; color: #0f0; font-family: 'Courier New', Courier, monospace; padding: 20px; margin: 0; }
            .header { border-bottom: 1px solid #0f0; padding-bottom: 10px; margin-bottom: 20px; display: flex; justify-content: space-between;}
            .log-container { background: #111; border: 1px solid #333; padding: 15px; border-radius: 5px; height: 300px; overflow-y: auto; margin-bottom: 20px; }
            h3 { color: #fff; margin-top: 0; }
            .log-line { margin: 5px 0; border-bottom: 1px dashed #222; padding-bottom: 5px; }
            .level-INFO { color: #3b82f6; font-weight: bold; }
            .level-CRITICAL { color: #ef4444; font-weight: bold; }
            .level-SUCCESS { color: #10b981; font-weight: bold; }
            .level-ERROR { color: #f59e0b; font-weight: bold; }
            .req-log { color: #aaa; }
        </style>
    </head>
    <body>
        <div class="header">
            <h2>⚙️ BYTE3 SYSTEM LOGS</h2>
            <a href="/" style="color: #fff; text-decoration: none; border: 1px solid #fff; padding: 5px 10px;">← Back to Dashboard</a>
        </div>
        
        <h3>[System Events]</h3>
        <div class="log-container" id="sys-logs">Loading system events...</div>

        <h3>[All Raw Traffic Requests]</h3>
        <div class="log-container" id="req-logs">Loading traffic logs...</div>

        <script>
            async function fetchLogs() {
                try {
                    const sysLogs = await (await fetch('/api/syslogs')).json();
                    document.getElementById('sys-logs').innerHTML = sysLogs.map(r => 
                        `<div class="log-line">[${r.time}] <span class="level-${r.level}">[${r.level}]</span> ${r.msg}</div>`
                    ).join('');

                    const reqLogs = await (await fetch('/api/traffic_all')).json();
                    document.getElementById('req-logs').innerHTML = reqLogs.map(r => 
                        `<div class="log-line req-log">[${r.time}] INBOUND -> SRC: ${r.ip} | PROTOCOL: ${r.protocol} | SIZE: ${r.size} bytes</div>`
                    ).join('');
                } catch (e) { }
            }
            setInterval(fetchLogs, 2000);
            fetchLogs();
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)

# --- API ENDPOINTS ---
@app.get("/api/stats")
def get_stats():
    reqs = query_db("SELECT COUNT(*) FROM traffic_logs", fetchall=False)
    blocked = query_db("SELECT COUNT(*) FROM blocked_ips", fetchall=False)
    return {"requests": reqs[0] if reqs else 0, "blocked": blocked[0] if blocked else 0}

@app.get("/api/traffic")
def get_traffic():
    rows = query_db("SELECT timestamp, source_ip, protocol, packet_size FROM traffic_logs ORDER BY id DESC LIMIT 10")
    return [{"time": r[0], "ip": r[1], "protocol": r[2], "size": r[3]} for r in rows]

@app.get("/api/traffic_all")
def get_traffic_all():
    rows = query_db("SELECT timestamp, source_ip, protocol, packet_size FROM traffic_logs ORDER BY id DESC LIMIT 100")
    return [{"time": r[0], "ip": r[1], "protocol": r[2], "size": r[3]} for r in rows]

@app.get("/api/blocked")
def get_blocked():
    rows = query_db("SELECT timestamp, ip_address, reason FROM blocked_ips ORDER BY id DESC")
    return [{"time": r[0], "ip": r[1], "reason": r[2]} for r in rows]

@app.get("/api/syslogs")
def get_syslogs():
    rows = query_db("SELECT timestamp, level, message FROM system_logs ORDER BY id DESC LIMIT 50")
    return [{"time": r[0], "level": r[1], "msg": r[2]} for r in rows]

# ================= 4. MAIN LAUNCHER =================
if __name__ == "__main__":
    print("[*] Initializing Database & Log System...")
    init_db()
    
    # 1. Start Sniffer Engine in a background thread
    engine_thread = threading.Thread(target=start_engine, daemon=True)
    engine_thread.start()
    
    print("[*] Starting Web Server...")
    
    # 2. Auto-open main dashboard
    threading.Timer(1.5, lambda: webbrowser.open("http://127.0.0.1:8000")).start()
    
    # 3. Start FastAPI Server
    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="error")