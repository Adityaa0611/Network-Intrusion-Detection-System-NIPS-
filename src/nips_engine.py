import joblib
import pandas as pd
import time
import os
import socket
import warnings
import signal
import sys
import csv
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP
from fpdf import FPDF

warnings.filterwarnings("ignore")

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(BASE_DIR, "models", "phase1_model.pkl")
ENCODER_PATH = os.path.join(BASE_DIR, "models", "attack_encoder.pkl")
FEATURE_PATH = os.path.join(BASE_DIR, "models", "feature_columns.pkl")
LOG_PATH = os.path.join(BASE_DIR, "data", "live_logs.csv")
REPORT_DIR = os.path.join(BASE_DIR, "reports")

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except:
        return "127.0.0.1"

MY_IP = get_local_ip()
INTERFACE = "enp0s3" if os.name != "nt" else None
BLOCKED_IPS = set()
ATTACK_LOGS = []

print("="*65)
print("🛡️  AI-DRIVEN NETWORK INTRUSION PREVENTION SYSTEM (AI-NIPS)")
print(f"[*] Local Host IP: {MY_IP}")
print(f"[*] Active Interface: {INTERFACE if INTERFACE else 'Default System Interface'}")
print("="*65)

try:
    model = joblib.load(MODEL_PATH)
    attack_encoder = joblib.load(ENCODER_PATH)
    feature_cols = joblib.load(FEATURE_PATH)
    print(f"[+] AI Brain Online: Loaded XGBoost model ({len(feature_cols)} flow features).")
except Exception as e:
    print(f"[!] Error loading model artifacts: {e}")
    sys.exit(1)

flow_memory = {}
ip_ports = {}

if not os.path.exists(LOG_PATH):
    with open(LOG_PATH, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Time", "IP", "Port", "Type", "Action"])

def log_to_dashboard(ip, port, attack_type, action):
    try:
        with open(LOG_PATH, "a", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([datetime.now().strftime("%H:%M:%S"), ip, port, attack_type, action])
    except Exception:
        pass

def generate_pdf_report():
    if not ATTACK_LOGS:
        print("\n[+] No malicious intrusions recorded during this session.")
        return

    print("\n[*] Generating Forensic Security PDF Report...")
    os.makedirs(REPORT_DIR, exist_ok=True)

    pdf = FPDF()
    pdf.add_page()
    
    pdf.set_font("Arial", 'B', 16)
    pdf.cell(190, 10, txt="AI-NIPS: Security Incident & Forensic Report", ln=True, align='C')
    pdf.ln(5)

    pdf.set_font("Arial", 'B', 11)
    pdf.cell(190, 8, txt=f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True)
    pdf.cell(190, 8, txt=f"Total Malicious Hosts Contained: {len(BLOCKED_IPS)}", ln=True)
    pdf.ln(5)

    pdf.set_font("Arial", 'B', 10)
    pdf.cell(45, 10, "Timestamp", border=1)
    pdf.cell(45, 10, "Attacker IP", border=1)
    pdf.cell(100, 10, "Attack Classification", border=1)
    pdf.ln()

    pdf.set_font("Arial", '', 9)
    for log in ATTACK_LOGS:
        pdf.cell(45, 8, log['time'], border=1)
        pdf.cell(45, 8, log['ip'], border=1)
        pdf.cell(100, 8, log['type'], border=1)
        pdf.ln()

    filename = f"NIPS_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    filepath = os.path.join(REPORT_DIR, filename)
    pdf.output(filepath)
    print(f"[✅] Forensic Report Successfully Generated: {filepath}")

def ban_attacker(ip_address, attack_type, port=0):
    if ip_address not in BLOCKED_IPS:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"\n[🚨 MITIGATION] Banning {ip_address} for {attack_type}...")
        
        # Apply iptables drop rule on Linux platforms
        if os.name != "nt":
            os.system(f"sudo iptables -A INPUT -s {ip_address} -j DROP")
            
        BLOCKED_IPS.add(ip_address)
        ATTACK_LOGS.append({'time': timestamp, 'ip': ip_address, 'type': attack_type})
        log_to_dashboard(ip_address, port, attack_type, "BANNED")
        print(f"[🛡️ STATUS] Access permanently revoked via IPTables.\n")

def process_packet(pkt):
    if not IP in pkt: return
    
    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst
    
    if src_ip == MY_IP or src_ip in BLOCKED_IPS: return
    if src_ip == "0.0.0.0" or src_ip.startswith("224.") or src_ip.startswith("239."): return
    if dst_ip == "255.255.255.255" or dst_ip.endswith(".255"): return

    proto = pkt[IP].proto
    dport = pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else 0)

    # Heuristic Reconnaissance Detection (Port Scan velocity)
    if src_ip not in ip_ports:
        ip_ports[src_ip] = set()
    if dport != 0:
        ip_ports[src_ip].add(dport)

    if len(ip_ports[src_ip]) > 20:
        print(f"[🚨] {src_ip} -> RECONNAISSANCE DETECTED (Port Scan)!", flush=True)
        ban_attacker(src_ip, "RECONNAISSANCE (Port Scan)", dport)
        return

    # Statistical Flow Feature Extraction
    flow_key = (src_ip, dst_ip, dport, proto)
    if flow_key not in flow_memory:
        flow_memory[flow_key] = {'start': time.time(), 'fwd_pkts': 0, 'fwd_len': 0, 'max_len': 0}
    
    f = flow_memory[flow_key]
    f['fwd_pkts'] += 1
    f['fwd_len'] += len(pkt)
    f['max_len'] = max(f['max_len'], len(pkt))
    
    if f['fwd_pkts'] < 3: return

    duration = int((time.time() - f['start']) * 1000000) # Duration in microseconds
    live_row = [dport, proto, duration, f['fwd_pkts'], 0, f['fwd_len'], f['max_len']]
    df_live = pd.DataFrame([live_row], columns=feature_cols)

    pred_idx = model.predict(df_live)[0]
    attack_label = attack_encoder.inverse_transform([pred_idx])[0]

    if attack_label in ["Benign", "Normal"]:
        log_to_dashboard(src_ip, dport, "NORMAL", "ALLOWED")
    else:
        print(f"[🚨 THREAT DETECTED] {src_ip} -> {attack_label.upper()}!", flush=True)
        ban_attacker(src_ip, attack_label.upper(), dport)

def graceful_shutdown(sig, frame):
    print("\n\n[*] Shutting down NIPS Engine gracefully...")
    try:
        generate_pdf_report()
    except Exception as e:
        print(f"[!] Error generating PDF: {e}")
    print("[*] NIPS Offline. Stay safe.")
    sys.exit(0)

if __name__ == "__main__":
    signal.signal(signal.SIGINT, graceful_shutdown)
    if os.name != "nt":
        os.system("sudo iptables -F")
    print("[*] Sensor live. Capturing traffic... (Press Ctrl+C to generate PDF report)\n")
    if INTERFACE:
        sniff(iface=INTERFACE, prn=process_packet, store=False)
    else:
        sniff(prn=process_packet, store=False)
