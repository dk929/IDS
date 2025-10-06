from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import defaultdict
import time

# Thresholds for alerts
PORT_SCAN_THRESHOLD = 10
ICMP_THRESHOLD = 15

# Track activity
port_activity = defaultdict(set)
icmp_counter = defaultdict(int)

def detect_packet(packet):
    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst

        # Detect Port Scan
        if TCP in packet or UDP in packet:
            port = packet[TCP].dport if TCP in packet else packet[UDP].dport
            port_activity[src].add(port)
            if len(port_activity[src]) > PORT_SCAN_THRESHOLD:
                alert = f"[!] Possible Port Scan Detected from {src} -> {len(port_activity[src])} ports"
                log_alert(alert)

        # Detect ICMP Flood
        elif ICMP in packet:
            icmp_counter[src] += 1
            if icmp_counter[src] > ICMP_THRESHOLD:
                alert = f"[!] ICMP Flood Detected from {src} ({icmp_counter[src]} pings)"
                log_alert(alert)

def log_alert(message):
    print(message)
    with open("alerts.log", "a") as log:
        log.write(f"{time.ctime()} - {message}\n")

print("🔍 Starting IDS... (Press Ctrl+C to stop)")
sniff(prn=detect_packet, store=False, iface="lo")
