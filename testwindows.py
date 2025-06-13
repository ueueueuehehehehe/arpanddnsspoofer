import socket
import re
import subprocess

INTERFACE = "eth0"  # or your interface, if needed for ARP poison subprocess
SYSLOG_PORT = 514
ERROR_THRESHOLD = 3

# Regex to extract MAC and IP from your Cisco syslog message
mac_ip_pattern = re.compile(r'\(?\[\s*([0-9a-fA-F\.:]{4,17})/(\d{1,3}(?:\.\d{1,3}){3})', re.IGNORECASE)

error_counts = {}

import subprocess
import sys
import platform

def start_poison_terminal(attacker_ip):
    gateway_ip = "192.168.1.1"  # <-- manually set your gateway IP here
    interface = INTERFACE        # keep your existing interface variable

    if platform.system() == "Windows":
        subprocess.Popen([
            "cmd.exe", "/k",
            sys.executable, "desertarpLoop.py",
            attacker_ip, gateway_ip, interface
        ])
    else:
        subprocess.Popen([
            "gnome-terminal", "--",
            sys.executable, "desertarpLoop.py",
            attacker_ip, gateway_ip, interface
        ])

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", SYSLOG_PORT))
    print(f"Listening on UDP port {SYSLOG_PORT} for syslog messages...")

    while True:
        data, addr = sock.recvfrom(4096)
        message = data.decode(errors="ignore")
        if "%SW_DAI-4-DHCP_SNOOPING_DENY" in message:
            match = mac_ip_pattern.search(message)
            if match:
                attacker_mac = match.group(1)
                attacker_ip = match.group(2)
                print(f"[DETECTED] Attacker MAC: {attacker_mac}, IP: {attacker_ip}")
                error_counts[attacker_ip] = error_counts.get(attacker_ip, 0) + 1
                print(f"[COUNT] {attacker_ip} error count: {error_counts[attacker_ip]}")
                if error_counts[attacker_ip] == ERROR_THRESHOLD:
                    start_poison_terminal(attacker_ip)

if __name__ == "__main__":
    main()
