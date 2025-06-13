import socket
import time

TARGET_IP = "127.0.0.1"   # Replace with IP of the machine running your main script
TARGET_PORT = 514         # Syslog UDP port

# Fake DAI message format to test your regex and logic
fake_message = "%SW_DAI-4-DHCP_SNOOPING_DENY: 1 Invalid ARPs (Res) on Gi1/0/3, vlan 18.([1111.1111.1111/192.26.18.187/2222.2222.2222/192.26.18.115/01:09:03"

def send_fake_syslog():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for i in range(5):
        sock.sendto(fake_message.encode(), (TARGET_IP, TARGET_PORT))
        print(f"[FAKE LOG SENT] {fake_message}")
        time.sleep(1)
    sock.close()

if __name__ == "__main__":
    send_fake_syslog()
