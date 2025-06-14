import paramiko
import re
import time

SWITCH_IP = "192.168.0.2"
USERNAME = "sysloguser"
PASSWORD = "hashbrown"
LOG_FILE = "/var/log/cisco9200.log"
DAI_PATTERN = r".*%SW_DAI-4-DHCP_SNOOPING_DENY.*.*, vlan"
ATTEMPTED = False

def follow(logfile_path):
    """Follow log file like tail -f."""
    with open(logfile_path, "r") as file:
        file.seek(0, 2)
        while True:
            line = file.readline()
            if not line:
                time.sleep(0.5)
                continue
            yield line.strip()

def ssh_and_shut_interface(mac):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(SWITCH_IP, username=USERNAME, password=PASSWORD)

    shell = ssh.invoke_shell()
    shell.send("terminal length 0\n")
    shell.send(f"show mac address-table | include {mac}\n")
    time.sleep(2)
    output = shell.recv(5000).decode()

    intf_match = re.search(rf"{mac}.*(Gi\S+)", output)
    if intf_match:
        intf = intf_match.group(1)
        print(f"Shutting down interface {intf} for MAC {mac}")
        shell.send("configure terminal\n")
        shell.send(f"interface {intf}\n")
        shell.send("shutdown\n")
        shell.send("end\n")
        ATTEMPTED = True
    else:
        print("MAC not found in MAC address-table.")
        if ATTEMPTED == True:
            print("Downed em")
            exit()

    ssh.close()

def monitor_log():
    for line in follow(LOG_FILE):
        match = re.search(DAI_PATTERN, line)
        if match:
            mac_match = re.search( r'\[([^/]+)/[^/]+/([^/]+)/[^/]+', line, re.IGNORECASE)
            if mac_match:
                print(mac_match.group(1))
                attackermac = mac_match.group(1)
                ssh_and_shut_interface(attackermac)
            


if __name__ == "__main__":
    print("[*] Monitoring DAI violations in syslog...")
    monitor_log()