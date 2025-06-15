#!/usr/bin/env python3
import re
import time
import paramiko

# Configuration
LOG_FILE = "/var/log/cisco9200.log" # location of rsyslog files
DAI_PATTERN = r".*%SW_DAI-4-DHCP_SNOOPING_DENY.*?on\s+(Gi\S+).*, vlan" # pattern to match for arp violation warning
SWITCH_IP = "192.168.0.2" # Management IP of switch
SSH_USER = "sysloguser"
SSH_PASS = "hashbrown"  # credentials of switch
SHUT_COMMAND = "shutdown" # action to take on violation interface

def follow(logfile_path): 
    """
    Follow log file like tail -f.
    Constantly reads the end of the the file
    """
    with open(logfile_path, "r") as file:
        file.seek(0, 2)
        while True:
            line = file.readline()
            if not line:
                time.sleep(0.5)
                continue
            yield line.strip()

def shutdown_interface(interface):
    """
    SSH into the switch and shut the specified interface.
    
    """
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(SWITCH_IP, username=SSH_USER, password=SSH_PASS, look_for_keys=False)

        remote_conn = ssh.invoke_shell()
        time.sleep(1)
        remote_conn.send("enable\n")
        time.sleep(0.5)
        # Add enable password prompt here if needed

        remote_conn.send("conf t\n")
        time.sleep(0.5)
        remote_conn.send(f"interface {interface}\n")
        time.sleep(0.5)
        remote_conn.send("shutdown\n")
        time.sleep(0.5)
        remote_conn.send("end\n")
        remote_conn.send("exit\n")
        time.sleep(1)
        ssh.close()
        print(f"[ACTION] Interface {interface} shut down successfully.")
        exit()
    except Exception as e:
        print(f"[ERROR] SSH failed: {e}")

def monitor_log():
    '''
    searches each log file for the matching error
    
    '''
    for line in follow(LOG_FILE):
        print(line)
        match = re.search(DAI_PATTERN, line)
        if match:
            interface = match.group(1)
            print(f"[ALERT] DAI violation on {interface}")
            shutdown_interface(interface)


if __name__ == "__main__":
    print("[*] Monitoring DAI violations in syslog...")
    monitor_log()