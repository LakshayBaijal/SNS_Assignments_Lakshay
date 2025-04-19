import os
import sys
import time
from datetime import datetime
import subprocess
from collections import defaultdict, deque
import threading
from scapy.all import sniff, IP, TCP, UDP, ICMP, Ether
from scapy.error import Scapy_Exception 
from scapy.config import conf
import argparse
import platform
from textwrap import shorten

conf.use_bpf = False

class NIDS:
    def _init_(self):
        self.port_scan_data = defaultdict(list)
        self.fingerprint_data = defaultdict(list)
        self.blocked_ips = set()
        self.internal_block_list = set()
        self.running = False
        self.sniff_thread = None
        self.log_file = "ids.log"
        self.block_list_file = "blocked_ips.txt"
        self.block_method = "both"
        self.packet_buffer = deque(maxlen=100)
        self.PORT_SCAN_THRESHOLD = 3
        self.PORT_SCAN_WINDOW = 10
        self.FINGERPRINT_THRESHOLD = 5
        self.FINGERPRINT_WINDOW = 20
        self.load_blocked_ips()

    def load_blocked_ips(self):
        try:
            with open(self.block_list_file, 'r') as f:
                self.internal_block_list.update(line.strip() for line in f if line.strip())
        except FileNotFoundError:
            pass

    def save_blocked_ips(self):
        with open(self.block_list_file, 'w') as f:
            for ip in self.internal_block_list:
                f.write(f"{ip}\n")

    def block_ip(self, ip, method=None):
        method = method or self.block_method
        if ip in self.internal_block_list:
            return
            
        self.internal_block_list.add(ip)
        self.log(f"Blocked IP: {ip}")
        
        if method in ("firewall", "both"):
            try:
                if platform.system() == "Linux":
                    subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
                elif platform.system() == "Windows":
                    subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule", 
                                  f"name=Block_{ip}", "dir=in", "action=block", 
                                  f"remoteip={ip}"], check=True)
            except subprocess.CalledProcessError as e:
                self.log(f"Firewall block failed: {str(e)}")
        
        self.save_blocked_ips()

    def unblock_ip(self, ip):
        if ip not in self.internal_block_list:
            return
            
        self.internal_block_list.discard(ip)
        try:
            if platform.system() == "Linux":
                subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            elif platform.system() == "Windows":
                subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule",
                               f"name=Block_{ip}"], check=True)
        except subprocess.CalledProcessError as e:
            self.log(f"Firewall unblock failed: {str(e)}")
        
        self.save_blocked_ips()

    def clear_block_list(self):
        for ip in list(self.internal_block_list):
            self.unblock_ip(ip)

    def should_block_packet(self, packet):
        return IP in packet and packet[IP].src in self.internal_block_list

    def log(self, message, intrusion_type=None, attacker_ip=None, target=None, time_span=None):
        timestamp = datetime.now().strftime("%d-%m-%y %H:%M:%S")
        if intrusion_type:
            log_entry = f"{timestamp} — {intrusion_type} — {attacker_ip} — {target} — {time_span}s\n"
            with open(self.log_file, 'a') as f:
                f.write(log_entry)
            print(f"\n[ALERT] {log_entry}", end='')
        else:
            print(f"[LOG] {timestamp} — {message}")

    def analyze_packet(self, packet):
        try:
            if not packet.haslayer(IP) or not packet.haslayer(Ether):
                return
            
            if self.should_block_packet(packet):
                return
            
            self.packet_buffer.append(packet)

            ip_src = packet[IP].src
            if packet.haslayer(TCP):
                self.detect_port_scan(ip_src, packet[TCP].dport)
                self.detect_os_fingerprinting(ip_src, packet[TCP].flags)
        except Exception as e:
            self.log(f"Packet analysis error: {str(e)}")
        
    def detect_port_scan(self, ip, port):
        current_time = time.time()
        self.port_scan_data[ip].append((current_time, port))
        self.port_scan_data[ip] = [(t, p) for t, p in self.port_scan_data[ip] if current_time - t <= self.PORT_SCAN_WINDOW]
        
        if len(set(p for t, p in self.port_scan_data[ip])) >= self.PORT_SCAN_THRESHOLD:
            self.log("Port scanning detected", "PORT_SCAN", ip, f"ports: {', '.join(str(p) for t, p in self.port_scan_data[ip])}", 
                    round(max(t for t, p in self.port_scan_data[ip]) - min(t for t, p in self.port_scan_data[ip]), 2))
            self.block_ip(ip)
            self.port_scan_data[ip].clear()

    def detect_os_fingerprinting(self, ip, flags):
        current_time = time.time()
        self.fingerprint_data[ip].append((current_time, flags))
        self.fingerprint_data[ip] = [(t, f) for t, f in self.fingerprint_data[ip] if current_time - t <= self.FINGERPRINT_WINDOW]
        
        if len(set(f for t, f in self.fingerprint_data[ip])) >= self.FINGERPRINT_THRESHOLD:
            self.log("OS fingerprinting detected", "OS_FINGERPRINTING", ip, f"flags: {', '.join(self.fingerprint_data[ip])}", 
                    round(max(t for t, f in self.fingerprint_data[ip]) - min(t for t, f in self.fingerprint_data[ip]), 2))
            self.block_ip(ip)
            self.fingerprint_data[ip].clear()

    def start_ids(self, interface=None):
        if not self.running:
            self.running = True
            self.sniff_thread = threading.Thread(target=self._packet_capture, args=(interface,), daemon=True)
            self.sniff_thread.start()
            self.log("IDS started")

    def stop_ids(self):
        if self.running:
            self.running = False
            if self.sniff_thread:
                self.sniff_thread.join(timeout=2)
            self.log("IDS stopped")

    def _packet_capture(self, interface):
        conf.sniff_promisc = True
        conf.use_pcap = True

        def packet_handler(packet):
            try:
                if not self.should_block_packet(packet):
                    self.analyze_packet(packet)
            except Exception as e:
                pass
        
        sniff_params = {
            'prn': packet_handler,
            'store' : 0,
            'filter': 'ip or arp',
            'timeout': 1
        }

        if interface:
            sniff_params['iface'] = interface
        
        while self.running:
            try:
                sniff(**sniff_params)
            except Exception as e:
                self.log(f"Capture error: {str(e)}")
                time.sleep(1)
       
    def _display_packets(self, count):
        os.system('cls' if os.name == 'nt' else 'clear')
        print("{:<20} {:<15} {:<15} {:<10} {:<10} {:<30}".format(
            "Time", "Source", "Destination", "Protocol", "Length", "Info"))
        print("-" * 100)
        
        for packet in list(self.packet_buffer)[-count:]:
            if IP in packet:
                src = packet[IP].src
                dst = packet[IP].dst
                proto = "TCP" if TCP in packet else "UDP" if UDP in packet else "ICMP" if ICMP in packet else "IP"
                info = f"{packet[TCP].sport}->{packet[TCP].dport} [{packet[TCP].flags}]" if TCP in packet else ""
                
                print("{:<20} {:<15} {:<15} {:<10} {:<10} {:<30}".format(
                    datetime.fromtimestamp(packet.time).strftime('%H:%M:%S.%f')[:-3],
                    shorten(src, 15, placeholder='...'),
                    shorten(dst, 15, placeholder='...'),
                    proto,
                    len(packet),
                    shorten(info, 30, placeholder='...')
                ))

    def view_live_traffic(self, count=10):
        print("\nLive traffic view (Press Enter to return)")
        time.sleep(1)
        
        while True:
            self._display_packets(count)
            if self._check_enter():
                break
            time.sleep(1)

    def _check_enter(self):
        if os.name == 'nt':
            import msvcrt
            return msvcrt.kbhit() and msvcrt.getch() == b'\r'
        else:
            import sys, select
            return select.select([sys.stdin], [], [], 0) == ([sys.stdin], [], [])

    def cli_interface(self):
        while True:
            print("\n=== NIDS Management Interface ===")
            print("1. Start/Stop IDS")
            print("2. View Live Traffic")
            print("3. View Intrusion Logs")
            print("4. Display Blocked IPs")
            print("5. Clear Block List")
            print("6. Unblock an IP")
            print("7. Generate Report")
            print("8. Set Blocking Method")
            print("9. Exit")
            
            try:
                choice = input("Enter choice (1-9): ").strip()
                
                if choice == '1':
                    if self.running:
                        self.stop_ids()
                    else:
                        interface = input("Enter interface (leave blank for default): ").strip()
                        self.start_ids(interface or None)
                elif choice == '2':
                    count = input("Packet count (default 10): ")
                    self.view_live_traffic(int(count) if count.isdigit() else 10)
                elif choice == '3':
                    self.view_intrusion_logs()
                elif choice == '4':
                    self.display_blocked_ips()
                elif choice == '5':
                    self.clear_block_list()
                elif choice == '6':
                    self.unblock_ip(input("IP to unblock: "))
                elif choice == '7':
                    self.generate_report()
                elif choice == '8':
                    method = input("Block method (internal/firewall/both): ").lower()
                    if method in ("internal", "firewall", "both"):
                        self.block_method = method
                elif choice == '9':
                    self.stop_ids()
                    print("Exiting...")
                    break
                else:
                    print("Invalid choice")
                    
            except KeyboardInterrupt:
                self.stop_ids()
                break
            except Exception as e:
                print(f"Error: {str(e)}")

    def view_intrusion_logs(self):
        try:
            with open(self.log_file) as f:
                print(f.read())
        except FileNotFoundError:
            print("No logs found")

    def display_blocked_ips(self):
        print("\n".join(self.internal_block_list) if self.internal_block_list else "No blocked IPs")

    def generate_report(self):
        try:
            with open(self.log_file) as f:
                logs = f.readlines()
                
            print(f"Total intrusions: {len(logs)}")
            types = defaultdict(int)
            for log in logs:
                parts = log.split(' — ')
                if len(parts) > 1:
                    types[parts[1]] += 1
            print("Intrusion types:")
            for t, c in types.items():
                print(f"{t}: {c}")
                
        except FileNotFoundError:
            print("No logs found")

def main():
    if os.geteuid() != 0 and platform.system() != "Windows":
        print("Warning: Run as root/admin for full functionality")
        
    nids = NIDS()
    nids.cli_interface()

if __name__ == "__main__":
    main()