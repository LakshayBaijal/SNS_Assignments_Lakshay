#!/usr/bin/env python3
from scapy.all import *
from scapy.config import conf
import argparse
import random
import sys
import time
import os
# Import scapy modules only once.
from scapy.all import sniff, IP, TCP, UDP, ICMP, Ether

class AttackSimulator:
    def __init__(self, interface=None):  # Corrected constructor name
        self.interface = interface
        conf.verb = 0  # Suppress Scapy output
    
    def validate_interface(self):
        """Check if specified interface exists"""
        if self.interface and self.interface not in get_if_list():
            print(f"\n[!] Interface {self.interface} not found. Available interfaces:")
            for iface in get_if_list():
                print(f" - {iface}")
            return False
        return True
    
    def send_packet(self, packet, delay=0.1):
        """Send packet with optional delay and interface binding"""
        try:
            if self.interface:
                sendp(packet, iface=self.interface, verbose=False)
            else:
                send(packet, verbose=False)
            time.sleep(delay)  # Avoid flooding
            return True
        except Exception as e:
            print(f"\n[!] Packet sending failed: {str(e)}")
            return False
    
    def port_scan(self, target_ip, ports=range(1, 100), scan_type="syn"):
        """Simulate different port scan types"""
        print(f"\n[+] Starting {scan_type.upper()} port scan against {target_ip}")
        
        for port in ports:
            if scan_type == "syn":
                packet = IP(dst=target_ip)/TCP(dport=port, flags="S")
            elif scan_type == "xmas":
                packet = IP(dst=target_ip)/TCP(dport=port, flags="FPU")
            elif scan_type == "fin":
                packet = IP(dst=target_ip)/TCP(dport=port, flags="F")
            elif scan_type == "null":
                packet = IP(dst=target_ip)/TCP(dport=port, flags="")
            
            if self.send_packet(packet):
                print(f"Sent {scan_type} packet to {target_ip}:{port}", end='\r')
        
        print("\n[+] Scan completed")
    
    def os_fingerprinting(self, target_ip):
        """Simulate OS fingerprinting attempts"""
        print(f"\n[+] Starting OS fingerprinting against {target_ip}")
        
        # TCP packets with unusual flag combinations
        flag_combinations = [
            ('SYN', 'S'),
            ('NULL', ''),
            ('FIN', 'F'),
            ('XMAS', 'FPU'),
            ('ACK', 'A'),
            ('SYN-ACK', 'SA')
        ]
        
        for name, flags in flag_combinations:
            packet = IP(dst=target_ip)/TCP(dport=80, flags=flags)
            if self.send_packet(packet):
                print(f"Sent {name} packet ({flags}) to {target_ip}", end='\r')
            time.sleep(0.5)
        
        # ICMP probes
        icmp_types = [8, 13, 15, 17]  # Echo, Timestamp, Info, Address Mask
        for icmp_type in icmp_types:
            packet = IP(dst=target_ip)/ICMP(type=icmp_type)
            if self.send_packet(packet):
                print(f"Sent ICMP type {icmp_type} to {target_ip}", end='\r')
            time.sleep(0.5)
        
        print("\n[+] Fingerprinting completed")
    
    def ddos_simulation(self, target_ip, count=100):
        """Simulate volumetric attack"""
        print(f"\n[+] Starting DDoS simulation against {target_ip}")
        
        for i in range(count):
            # Randomize source port and payload
            sport = random.randint(1024, 65535)
            payload = bytes([random.getrandbits(8) for _ in range(random.randint(64, 1024))])
            
            # Alternate between TCP and UDP
            if i % 2 == 0:
                packet = IP(dst=target_ip)/TCP(sport=sport, dport=80)/Raw(payload)
            else:
                packet = IP(dst=target_ip)/UDP(sport=sport, dport=53)/Raw(payload)
            
            if self.send_packet(packet, delay=0.01):
                print(f"Sent attack packet {i+1}/{count}", end='\r')
        
        print("\n[+] DDoS simulation completed")

def list_interfaces():
    """Display available network interfaces"""
    print("\nAvailable network interfaces:")
    for idx, iface in enumerate(get_if_list(), 1):
        print(f"{idx}. {iface}")
    print()

def main():
    parser = argparse.ArgumentParser(
        description="Network Attack Simulator for NIDS Testing",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("-t", "--target", required=True, help="Target IP address")
    parser.add_argument("-i", "--interface", help="Network interface to use")
    parser.add_argument("-a", "--attack", required=True,
                        choices=['scan', 'fingerprint', 'ddos', 'list'],
                        help="Attack type to simulate")
    parser.add_argument("-st", "--scan-type", default="syn",
                        choices=['syn', 'xmas', 'fin', 'null'],
                        help="Port scan type")
    parser.add_argument("-p", "--ports", default="1-100",
                        help="Port range (e.g., 1-100, 22,80,443)")
    parser.add_argument("-c", "--count", type=int, default=100,
                        help="Number of packets for DDoS simulation")
    
    args = parser.parse_args()
    
    if args.attack == "list":
        list_interfaces()
        return
    
    simulator = AttackSimulator(args.interface)
    
    if not simulator.validate_interface():
        sys.exit(1)
    
    try:
        # Parse port range
        if '-' in args.ports:
            start, end = map(int, args.ports.split('-'))
            ports = range(start, end + 1)
        elif ',' in args.ports:
            ports = list(map(int, args.ports.split(',')))
        else:
            ports = [int(args.ports)]
        
        # Execute attack based on the provided parameter
        if args.attack == "scan":
            simulator.port_scan(args.target, ports, args.scan_type)
        elif args.attack == "fingerprint":
            simulator.os_fingerprinting(args.target)
        elif args.attack == "ddos":
            simulator.ddos_simulation(args.target, args.count)
            
    except KeyboardInterrupt:
        print("\n[!] Attack interrupted by user")
    except Exception as e:
        print(f"\n[!] Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    # Check root privileges
    if os.geteuid() != 0:
        print("\n[!] Warning: Some attacks require root privileges")
        print("[!] Consider running with 'sudo' for full functionality\n")
    
    main()
