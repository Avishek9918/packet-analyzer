#!/usr/bin/env python3
"""
Network Packet Analyzer
------------------------
Captures/reads network packets and decodes Ethernet, IP, TCP, UDP, and ICMP
headers to inspect traffic. Supports basic filtering and summary stats.

Usage (live capture, needs root/admin):
    sudo python3 packet_analyzer.py --iface eth0 --count 50

Usage (read from a saved pcap file):
    python3 packet_analyzer.py --pcap sample.pcap

Filtering:
    python3 packet_analyzer.py --pcap sample.pcap --protocol tcp
    python3 packet_analyzer.py --pcap sample.pcap --ip 192.168.1.100
    python3 packet_analyzer.py --pcap sample.pcap --port 443
"""

import argparse
from collections import Counter
from scapy.all import sniff, rdpcap, IP, TCP, UDP, ICMP, Ether


class PacketStats:
    """Keeps running counts so we can print a summary at the end."""

    def __init__(self):
        self.total = 0
        self.protocol_counts = Counter()
        self.src_ip_counts = Counter()
        self.dst_ip_counts = Counter()
        self.top_ports = Counter()

    def update(self, packet):
        self.total += 1

        if IP in packet:
            self.src_ip_counts[packet[IP].src] += 1
            self.dst_ip_counts[packet[IP].dst] += 1

        if TCP in packet:
            self.protocol_counts["TCP"] += 1
            self.top_ports[packet[TCP].dport] += 1
        elif UDP in packet:
            self.protocol_counts["UDP"] += 1
            self.top_ports[packet[UDP].dport] += 1
        elif ICMP in packet:
            self.protocol_counts["ICMP"] += 1
        else:
            self.protocol_counts["OTHER"] += 1

    def print_summary(self):
        print("\n" + "=" * 55)
        print(" CAPTURE SUMMARY")
        print("=" * 55)
        print(f"Total packets analyzed: {self.total}")

        print("\nProtocol breakdown:")
        for proto, count in self.protocol_counts.most_common():
            pct = (count / self.total * 100) if self.total else 0
            print(f"  {proto:<8} {count:>5}  ({pct:5.1f}%)")

        print("\nTop 5 source IPs:")
        for ip, count in self.src_ip_counts.most_common(5):
            print(f"  {ip:<20} {count}")

        print("\nTop 5 destination ports:")
        for port, count in self.top_ports.most_common(5):
            print(f"  {port:<10} {count}")
        print("=" * 55)


def decode_packet(packet, verbose=True):
    """
    Pulls apart a Scapy packet layer by layer and prints the fields
    we care about. This is the 'deep' part -- looking inside each
    protocol layer rather than treating the packet as a black box.
    """
    lines = []

    # --- Layer 2: Ethernet ---
    if Ether in packet:
        eth = packet[Ether]
        lines.append(f"Ethernet  | src={eth.src}  dst={eth.dst}  type=0x{eth.type:04x}")

    # --- Layer 3: IP ---
    if IP in packet:
        ip = packet[IP]
        lines.append(
            f"IP        | src={ip.src:<15} dst={ip.dst:<15} "
            f"ttl={ip.ttl:<3} proto={ip.proto}"
        )

    # --- Layer 4: TCP / UDP / ICMP ---
    if TCP in packet:
        tcp = packet[TCP]
        flags = tcp.sprintf("%TCP.flags%")
        lines.append(
            f"TCP       | sport={tcp.sport:<6} dport={tcp.dport:<6} "
            f"flags={flags:<8} seq={tcp.seq}"
        )
    elif UDP in packet:
        udp = packet[UDP]
        lines.append(f"UDP       | sport={udp.sport:<6} dport={udp.dport:<6} len={udp.len}")
    elif ICMP in packet:
        icmp = packet[ICMP]
        lines.append(f"ICMP      | type={icmp.type} code={icmp.code}")

    if verbose:
        print("-" * 55)
        for line in lines:
            print(line)

    return lines


def passes_filter(packet, protocol=None, ip_filter=None, port_filter=None):
    """Returns True if the packet matches all the active filters."""
    if protocol:
        protocol = protocol.upper()
        if protocol == "TCP" and TCP not in packet:
            return False
        if protocol == "UDP" and UDP not in packet:
            return False
        if protocol == "ICMP" and ICMP not in packet:
            return False

    if ip_filter and IP in packet:
        if packet[IP].src != ip_filter and packet[IP].dst != ip_filter:
            return False
    elif ip_filter and IP not in packet:
        return False

    if port_filter:
        port_filter = int(port_filter)
        matched = False
        if TCP in packet and port_filter in (packet[TCP].sport, packet[TCP].dport):
            matched = True
        if UDP in packet and port_filter in (packet[UDP].sport, packet[UDP].dport):
            matched = True
        if not matched:
            return False

    return True


def process_packets(packets, args, stats):
    for packet in packets:
        if not passes_filter(packet, args.protocol, args.ip, args.port):
            continue
        decode_packet(packet, verbose=not args.quiet)
        stats.update(packet)


def main():
    parser = argparse.ArgumentParser(description="Network Packet Analyzer")
    parser.add_argument("--iface", help="Network interface for live capture (e.g. eth0, wlan0)")
    parser.add_argument("--pcap", help="Path to a .pcap file to read instead of live capture")
    parser.add_argument("--count", type=int, default=20, help="Number of packets to capture (live mode)")
    parser.add_argument("--protocol", help="Filter by protocol: tcp, udp, icmp")
    parser.add_argument("--ip", help="Filter by source or destination IP")
    parser.add_argument("--port", help="Filter by source or destination port")
    parser.add_argument("--quiet", action="store_true", help="Suppress per-packet output, show summary only")
    args = parser.parse_args()

    stats = PacketStats()

    if args.pcap:
        print(f"Reading packets from {args.pcap} ...")
        packets = rdpcap(args.pcap)
        process_packets(packets, args, stats)

    elif args.iface:
        print(f"Starting live capture on {args.iface} (count={args.count}) ... Ctrl+C to stop early")

        def handle(packet):
            if not passes_filter(packet, args.protocol, args.ip, args.port):
                return
            decode_packet(packet, verbose=not args.quiet)
            stats.update(packet)

        sniff(iface=args.iface, prn=handle, count=args.count, store=False)

    else:
        parser.error("Provide either --iface (live capture) or --pcap (read from file)")

    stats.print_summary()


if __name__ == "__main__":
    main()
