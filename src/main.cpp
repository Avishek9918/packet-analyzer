#include "pcap_reader.h"
#include "packet_parser.h"
#include "sni_extractor.h"
#include "traffic_stats.h"
#include "rule_manager.h"
#include <iostream>
#include <vector>
#include <string>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <pcap_file> [--block-domain <domain>]...\n";
        return 1;
    }

    std::string pcap_path = argv[1];
    RuleManager rules;

    // Parse simple --block-domain flags, can be repeated.
    for (int i = 2; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--block-domain" && i + 1 < argc) {
            rules.blockDomain(argv[i + 1]);
            std::cout << "[Rule] Blocking domain: " << argv[i + 1] << "\n";
            i++;
        }
    }

    PcapReader reader;
    if (!reader.open(pcap_path)) {
        return 1;
    }

    TrafficStats stats;
    RawPacket packet;
    int count = 0;

    while (reader.readNextPacket(packet)) {
        count++;
        ParsedPacket parsed = PacketParser::parse(packet.data);

        std::string sni;
        if (parsed.has_tcp && parsed.payload_offset < packet.data.size()) {
            std::vector<uint8_t> payload(
                packet.data.begin() + parsed.payload_offset,
                packet.data.end()
            );
            sni = SniExtractor::extract(payload);
        }

        std::cout << "--- Packet #" << count << " (" << packet.captured_len << " bytes) ---\n";

        if (parsed.has_ip) {
            std::cout << "  IP: " << PacketParser::ipToString(parsed.ip.src_ip)
                      << " -> " << PacketParser::ipToString(parsed.ip.dst_ip)
                      << "  protocol=" << static_cast<int>(parsed.ip.protocol) << "\n";
        }
        if (parsed.has_tcp) {
            std::cout << "  TCP: port " << parsed.tcp.src_port
                      << " -> port " << parsed.tcp.dst_port << "\n";
            if (!sni.empty()) {
                std::cout << "  TLS SNI (domain): " << sni << "\n";
            }
        }

        if (!parsed.has_ip) {
            continue; // nothing to block/record without an IP layer
        }

        // Check blocking BEFORE recording stats, so blocked traffic
        // never leaks into the "allowed traffic" summary counts.
        if (rules.shouldBlock(parsed.ip.dst_ip, sni)) {
            std::cout << "  >>> BLOCKED (rule match) <<<\n";
            continue; // skip recordPacket entirely for blocked traffic
        }

        stats.recordPacket(parsed.ip.dst_ip, parsed.ip.protocol, sni);
    }

    std::cout << "\nTotal packets read: " << count << "\n";
    std::cout << "Packets blocked: " << rules.blockedCount() << "\n";
    stats.printSummary();
    return 0;
}
