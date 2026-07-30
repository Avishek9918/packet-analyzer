#include "pcap_reader.h"
#include "packet_parser.h"
#include "sni_extractor.h"
#include <iostream>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <pcap_file>\n";
        return 1;
    }

    PcapReader reader;
    if (!reader.open(argv[1])) {
        return 1;
    }

    RawPacket packet;
    int count = 0;
    while (reader.readNextPacket(packet)) {
        count++;
        ParsedPacket parsed = PacketParser::parse(packet.data);

        std::cout << "--- Packet #" << count << " (" << packet.captured_len << " bytes) ---\n";

        if (parsed.has_ethernet) {
            std::cout << "  Ethernet: " << PacketParser::macToString(parsed.eth.src_mac)
                      << " -> " << PacketParser::macToString(parsed.eth.dst_mac)
                      << "  type=0x" << std::hex << parsed.eth.ether_type << std::dec << "\n";
        }

        if (parsed.has_ip) {
            std::cout << "  IP: " << PacketParser::ipToString(parsed.ip.src_ip)
                      << " -> " << PacketParser::ipToString(parsed.ip.dst_ip)
                      << "  protocol=" << static_cast<int>(parsed.ip.protocol) << "\n";
        }

        if (parsed.has_tcp) {
            std::cout << "  TCP: port " << parsed.tcp.src_port
                      << " -> port " << parsed.tcp.dst_port << "\n";

            // Payload is whatever comes after all the headers we parsed.
            if (parsed.payload_offset < packet.data.size()) {
                std::vector<uint8_t> payload(
                    packet.data.begin() + parsed.payload_offset,
                    packet.data.end()
                );
                std::string sni = SniExtractor::extract(payload);
                if (!sni.empty()) {
                    std::cout << "  TLS SNI (domain): " << sni << "\n";
                }
            }
        }
    }

    std::cout << "\nTotal packets read: " << count << "\n";
    return 0;
}
