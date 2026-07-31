#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include <cstdint>
#include <string>
#include <vector>

// Parsed Ethernet header fields we care about.
struct EthernetHeader {
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint16_t ether_type;
};

// Parsed IPv4 header fields we care about.
struct IPHeader {
    uint8_t version;        // should be 4 for IPv4
    uint8_t header_len;     // in bytes (IP header can be 20-60 bytes)
    uint8_t protocol;       // 6 = TCP, 17 = UDP
    uint32_t src_ip;        // stored as raw 32-bit value
    uint32_t dst_ip;
};

// Parsed TCP header fields we care about.
struct TCPHeader {
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t header_len;     // in bytes (TCP header can be 20-60 bytes)
};

// The final result of parsing one packet: which layers were present,
// their fields, and where the leftover payload (if any) starts.
struct ParsedPacket {
    bool has_ethernet = false;
    bool has_ip = false;
    bool has_tcp = false;

    EthernetHeader eth{};
    IPHeader ip{};
    TCPHeader tcp{};

    // Offset into the original packet data where the payload
    // (whatever comes after all headers -- e.g. TLS data) begins.
    size_t payload_offset = 0;
};

class PacketParser {
public:
    // Parses raw packet bytes into structured header fields.
    // Fills in as much as it validly can -- e.g. if it's not TCP,
    // has_tcp stays false but has_ethernet/has_ip may still be true.
    static ParsedPacket parse(const std::vector<uint8_t>& data);

    // Helper to turn a raw 32-bit IP value into "192.168.1.10" string form.
    static std::string ipToString(uint32_t ip);

    // Helper to turn a raw MAC array into "aa:bb:cc:dd:ee:ff" string form.
    static std::string macToString(const uint8_t mac[6]);
};

#endif
