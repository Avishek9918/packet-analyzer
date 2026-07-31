#include "packet_parser.h"
#include <cstring>
#include <sstream>
#include <iomanip>

namespace {
constexpr size_t ETH_HEADER_LEN = 14;
constexpr uint16_t ETHERTYPE_IPV4 = 0x0800;
constexpr uint8_t PROTO_TCP = 6;

uint16_t read_u16_be(const uint8_t* p) {
    // Network byte order is big-endian: most significant byte first.
    return (static_cast<uint16_t>(p[0]) << 8) | p[1];
}

uint32_t read_u32_be(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8)  |
           static_cast<uint32_t>(p[3]);
}
} // namespace

ParsedPacket PacketParser::parse(const std::vector<uint8_t>& data) {
    ParsedPacket result;

    // --- Layer 2: Ethernet ---
    if (data.size() < ETH_HEADER_LEN) {
        return result; // too small to even have a full Ethernet header
    }

    std::memcpy(result.eth.dst_mac, &data[0], 6);
    std::memcpy(result.eth.src_mac, &data[6], 6);
    result.eth.ether_type = read_u16_be(&data[12]);
    result.has_ethernet = true;
    result.payload_offset = ETH_HEADER_LEN;

    if (result.eth.ether_type != ETHERTYPE_IPV4) {
        return result; // not IPv4 (could be ARP, IPv6, etc.) -- stop here
    }

    // --- Layer 3: IP ---
    size_t ip_start = ETH_HEADER_LEN;
    if (data.size() < ip_start + 20) {
        return result; // not enough bytes left for a minimal IP header
    }

    uint8_t version_and_ihl = data[ip_start + 0];
    result.ip.version = version_and_ihl >> 4;          // top 4 bits
    uint8_t ihl_words = version_and_ihl & 0x0F;         // bottom 4 bits
    result.ip.header_len = ihl_words * 4;               // IHL is in 32-bit words

    if (result.ip.version != 4) {
        return result; // we only handle IPv4 in this project
    }
    if (data.size() < ip_start + result.ip.header_len) {
        return result; // header_len claims more bytes than we actually have
    }

    result.ip.protocol = data[ip_start + 9];
    result.ip.src_ip = read_u32_be(&data[ip_start + 12]);
    result.ip.dst_ip = read_u32_be(&data[ip_start + 16]);
    result.has_ip = true;
    result.payload_offset = ip_start + result.ip.header_len;

    if (result.ip.protocol != PROTO_TCP) {
        return result; // not TCP (could be UDP, ICMP, etc.) -- stop here
    }

    // --- Layer 4: TCP ---
    size_t tcp_start = result.payload_offset;
    if (data.size() < tcp_start + 20) {
        return result; // not enough bytes left for a minimal TCP header
    }

    result.tcp.src_port = read_u16_be(&data[tcp_start + 0]);
    result.tcp.dst_port = read_u16_be(&data[tcp_start + 2]);

    uint8_t data_offset_word = data[tcp_start + 12] >> 4; // top 4 bits
    result.tcp.header_len = data_offset_word * 4;          // in 32-bit words

    if (data.size() < tcp_start + result.tcp.header_len) {
        return result; // claims more bytes than we have -- bail before using it
    }

    result.has_tcp = true;
    result.payload_offset = tcp_start + result.tcp.header_len;

    return result;
}

std::string PacketParser::ipToString(uint32_t ip) {
    std::ostringstream oss;
    oss << ((ip >> 24) & 0xFF) << "."
        << ((ip >> 16) & 0xFF) << "."
        << ((ip >> 8) & 0xFF) << "."
        << (ip & 0xFF);
    return oss.str();
}

std::string PacketParser::macToString(const uint8_t mac[6]) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (int i = 0; i < 6; i++) {
        if (i > 0) oss << ":";
        oss << std::setw(2) << static_cast<int>(mac[i]);
    }
    return oss.str();
}
