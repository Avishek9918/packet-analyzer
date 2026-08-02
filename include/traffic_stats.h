#ifndef TRAFFIC_STATS_H
#define TRAFFIC_STATS_H

#include <cstdint>
#include <map>
#include <string>

class TrafficStats {
public:
    // Call once per packet, after parsing headers (and SNI, if any).
    // ip is the destination IP (as a raw uint32_t, same form as IPHeader::dst_ip).
    // protocol_num is the IP protocol number (6=TCP, 17=UDP, etc).
    // sni is the extracted domain name, or empty string if none found on this packet.
    void recordPacket(uint32_t dst_ip, uint8_t protocol_num, const std::string& sni);

    // Prints the final report to stdout.
    void printSummary() const;

private:
    int total_packets_ = 0;
    std::map<std::string, int> protocol_counts_;   // "TCP" -> count, "UDP" -> count, etc.
    std::map<uint32_t, std::string> ip_to_domain_;  // learned from SNI as we go
    std::map<std::string, int> domain_counts_;      // "youtube.com" -> packet count

    static std::string protocolName(uint8_t protocol_num);
};

#endif
