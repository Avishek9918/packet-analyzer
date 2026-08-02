#include "traffic_stats.h"
#include <iostream>
#include <iomanip>

std::string TrafficStats::protocolName(uint8_t protocol_num) {
    switch (protocol_num) {
        case 6:  return "TCP";
        case 17: return "UDP";
        case 1:  return "ICMP";
        default: return "OTHER";
    }
}

void TrafficStats::recordPacket(uint32_t dst_ip, uint8_t protocol_num, const std::string& sni) {
    total_packets_++;
    protocol_counts_[protocolName(protocol_num)]++;

    // If this packet gave us a domain name (it was a TLS Client Hello),
    // learn that its destination IP belongs to that domain from now on.
    if (!sni.empty()) {
        ip_to_domain_[dst_ip] = sni;
    }

    // Regardless of whether THIS packet had SNI, check if we've already
    // learned this IP's domain from an earlier packet -- if so, count
    // this packet under that domain too (this is how we count the
    // encrypted follow-up packets, not just the one Client Hello).
    auto it = ip_to_domain_.find(dst_ip);
    if (it != ip_to_domain_.end()) {
        domain_counts_[it->second]++;
    }
}

void TrafficStats::printSummary() const {
    std::cout << "\n========================================\n";
    std::cout << " TRAFFIC SUMMARY\n";
    std::cout << "========================================\n";
    std::cout << "Total packets: " << total_packets_ << "\n";

    std::cout << "\nBy protocol:\n";
    for (const auto& [proto, count] : protocol_counts_) {
        double pct = total_packets_ ? (100.0 * count / total_packets_) : 0.0;
        std::cout << "  " << std::left << std::setw(8) << proto
                   << count << "  (" << std::fixed << std::setprecision(1) << pct << "%)\n";
    }

    if (!domain_counts_.empty()) {
        std::cout << "\nBy domain (identified via TLS SNI):\n";
        for (const auto& [domain, count] : domain_counts_) {
            std::cout << "  " << std::left << std::setw(20) << domain << count << " packets\n";
        }
    }
    std::cout << "========================================\n";
}
