#ifndef RULE_MANAGER_H
#define RULE_MANAGER_H

#include <cstdint>
#include <set>
#include <string>

class RuleManager {
public:
    // Add a domain to the block list (case-insensitive, e.g. "youtube.com").
    void blockDomain(const std::string& domain);

    // Add an IP to the block list. Takes the raw uint32_t form
    // (same representation as IPHeader::dst_ip).
    void blockIp(uint32_t ip);

    // Returns true if this packet should be blocked, based on either
    // its destination IP or its SNI domain (if any).
    // Checking both matters: the first packet to a blocked domain has
    // an SNI we can match directly, but follow-up packets to the same
    // connection have no SNI -- only the IP, which we still recognize.
    bool shouldBlock(uint32_t dst_ip, const std::string& sni) const;

    int blockedCount() const { return blocked_count_; }

private:
    std::set<std::string> blocked_domains_;
    mutable std::set<uint32_t> blocked_ips_; // mutable: shouldBlock() is const but still learns new IPs
    mutable int blocked_count_ = 0;          // mutable: shouldBlock() is const but still tallies

    static std::string toLower(const std::string& s);
};

#endif
