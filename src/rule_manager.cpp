#include "rule_manager.h"
#include <algorithm>
#include <cctype>

std::string RuleManager::toLower(const std::string& s) {
    std::string out = s;
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return out;
}

void RuleManager::blockDomain(const std::string& domain) {
    blocked_domains_.insert(toLower(domain));
}

void RuleManager::blockIp(uint32_t ip) {
    blocked_ips_.insert(ip);
}

bool RuleManager::shouldBlock(uint32_t dst_ip, const std::string& sni) const {
    // Case 1: we already know this IP is blocked (either explicitly
    // added via blockIp(), or learned earlier from a blocked SNI match).
    if (blocked_ips_.count(dst_ip)) {
        blocked_count_++;
        return true;
    }

    // Case 2: this packet has an SNI, and it matches a blocked domain.
    // Learn this IP too, so later packets on the same connection
    // (which won't have SNI anymore) are still recognized and blocked.
    if (!sni.empty() && blocked_domains_.count(toLower(sni))) {
        blocked_ips_.insert(dst_ip);
        blocked_count_++;
        return true;
    }

    return false;
}
