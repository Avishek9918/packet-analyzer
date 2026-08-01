#ifndef SNI_EXTRACTOR_H
#define SNI_EXTRACTOR_H

#include <cstdint>
#include <string>
#include <vector>

class SniExtractor {
public:
    // Looks at the TCP payload bytes (starting right after the TCP header)
    // and, if this looks like a TLS Client Hello, extracts the SNI domain
    // name from the server_name extension.
    //
    // Returns the domain name if found, or an empty string if this isn't
    // a Client Hello or has no SNI extension.
    static std::string extract(const std::vector<uint8_t>& payload);

private:
    static bool isClientHello(const std::vector<uint8_t>& payload);
};

#endif
