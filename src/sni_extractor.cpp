#include "sni_extractor.h"

namespace {
constexpr uint8_t TLS_HANDSHAKE_CONTENT_TYPE = 0x16;
constexpr uint8_t TLS_HANDSHAKE_TYPE_CLIENT_HELLO = 0x01;
constexpr uint16_t EXTENSION_TYPE_SERVER_NAME = 0x0000;

uint16_t read_u16_be(const uint8_t* p) {
    return (static_cast<uint16_t>(p[0]) << 8) | p[1];
}
} // namespace

bool SniExtractor::isClientHello(const std::vector<uint8_t>& payload) {
    // Need at least: TLS record header (5) + handshake header (4)
    if (payload.size() < 9) return false;

    // Byte 0 of the TLS record header: content type.
    // 0x16 means "Handshake" -- this is the category of message
    // that Client Hello belongs to (as opposed to, say, encrypted
    // application data once the handshake is done).
    if (payload[0] != TLS_HANDSHAKE_CONTENT_TYPE) return false;

    // Byte 5 (first byte after the 5-byte record header) is the
    // handshake message type. 0x01 = Client Hello specifically.
    if (payload[5] != TLS_HANDSHAKE_TYPE_CLIENT_HELLO) return false;

    return true;
}

std::string SniExtractor::extract(const std::vector<uint8_t>& payload) {
    if (!isClientHello(payload)) {
        return "";
    }

    // Walk past the fixed-size fields we don't need, to reach the
    // variable-length section (session ID, cipher suites, etc).
    //
    // Offsets from the start of `payload`:
    //   0-4   : TLS record header (5 bytes)
    //   5-8   : Handshake header (4 bytes: type + 3-byte length)
    //   9-10  : Client version (2 bytes)
    //   11-42 : Random (32 bytes)
    //   43    : Session ID length (1 byte)
    size_t pos = 43;
    if (pos >= payload.size()) return "";

    uint8_t session_id_len = payload[pos];
    pos += 1 + session_id_len; // skip the length byte AND the session ID itself
    if (pos + 2 > payload.size()) return "";

    // Cipher suites: 2-byte length, then that many bytes of data
    uint16_t cipher_suites_len = read_u16_be(&payload[pos]);
    pos += 2 + cipher_suites_len;
    if (pos + 1 > payload.size()) return "";

    // Compression methods: 1-byte length, then that many bytes of data
    uint8_t compression_len = payload[pos];
    pos += 1 + compression_len;
    if (pos + 2 > payload.size()) return "";

    // Now we're at the extensions block: 2-byte total length,
    // followed by a list of [type(2) + length(2) + data(length)] entries.
    uint16_t extensions_total_len = read_u16_be(&payload[pos]);
    pos += 2;
    size_t extensions_end = pos + extensions_total_len;
    if (extensions_end > payload.size()) return "";

    // Walk the extension list looking for server_name (type 0x0000).
    while (pos + 4 <= extensions_end) {
        uint16_t ext_type = read_u16_be(&payload[pos]);
        uint16_t ext_len = read_u16_be(&payload[pos + 2]);
        size_t ext_data_start = pos + 4;

        if (ext_data_start + ext_len > payload.size()) {
            return ""; // malformed -- claims more data than we have
        }

        if (ext_type == EXTENSION_TYPE_SERVER_NAME) {
            // Inside the server_name extension itself:
            //   0-1 : Server Name List length (2 bytes)
            //   2   : Name Type (1 byte, 0 = hostname)
            //   3-4 : Name length (2 bytes)
            //   5.. : the actual hostname bytes
            if (ext_len < 5) return "";
            size_t name_len_pos = ext_data_start + 3;
            if (name_len_pos + 2 > payload.size()) return "";

            uint16_t name_len = read_u16_be(&payload[name_len_pos]);
            size_t name_start = name_len_pos + 2;
            if (name_start + name_len > payload.size()) return "";

            return std::string(
                reinterpret_cast<const char*>(&payload[name_start]),
                name_len
            );
        }

        // Not the extension we want -- skip past it and check the next one.
        pos = ext_data_start + ext_len;
    }

    return ""; // walked all extensions, no server_name found
}
