#include "pcap_reader.h"
#include <iostream>
#include <cstring>

namespace {

constexpr uint32_t PCAP_MAGIC_NORMAL = 0xa1b2c3d4;
constexpr uint32_t PCAP_MAGIC_SWAPPED = 0xd4c3b2a1;

// Reads a 4-byte little/big-endian value depending on swap flag.
uint32_t read_u32(const uint8_t* bytes, bool swap) {
    uint32_t value;
    std::memcpy(&value, bytes, 4);
    if (swap) {
        value = ((value & 0x000000FF) << 24) |
                ((value & 0x0000FF00) << 8)  |
                ((value & 0x00FF0000) >> 8)  |
                ((value & 0xFF000000) >> 24);
    }
    return value;
}

} // namespace

bool PcapReader::open(const std::string& filepath) {
    file_.open(filepath, std::ios::binary);
    if (!file_.is_open()) {
        std::cerr << "[PcapReader] Could not open file: " << filepath << "\n";
        return false;
    }

    uint8_t global_header[24];
    file_.read(reinterpret_cast<char*>(global_header), 24);
    if (!file_ || file_.gcount() != 24) {
        std::cerr << "[PcapReader] File too small to be a valid pcap\n";
        return false;
    }

    // First 4 bytes are the magic number, read WITHOUT swapping first
    // so we can figure out which byte order this file actually uses.
    uint32_t magic = read_u32(global_header, false);

    if (magic == PCAP_MAGIC_NORMAL) {
        byte_swap_ = false;
    } else if (magic == PCAP_MAGIC_SWAPPED) {
        byte_swap_ = true;
    } else {
        std::cerr << "[PcapReader] Not a valid pcap file (bad magic number)\n";
        return false;
    }

    // We don't need the rest of the global header's fields (version,
    // snaplen, link type) for this project -- we assume Ethernet capture,
    // which is true for essentially all pcap files from Wireshark/tcpdump.
    return true;
}

bool PcapReader::readNextPacket(RawPacket& out) {
    uint8_t packet_header[16];
    file_.read(reinterpret_cast<char*>(packet_header), 16);

    if (!file_ || file_.gcount() != 16) {
        return false; // EOF or truncated file -- either way, we're done
    }

    out.timestamp_sec  = read_u32(packet_header + 0, byte_swap_);
    out.timestamp_usec = read_u32(packet_header + 4, byte_swap_);
    out.captured_len    = read_u32(packet_header + 8, byte_swap_);
    out.original_len   = read_u32(packet_header + 12, byte_swap_);

    // Sanity check: refuse to allocate absurd amounts of memory if the
    // file is corrupt and captured_len is garbage.
    if (out.captured_len > 262144) { // 256 KB is far bigger than any real packet
        std::cerr << "[PcapReader] Suspicious captured_len, stopping\n";
        return false;
    }

    out.data.resize(out.captured_len);
    file_.read(reinterpret_cast<char*>(out.data.data()), out.captured_len);

    if (!file_ || static_cast<uint32_t>(file_.gcount()) != out.captured_len) {
        std::cerr << "[PcapReader] Truncated packet data, stopping\n";
        return false;
    }

    return true;
}
