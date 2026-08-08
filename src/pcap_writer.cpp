#include "pcap_writer.h"
#include <iostream>
#include <cstring>

namespace {
constexpr uint32_t PCAP_MAGIC_NORMAL = 0xa1b2c3d4;

void write_u32(std::ofstream& out, uint32_t value) {
    out.write(reinterpret_cast<const char*>(&value), 4);
}
void write_u16(std::ofstream& out, uint16_t value) {
    out.write(reinterpret_cast<const char*>(&value), 2);
}
} // namespace

bool PcapWriter::open(const std::string& filepath) {
    file_.open(filepath, std::ios::binary);
    if (!file_.is_open()) {
        std::cerr << "[PcapWriter] Could not create file: " << filepath << "\n";
        return false;
    }

    // Global header (24 bytes) -- same layout PcapReader expects.
    write_u32(file_, PCAP_MAGIC_NORMAL); // magic number
    write_u16(file_, 2);                 // version major
    write_u16(file_, 4);                 // version minor
    write_u32(file_, 0);                 // timezone offset
    write_u32(file_, 0);                 // timestamp accuracy
    write_u32(file_, 262144);            // snaplen (max bytes per packet)
    write_u32(file_, 1);                 // link-layer type: 1 = Ethernet

    return true;
}

void PcapWriter::writePacket(const RawPacket& packet) {
    if (!file_.is_open()) return;

    // Per-packet header (16 bytes) -- must match what PcapReader::readNextPacket expects.
    write_u32(file_, packet.timestamp_sec);
    write_u32(file_, packet.timestamp_usec);
    write_u32(file_, packet.captured_len);
    write_u32(file_, packet.original_len);

    // Then the raw packet bytes themselves.
    file_.write(reinterpret_cast<const char*>(packet.data.data()), packet.data.size());
}
