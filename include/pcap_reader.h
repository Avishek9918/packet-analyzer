#ifndef PCAP_READER_H
#define PCAP_READER_H

#include <cstdint>
#include <fstream>
#include <string>
#include <vector>

// One captured packet: its raw bytes plus the metadata pcap stored with it.
struct RawPacket {
    uint32_t timestamp_sec;
    uint32_t timestamp_usec;
    uint32_t captured_len;   // how many bytes we actually have in `data`
    uint32_t original_len;   // how big the packet was on the wire
    std::vector<uint8_t> data;
};

class PcapReader {
public:
    // Opens the file and reads/validates the 24-byte global header.
    // Returns false if the file can't be opened or isn't a valid pcap.
    bool open(const std::string& filepath);

    // Reads the next packet into `out`. Returns false at EOF or on error.
    bool readNextPacket(RawPacket& out);

private:
    std::ifstream file_;
    bool byte_swap_ = false; // true if file's byte order differs from ours
};

#endif
