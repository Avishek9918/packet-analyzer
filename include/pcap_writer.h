#ifndef PCAP_WRITER_H
#define PCAP_WRITER_H

#include "pcap_reader.h" // reuse the RawPacket struct
#include <fstream>
#include <string>

class PcapWriter {
public:
    // Opens the output file and writes the 24-byte global header.
    // Returns false if the file can't be created.
    bool open(const std::string& filepath);

    // Writes one packet's 16-byte header + raw data.
    void writePacket(const RawPacket& packet);

private:
    std::ofstream file_;
};

#endif
