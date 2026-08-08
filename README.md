# Network Packet Analyzer with TLS SNI Inspection

A C++ tool that reads network traffic from PCAP files, manually decodes packet headers byte-by-byte, and identifies which websites you're visiting over HTTPS — even though HTTPS is encrypted. It also supports blocking traffic by domain and processes packets using a multi-threaded pipeline.

I built this to actually understand how tools like firewalls and network monitors work under the hood, instead of just calling a library function and trusting it. Every header field here is parsed by hand, at the byte level, no shortcuts.

## What it does

- **Reads and writes PCAP files** — the standard packet capture format used by Wireshark and tcpdump
- **Manually parses Ethernet, IPv4, and TCP headers** directly from raw bytes — no parsing libraries, just reading the RFC-defined byte offsets myself
- **Extracts domain names from encrypted HTTPS traffic** using TLS Client Hello / SNI inspection — the same technique real DPI (deep packet inspection) tools use to see *which* site you're visiting without decrypting anything
- **Blocks traffic by domain or IP**, and remembers the IP once it's seen the domain, so it can keep blocking a connection's later packets even after the (unencrypted) handshake is over
- **Processes packets across multiple threads** using a thread-safe queue, so parsing work is spread across a small worker pool instead of running one packet at a time
- **Writes filtered output** to a new PCAP file containing only the traffic that wasn't blocked

## Why SNI matters

When your browser connects to a site like `youtube.com` over HTTPS, the connection is encrypted — but not from the very first packet. Before encryption kicks in, the browser sends a **Client Hello** message in plaintext, and that message includes the domain name it's trying to reach (called **SNI**, Server Name Indication). Servers need this because a single IP can host many different websites, so the server has to know which site's certificate to use before anything gets encrypted.

That one plaintext field is enough to identify traffic by domain, which is exactly what this project does.

## Architecture

```
PCAP file
   |
   v
[Main thread] reads packets one by one
   |
   v
[Thread-safe queue] -- packets pushed here
   |
   v
[Worker thread pool] -- each thread pulls a packet and:
   1. Parses Ethernet -> IP -> TCP headers
   2. Checks the TCP payload for a TLS Client Hello, extracts SNI if present
   3. Checks blocking rules (shared, mutex-protected)
   4. Updates traffic stats (shared, mutex-protected)
   5. Writes the packet to the output file, if allowed (shared, mutex-protected)
```

The parsing itself (steps 1-2) needs no locking — each thread works on its own packet independently. Locking only kicks in once a thread touches something *shared* across all workers (the rule list, the stats counters, the output file).

## File-by-file breakdown

| File | What it does |
|---|---|
| `pcap_reader.h/.cpp` | Opens a `.pcap` file, validates the format, reads packets one at a time |
| `pcap_writer.h/.cpp` | Writes packets back out to a new `.pcap` file, in a format any pcap tool (including Wireshark) can open |
| `packet_parser.h/.cpp` | Slices raw packet bytes into Ethernet, IP, and TCP header fields |
| `sni_extractor.h/.cpp` | Walks the TLS Client Hello structure to pull out the SNI domain name |
| `rule_manager.h/.cpp` | Tracks blocked domains/IPs, learns new IPs from matched SNI so it can keep blocking a connection after the handshake |
| `traffic_stats.h/.cpp` | Tracks packet counts by protocol and by domain (using the same IP-learning trick as the rule manager) |
| `thread_safe_queue.h` | A mutex + condition_variable queue used to hand packets from the reader thread to the worker pool |
| `main.cpp` | Wires everything together: CLI args, thread pool setup, the actual worker loop |

~850 lines total.

## Building it

Needs a C++17 compiler.

```bash
g++ -std=c++17 -Wall -O2 -pthread -I include -o pcap_analyzer \
    src/main.cpp src/pcap_reader.cpp src/pcap_writer.cpp \
    src/packet_parser.cpp src/sni_extractor.cpp \
    src/rule_manager.cpp src/traffic_stats.cpp
```

## Running it

```bash
# Basic analysis
./pcap_analyzer capture.pcap

# Block a domain (and any IP it resolves to, once seen)
./pcap_analyzer capture.pcap --block-domain youtube.com

# Save everything that wasn't blocked to a new file
./pcap_analyzer capture.pcap --block-domain youtube.com --output allowed.pcap
```

## A design decision worth explaining: how blocking survives the handshake

SNI only shows up in the *first* packet of a connection — the Client Hello. Every packet after that is encrypted and has no domain name in it anymore. So if `RuleManager` only checked SNI, it would only ever catch that one packet and let everything else through.

Instead, the first time it sees a Client Hello matching a blocked domain, it remembers the destination IP that packet was headed to. Every later packet — even with zero SNI, even fully encrypted — gets checked against that IP too. That's the same approach real DPI/firewall tools use, since they run into the exact same problem.

## What's intentionally not in here

I scoped this deliberately rather than trying to build everything a production DPI tool would have:

- No full TCP connection/flow state tracking (SYN/ACK/FIN state machine) — packets are classified independently rather than grouped into tracked flows
- No IPv6 support — IPv4 only
- No live capture from a network interface yet — this reads from `.pcap` files (adding live capture would mean pulling in libpcap/Npcap for OS-level raw socket access, which is a reasonable next step)

## What I'd add next

- Live packet capture via libpcap, instead of only reading saved `.pcap` files
- IPv6 header parsing
- A small stats dashboard that updates in real time instead of printing a summary at the end
