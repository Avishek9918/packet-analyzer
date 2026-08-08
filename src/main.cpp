#include "pcap_reader.h"
#include "packet_parser.h"
#include "sni_extractor.h"
#include "traffic_stats.h"
#include "rule_manager.h"
#include "thread_safe_queue.h"
#include "pcap_writer.h"
#include <iostream>
#include <vector>
#include <string>
#include <thread>
#include <mutex>
#include <atomic>
#include <memory>

namespace {

constexpr int NUM_WORKER_THREADS = 3;

// One item of work handed from the reader thread to a worker thread.
struct WorkItem {
    RawPacket packet;
    int packet_number;
};

// Everything a worker thread touches that's SHARED across threads.
// Anything not in here (like a local ParsedPacket) is safely private
// to each worker's own stack -- no locking needed for those.
struct SharedState {
    RuleManager rules;
    TrafficStats stats;
    std::mutex stats_mutex;   // protects rules + stats from concurrent access
    std::mutex print_mutex;   // protects std::cout so lines don't interleave
    std::atomic<int> blocked_total{0};

    std::unique_ptr<PcapWriter> output_writer; // null if --output wasn't given
    std::mutex writer_mutex;                    // protects output_writer from concurrent writes
};

void workerLoop(ThreadSafeQueue<WorkItem>& queue, SharedState& shared) {
    WorkItem item;
    while (queue.waitAndPop(item)) {
        // --- Parsing is CPU work with no shared state -- runs freely
        // in parallel across all worker threads, no lock needed. ---
        ParsedPacket parsed = PacketParser::parse(item.packet.data);

        std::string sni;
        if (parsed.has_tcp && parsed.payload_offset < item.packet.data.size()) {
            std::vector<uint8_t> payload(
                item.packet.data.begin() + parsed.payload_offset,
                item.packet.data.end()
            );
            sni = SniExtractor::extract(payload);
        }

        if (!parsed.has_ip) continue;

        // --- From here on we touch SHARED state (rules + stats) ---
        // so this section must be protected by a mutex.
        bool blocked = false;
        {
            std::lock_guard<std::mutex> lock(shared.stats_mutex);
            blocked = shared.rules.shouldBlock(parsed.ip.dst_ip, sni);
            if (!blocked) {
                shared.stats.recordPacket(parsed.ip.dst_ip, parsed.ip.protocol, sni);
            }
        }
        if (blocked) {
            shared.blocked_total++; // std::atomic -- safe without a mutex
        } else if (shared.output_writer) {
            std::lock_guard<std::mutex> lock(shared.writer_mutex);
            shared.output_writer->writePacket(item.packet);
        }

        // --- Printing also needs its own lock, otherwise output from
        // different threads can interleave mid-line and look garbled. ---
        {
            std::lock_guard<std::mutex> lock(shared.print_mutex);
            std::cout << "--- Packet #" << item.packet_number
                       << " (" << item.packet.captured_len << " bytes) ---\n";
            if (parsed.has_ip) {
                std::cout << "  IP: " << PacketParser::ipToString(parsed.ip.src_ip)
                           << " -> " << PacketParser::ipToString(parsed.ip.dst_ip) << "\n";
            }
            if (!sni.empty()) {
                std::cout << "  TLS SNI: " << sni << (blocked ? "  >>> BLOCKED <<<" : "") << "\n";
            }
        }
    }
}

} // namespace

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <pcap_file> [--block-domain <domain>]...\n";
        return 1;
    }

    std::string pcap_path = argv[1];
    SharedState shared;

    for (int i = 2; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--block-domain" && i + 1 < argc) {
            shared.rules.blockDomain(argv[i + 1]);
            std::cout << "[Rule] Blocking domain: " << argv[i + 1] << "\n";
            i++;
        } else if (arg == "--output" && i + 1 < argc) {
            shared.output_writer = std::make_unique<PcapWriter>();
            if (!shared.output_writer->open(argv[i + 1])) {
                return 1;
            }
            std::cout << "[Output] Writing allowed packets to: " << argv[i + 1] << "\n";
            i++;
        }
    }

    PcapReader reader;
    if (!reader.open(pcap_path)) {
        return 1;
    }

    ThreadSafeQueue<WorkItem> queue;

    // Start the worker pool BEFORE we begin reading, so they're ready
    // to start pulling work as soon as the first packet is pushed.
    std::vector<std::thread> workers;
    for (int i = 0; i < NUM_WORKER_THREADS; i++) {
        workers.emplace_back(workerLoop, std::ref(queue), std::ref(shared));
    }

    // Main thread acts as the sole producer: read packets, push to queue.
    RawPacket packet;
    int count = 0;
    while (reader.readNextPacket(packet)) {
        count++;
        queue.push(WorkItem{std::move(packet), count});
    }

    // No more packets coming -- wake up any workers still waiting so
    // they can see the queue is empty + shut down and exit their loop.
    queue.shutdown();

    // Wait for every worker to finish processing what's left in the
    // queue and exit cleanly before we print the final summary.
    for (auto& t : workers) {
        t.join();
    }

    std::cout << "\nTotal packets read: " << count << "\n";
    std::cout << "Packets blocked: " << shared.blocked_total.load() << "\n";
    shared.stats.printSummary();
    return 0;
}
