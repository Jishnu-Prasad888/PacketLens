// sniffer_backend.cpp  (updated — adds HTTP API)
#include "sniffer_backend.h"
#include "tcp_parser.h"

#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>

#include <queue>
#include <mutex>
#include <condition_variable>
#include <unordered_map>
#include <unordered_set>
#include <fstream>
#include <cstring>
#include <iostream>
#include <memory>
#include <optional>
#include <chrono>

// ── Internal packet queue ─────────────────────────────────────────────────────
struct SnifferBackend::RawPacket {
    pcap_pkthdr           header;
    std::vector<u_char>   data;
};

struct SnifferBackend::PacketQueue {
    std::queue<RawPacket>      q;
    std::mutex                 mtx;
    std::condition_variable    cv;
    bool                       done = false;

    void push(RawPacket rp) {
        std::unique_lock<std::mutex> lk(mtx);
        q.push(std::move(rp));
        cv.notify_one();
    }

    bool pop(RawPacket& out) {
        std::unique_lock<std::mutex> lk(mtx);
        cv.wait(lk, [&]{ return !q.empty() || done; });
        if (q.empty()) return false;
        out = std::move(q.front());
        q.pop();
        return true;
    }

    void shutdown() {
        std::unique_lock<std::mutex> lk(mtx);
        done = true;
        cv.notify_all();
    }
};

// ── TCP flag helper ───────────────────────────────────────────────────────────
struct TCPFlags { bool syn = false, fin = false, rst = false; };
static TCPFlags parse_tcp_flags(const u_char* tcp_hdr) {
    uint8_t f = tcp_hdr[13];
    return { bool(f & 0x02), bool(f & 0x01), bool(f & 0x04) };
}

// ── Process name helper ───────────────────────────────────────────────────────
static std::string read_process_name(pid_t pid) {
    std::string p;
    std::ifstream f("/proc/" + std::to_string(pid) + "/comm");
    if (f && std::getline(f, p)) {
        while (!p.empty() && (p.back() == '\n' || p.back() == '\r')) p.pop_back();
        if (!p.empty()) return p;
    }
    std::ifstream g("/proc/" + std::to_string(pid) + "/cmdline", std::ios::binary);
    if (g) {
        std::string c; std::getline(g, c, '\0');
        if (!c.empty()) {
            auto pos = c.find_last_of('/');
            return (pos != std::string::npos) ? c.substr(pos + 1) : c;
        }
    }
    return {};
}

// ── Constructor / Destructor ──────────────────────────────────────────────────
SnifferBackend::SnifferBackend(QObject* parent)
    : QObject(parent), queue_(std::make_unique<PacketQueue>())
{}

SnifferBackend::~SnifferBackend() {
    stop();
}

// ── start() ───────────────────────────────────────────────────────────────────
bool SnifferBackend::start() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs = nullptr;

    if (pcap_findalldevs(&alldevs, errbuf) == -1 || !alldevs) {
        emit errorOccurred(QString("No devices found: %1\nRun as root.").arg(errbuf));
        return false;
    }

    pcap_t* handle = pcap_open_live(alldevs->name, BUFSIZ, 1, 1000, errbuf);
    pcap_freealldevs(alldevs);

    if (!handle) {
        emit errorOccurred(QString("pcap_open_live failed: %1").arg(errbuf));
        return false;
    }

    if (pcap_datalink(handle) != DLT_EN10MB) {
        emit errorOccurred("Unsupported link-layer type (need Ethernet).");
        pcap_close(handle);
        return false;
    }

    struct bpf_program fp;
    char filter[] = "tcp or udp";
    if (pcap_compile(handle, &fp, filter, 1, 0) == -1 ||
        pcap_setfilter(handle, &fp) == -1) {
        emit errorOccurred("Failed to compile/set BPF filter.");
        pcap_close(handle);
        return false;
    }

    pcap_handle_ = handle;
    running_.store(true);

    sniffer_thread_ = std::thread(&SnifferBackend::snifferThread, this);
    worker_thread_  = std::thread(&SnifferBackend::workerThread,  this);

    // ── Start embedded HTTP API ───────────────────────────────────────────────
    httpApi_ = std::make_unique<HttpApi>(
        HTTP_API_PORT,
        // Snapshot lambda — called from HttpApi's thread; FlowManager is mutex-guarded
        [this]() -> std::vector<FlowSnapshot> {
            return manager_.get_snapshot();
        },
        // Stats lambda
        [this](uint64_t& pkts, uint64_t& bytes, size_t& flows) {
            pkts  = manager_.total_packets();
            bytes = manager_.total_bytes();
            flows = manager_.get_flow_count();
        }
    );

    if (!httpApi_->start()) {
        // Non-fatal — PacketLens works fine without the API
        std::cerr << "[HttpApi] Failed to start — MCP integration unavailable\n";
        httpApi_.reset();
    }

    return true;
}

// ── stop() ────────────────────────────────────────────────────────────────────
void SnifferBackend::stop() {
    if (!running_.exchange(false)) return;

    if (httpApi_) {
        httpApi_->stop();
        httpApi_.reset();
    }

    if (pcap_handle_) {
        pcap_breakloop(static_cast<pcap_t*>(pcap_handle_));
    }
    queue_->shutdown();

    if (sniffer_thread_.joinable()) sniffer_thread_.join();
    if (worker_thread_.joinable())  worker_thread_.join();

    if (pcap_handle_) {
        pcap_close(static_cast<pcap_t*>(pcap_handle_));
        pcap_handle_ = nullptr;
    }
}

// ── Sniffer thread ────────────────────────────────────────────────────────────
void SnifferBackend::snifferThread() {
    auto* handle = static_cast<pcap_t*>(pcap_handle_);
    while (running_.load()) {
        pcap_pkthdr* hdr;
        const u_char* pkt;
        int res = pcap_next_ex(handle, &hdr, &pkt);
        if (res <= 0) continue;

        RawPacket rp;
        rp.header = *hdr;
        rp.data.assign(pkt, pkt + hdr->caplen);
        queue_->push(std::move(rp));
    }
}

// ── Worker thread ─────────────────────────────────────────────────────────────
void SnifferBackend::workerThread() {
    TcpParser parser;
    std::unordered_set<FlowKey, FlowHash>                                        seen;
    std::unordered_map<FlowKey, std::chrono::steady_clock::time_point, FlowHash> last_lookup;
    auto last_gc = std::chrono::steady_clock::now();

    RawPacket rp;
    while (queue_->pop(rp)) {
        if (rp.header.caplen < 34) continue;

        const u_char* pkt = rp.data.data();
        uint16_t eth_type = ntohs(*reinterpret_cast<const uint16_t*>(pkt + 12));
        if (eth_type != 0x0800) continue;

        const u_char* ip  = pkt + 14;
        uint8_t ihl       = (ip[0] & 0x0F) * 4;
        if (rp.header.caplen < static_cast<uint32_t>(14 + ihl + 4)) continue;

        uint8_t proto = ip[9];
        if (proto != 6 && proto != 17) continue;

        uint32_t sip = 0, dip = 0;
        std::memcpy(&sip, ip + 12, 4);
        std::memcpy(&dip, ip + 16, 4);

        const u_char*  l4    = ip + ihl;
        uint16_t sport       = ntohs(*reinterpret_cast<const uint16_t*>(l4));
        uint16_t dport       = ntohs(*reinterpret_cast<const uint16_t*>(l4 + 2));

        bool tcp_syn = false, tcp_fin_rst = false;
        if (proto == 6 && rp.header.caplen >= static_cast<uint32_t>(14 + ihl + 14)) {
            auto fl   = parse_tcp_flags(l4);
            tcp_syn   = fl.syn;
            tcp_fin_rst = fl.fin || fl.rst;
        }

        FlowKey key = make_key(sip, dip, sport, dport, proto);
        auto now    = std::chrono::steady_clock::now();
        bool is_new = (seen.find(key) == seen.end());

        auto cached = manager_.get_cached_process(key);
        bool do_lookup = false;
        if (!cached) {
            auto it = last_lookup.find(key);
            if (is_new || it == last_lookup.end() ||
                std::chrono::duration_cast<std::chrono::seconds>(now - it->second).count() >= 1) {
                do_lookup = true;
                last_lookup[key] = now;
            }
        }
        if (is_new) seen.insert(key);

        if (do_lookup) {
            parser.refresh();
            auto entry = parser.find(sip, sport, dip, dport);
            if (entry && entry->inode != 0) {
                auto pid_opt = parser.inode_to_pid(entry->inode);
                if (pid_opt) {
                    pid_t pid = *pid_opt;
                    std::string name = read_process_name(pid);
                    ProcessInfo info; info.pid = pid; info.name = name;
                    manager_.cache_process(key, info);
                    last_lookup.erase(key);

                    char sa[INET_ADDRSTRLEN], da[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &sip, sa, sizeof(sa));
                    inet_ntop(AF_INET, &dip, da, sizeof(da));
                    emit newConnectionFound(
                        QString::fromUtf8(sa),
                        QString::fromUtf8(da),
                        sport, dport,
                        proto == 6 ? "TCP" : "UDP",
                        QString::fromStdString(name.empty()
                            ? ("pid:" + std::to_string(pid)) : name)
                    );
                }
            }
        }

        manager_.update(key, rp.header.len, tcp_syn, tcp_fin_rst);

        if (std::chrono::duration_cast<std::chrono::seconds>(now - last_gc).count() >= 10) {
            manager_.garbage_collect();
            last_gc = now;
        }
    }
}
