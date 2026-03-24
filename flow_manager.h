#pragma once
#include <string>
#include <vector>
#include <unordered_map>
#include <chrono>
#include <mutex>
#include <optional>
#include <cstdint>
#include <sys/types.h>
#include <arpa/inet.h>
#include <iomanip>
#include <sstream>
#include <iostream>

// ── FlowKey ───────────────────────────────────────────────────────────────────
struct FlowKey {
    uint32_t ip1;   // network byte order
    uint32_t ip2;
    uint16_t port1; // host byte order
    uint16_t port2;
    uint8_t  proto;

    bool operator==(const FlowKey& o) const {
        return ip1 == o.ip1 && ip2 == o.ip2 &&
               port1 == o.port1 && port2 == o.port2 &&
               proto == o.proto;
    }
};

struct FlowHash {
    size_t operator()(const FlowKey& k) const {
        return ((size_t)k.ip1)       ^
               (((size_t)k.ip2)   << 1) ^
               (((size_t)k.port1) << 2) ^
               (((size_t)k.port2) << 3) ^
               (((size_t)k.proto) << 4);
    }
};

inline FlowKey make_key(uint32_t sip, uint32_t dip,
                        uint16_t sport, uint16_t dport, uint8_t proto) {
    FlowKey k;
    if (sip < dip || (sip == dip && sport <= dport)) {
        k.ip1 = sip; k.ip2 = dip; k.port1 = sport; k.port2 = dport;
    } else {
        k.ip1 = dip; k.ip2 = sip; k.port1 = dport; k.port2 = sport;
    }
    k.proto = proto;
    return k;
}

// ── State ─────────────────────────────────────────────────────────────────────
enum FlowState { FLOW_NEW, FLOW_ESTABLISHED, FLOW_CLOSED };

struct FlowData {
    uint64_t packets = 0;
    uint64_t bytes   = 0;
    FlowState state  = FLOW_NEW;
    std::chrono::steady_clock::time_point last_seen;
    bool tcp_syn_seen     = false;
    bool tcp_fin_rst_seen = false;

    FlowData() : last_seen(std::chrono::steady_clock::now()) {}
};

struct ProcessInfo {
    pid_t       pid  = 0;
    std::string name;
};

// ── Snapshot row (what the GUI displays) ─────────────────────────────────────
struct FlowSnapshot {
    std::string src_ip;
    std::string dst_ip;
    uint16_t    src_port  = 0;
    uint16_t    dst_port  = 0;
    std::string protocol; // "TCP" / "UDP"
    uint64_t    packets   = 0;
    uint64_t    bytes     = 0;
    std::string process;
    std::string state;
};

// ── FlowManager ───────────────────────────────────────────────────────────────
class FlowManager {
public:
    static constexpr int TCP_TIMEOUT_SEC = 60;
    static constexpr int UDP_TIMEOUT_SEC = 30;

    void update(const FlowKey& key, uint32_t bytes,
                bool tcp_syn, bool tcp_fin_rst) {
        std::unique_lock<std::mutex> lk(mtx_);

        auto& data = flows_[key];
        data.packets++;
        data.bytes += bytes;
        data.last_seen = std::chrono::steady_clock::now();
        total_packets_++;
        total_bytes_ += bytes;

        if (key.proto == 6) {
            if (tcp_syn)          { data.tcp_syn_seen = true; if (data.state == FLOW_NEW) data.state = FLOW_ESTABLISHED; }
            if (tcp_fin_rst)      { data.tcp_fin_rst_seen = true; data.state = FLOW_CLOSED; }
        } else if (key.proto == 17) {
            data.state = FLOW_ESTABLISHED;
        }
    }

    std::optional<ProcessInfo> get_cached_process(const FlowKey& key) {
        std::unique_lock<std::mutex> lk(mtx_);
        auto it = proc_cache_.find(key);
        if (it != proc_cache_.end()) return it->second;
        return std::nullopt;
    }

    void cache_process(const FlowKey& key, const ProcessInfo& info) {
        std::unique_lock<std::mutex> lk(mtx_);
        proc_cache_[key] = info;
    }

    void garbage_collect() {
        std::unique_lock<std::mutex> lk(mtx_);
        auto now = std::chrono::steady_clock::now();
        for (auto it = flows_.begin(); it != flows_.end(); ) {
            int timeout = (it->first.proto == 6) ? TCP_TIMEOUT_SEC : UDP_TIMEOUT_SEC;
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                               now - it->second.last_seen).count();
            if (elapsed > timeout) {
                proc_cache_.erase(it->first);
                it = flows_.erase(it);
            } else {
                ++it;
            }
        }
    }

    // Thread-safe snapshot for the GUI — called every 1 s from QTimer
    std::vector<FlowSnapshot> get_snapshot() {
        std::unique_lock<std::mutex> lk(mtx_);
        std::vector<FlowSnapshot> out;
        out.reserve(flows_.size());

        for (auto& [key, data] : flows_) {
            FlowSnapshot s;
            char a[INET_ADDRSTRLEN], b[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &key.ip1, a, sizeof(a));
            inet_ntop(AF_INET, &key.ip2, b, sizeof(b));
            s.src_ip   = a;
            s.dst_ip   = b;
            s.src_port = key.port1;
            s.dst_port = key.port2;
            s.protocol = (key.proto == 6) ? "TCP" : "UDP";
            s.packets  = data.packets;
            s.bytes    = data.bytes;

            auto pit = proc_cache_.find(key);
            if (pit != proc_cache_.end()) {
                s.process = pit->second.name.empty()
                            ? ("pid:" + std::to_string(pit->second.pid))
                            : pit->second.name;
            }

            switch (data.state) {
                case FLOW_NEW:         s.state = "NEW";    break;
                case FLOW_ESTABLISHED: s.state = "EST";    break;
                case FLOW_CLOSED:      s.state = "CLOSED"; break;
            }
            out.push_back(std::move(s));
        }
        return out;
    }

    size_t get_flow_count() {
        std::unique_lock<std::mutex> lk(mtx_);
        return flows_.size();
    }

    uint64_t total_packets() {
        std::unique_lock<std::mutex> lk(mtx_);
        return total_packets_;
    }

    uint64_t total_bytes() {
        std::unique_lock<std::mutex> lk(mtx_);
        return total_bytes_;
    }

private:
    std::unordered_map<FlowKey, FlowData,    FlowHash> flows_;
    std::unordered_map<FlowKey, ProcessInfo, FlowHash> proc_cache_;
    std::mutex  mtx_;
    uint64_t    total_packets_ = 0;
    uint64_t    total_bytes_   = 0;
};
