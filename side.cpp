// D:\PacketLens\main.cpp
#include <iostream>
#include <pcap.h>
#include <unordered_map>
#include <chrono>
#include <thread>
#include <arpa/inet.h>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <vector>
#include <memory>
#include <unordered_set>
#include <cstring>
#include <iomanip>
#include <fstream>
#include <optional>
#include <sys/types.h>
#include "tcp_parser.h"

using namespace std;

struct FlowKey {
    uint32_t ip1;   // stored in network byte order (as in packet / parser)
    uint32_t ip2;
    uint16_t port1; // host byte order
    uint16_t port2;
    uint8_t proto;

    bool operator==(const FlowKey& other) const {
        return ip1 == other.ip1 && ip2 == other.ip2 &&
               port1 == other.port1 && port2 == other.port2 &&
               proto == other.proto;
    }
};

struct FlowHash {
    size_t operator()(const FlowKey& k) const {
        return ((size_t)k.ip1) ^
               (((size_t)k.ip2) << 1) ^
               (((size_t)k.port1) << 2) ^
               (((size_t)k.port2) << 3) ^
               (((size_t)k.proto) << 4);
    }
};

enum FlowState {
    FLOW_NEW,
    FLOW_ESTABLISHED,
    FLOW_CLOSED
};

struct FlowData {
    uint64_t packets = 0;
    uint64_t bytes = 0;
    FlowState state = FLOW_NEW;
    chrono::steady_clock::time_point last_seen;
    bool tcp_syn_seen = false;
    bool tcp_fin_rst_seen = false;

    FlowData() : last_seen(chrono::steady_clock::now()) {}
};

FlowKey make_key(uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport, uint8_t proto) {
    FlowKey k;
    // Normalize so the smaller tuple (ip,port) comes first to make flow direction-agnostic
    if (sip < dip || (sip == dip && sport <= dport)) {
        k.ip1 = sip;
        k.ip2 = dip;
        k.port1 = sport;
        k.port2 = dport;
    } else {
        k.ip1 = dip;
        k.ip2 = sip;
        k.port1 = dport;
        k.port2 = sport;
    }
    k.proto = proto;
    return k;
}

struct ProcessInfo {
    pid_t pid = 0;
    std::string name;
};

class FlowManager {
private:
    unordered_map<FlowKey, FlowData, FlowHash> flows;
    unordered_map<FlowKey, ProcessInfo, FlowHash> process_cache;
    mutex flow_mutex;
    static constexpr int TCP_TIMEOUT_SEC = 60;
    static constexpr int UDP_TIMEOUT_SEC = 30;
    uint64_t total_packets = 0;
    uint64_t total_bytes = 0;

public:
    void update(const FlowKey& key, uint32_t bytes, bool tcp_syn, bool tcp_fin_rst) {
        unique_lock<mutex> lock(flow_mutex);

        auto it = flows.find(key);
        if (it == flows.end()) {
            flows[key] = FlowData();
            it = flows.find(key);
        }

        FlowData& data = it->second;
        data.packets++;
        data.bytes += bytes;
        data.last_seen = chrono::steady_clock::now();
        total_packets++;
        total_bytes += bytes;

        if (key.proto == 6) {
            if (tcp_syn) {
                data.tcp_syn_seen = true;
                if (data.state == FLOW_NEW) {
                    data.state = FLOW_ESTABLISHED;
                }
            }
            if (tcp_fin_rst) {
                data.tcp_fin_rst_seen = true;
                data.state = FLOW_CLOSED;
            }
        } else if (key.proto == 17) {
            data.state = FLOW_ESTABLISHED;
        }
    }

    optional<ProcessInfo> get_cached_process(const FlowKey& key) {
        unique_lock<mutex> lock(flow_mutex);
        auto it = process_cache.find(key);
        if (it != process_cache.end()) {
            return it->second;
        }
        return nullopt;
    }

    void cache_process(const FlowKey& key, const ProcessInfo& info) {
        unique_lock<mutex> lock(flow_mutex);
        process_cache[key] = info;
    }

    void garbage_collect() {
        unique_lock<mutex> lock(flow_mutex);
        auto now = chrono::steady_clock::now();
        int deleted = 0;

        for (auto it = flows.begin(); it != flows.end(); ) {
            int timeout = (it->first.proto == 6) ? TCP_TIMEOUT_SEC : UDP_TIMEOUT_SEC;
            auto elapsed = chrono::duration_cast<chrono::seconds>(
                now - it->second.last_seen).count();

            if (elapsed > timeout) {
                FlowKey key = it->first;
                it = flows.erase(it);
                process_cache.erase(key);
                deleted++;
            } else {
                ++it;
            }
        }

        if (deleted > 0) {
            cout << "[GC] Deleted " << deleted << " stale flows\n";
        }
    }

    void print() {
        unique_lock<mutex> lock(flow_mutex);
        cout << "\n========== NETWORK FLOW STATISTICS ==========\n";
        cout << "Total Packets: " << total_packets << " | Total Bytes: " << total_bytes << "\n";
        cout << "Active Flows: " << flows.size() << "\n\n";
        cout << left << setw(15) << "SrcIP"
             << setw(15) << "DstIP"
             << setw(7) << "SPrt"
             << setw(7) << "DPrt"
             << setw(5) << "Pro"
             << setw(10) << "Packets"
             << setw(12) << "Bytes"
             << setw(20) << "Process"
             << setw(12) << "State\n";
        cout << string(113, '-') << "\n";

        for (auto& it : flows) {
            char a[INET_ADDRSTRLEN], b[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &it.first.ip1, a, sizeof(a));
            inet_ntop(AF_INET, &it.first.ip2, b, sizeof(b));

            string state_str;
            if (it.second.state == FLOW_NEW) state_str = "NEW";
            else if (it.second.state == FLOW_ESTABLISHED) state_str = "EST";
            else state_str = "CLOSED";

            string proc_name = "";
            auto pit = process_cache.find(it.first);
            if (pit != process_cache.end()) {
                if (!pit->second.name.empty()) proc_name = pit->second.name;
                else if (pit->second.pid != 0) proc_name = ("pid:" + to_string(pit->second.pid));
            }

            cout << left << setw(15) << a
                 << setw(15) << b
                 << setw(7) << it.first.port1
                 << setw(7) << it.first.port2
                 << setw(5) << (int)it.first.proto
                 << setw(10) << it.second.packets
                 << setw(12) << it.second.bytes
                 << setw(20) << proc_name
                 << setw(12) << state_str << "\n";
        }
        cout << "==========================================\n";
    }

    size_t get_flow_count() {
        unique_lock<mutex> lock(flow_mutex);
        return flows.size();
    }
};

struct RawPacket {
    pcap_pkthdr header;
    vector<u_char> data;
};

template<typename T>
class ThreadSafeQueue {
private:
    queue<T> q;
    mutex m;
    condition_variable cv;
    volatile bool shutdown_flag = false;

public:
    void push(T val) {
        unique_lock<mutex> lock(m);
        q.push(move(val));
        cv.notify_one();
    }

    bool pop(T& result) {
        unique_lock<mutex> lock(m);
        cv.wait(lock, [this] { return !q.empty() || shutdown_flag; });

        if (q.empty()) {
            return false;
        }

        result = move(q.front());
        q.pop();
        return true;
    }

    size_t size() {
        unique_lock<mutex> lock(m);
        return q.size();
    }

    void shutdown() {
        unique_lock<mutex> lock(m);
        shutdown_flag = true;
        cv.notify_all();
    }
};

struct TCPFlags {
    bool syn = false;
    bool fin = false;
    bool rst = false;
};

TCPFlags parse_tcp_flags(const u_char* tcp_header) {
    TCPFlags flags;
    uint8_t flags_byte = tcp_header[13];
    flags.syn = (flags_byte & 0x02) != 0;
    flags.fin = (flags_byte & 0x01) != 0;
    flags.rst = (flags_byte & 0x04) != 0;
    return flags;
}

static string read_process_name(pid_t pid) {
    string proc_name;
    string comm_path = "/proc/" + to_string(pid) + "/comm";
    ifstream commf(comm_path);
    if (commf.is_open()) {
        getline(commf, proc_name);
        while (!proc_name.empty() && (proc_name.back() == '\n' || proc_name.back() == '\r'))
            proc_name.pop_back();
        if (!proc_name.empty()) return proc_name;
    }

    string cmd_path = "/proc/" + to_string(pid) + "/cmdline";
    ifstream cmdf(cmd_path, ios::in | ios::binary);
    if (cmdf.is_open()) {
        string content;
        getline(cmdf, content, '\0');
        if (!content.empty()) {
            size_t pos = content.find_last_of('/');
            if (pos != string::npos) content = content.substr(pos + 1);
            return content;
        }
    }

    return string();
}

int main(int argc, char** argv) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        cerr << "Error finding devices: " << errbuf << "\n";
        return 1;
    }

    if (alldevs == nullptr) {
        cerr << "No devices found. Run with sudo.\n";
        return 1;
    }

    pcap_if_t *dev = alldevs;
    cout << "Using device: " << dev->name << "\n";

    pcap_t *handle = pcap_open_live(dev->name, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        cerr << "Open failed: " << errbuf << "\n";
        return 1;
    }

    if (pcap_datalink(handle) != DLT_EN10MB) {
        cerr << "Unsupported link layer type\n";
        pcap_close(handle);
        return 1;
    }

    struct bpf_program fp;
    char filter_exp[] = "tcp or udp";
    bpf_u_int32 net = 0;

    if (pcap_compile(handle, &fp, filter_exp, 1, net) == -1) {
        cerr << "Compilation failed\n";
        pcap_close(handle);
        return 1;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        cerr << "Set filter failed\n";
        pcap_close(handle);
        return 1;
    }

    ThreadSafeQueue<RawPacket> packetQueue;
    FlowManager manager;

    thread sniffer([&]() {
        cout << "[Sniffer] Thread started\n";
        while (true) {
            pcap_pkthdr *header;
            const u_char *packet;
            int res = pcap_next_ex(handle, &header, &packet);

            if (res <= 0) continue;

            RawPacket rp;
            rp.header = *header;
            rp.data.assign(packet, packet + header->caplen);
            packetQueue.push(move(rp));
        }
    });

    thread worker([&]() {
        TcpParser parser;

        cout << "[Worker] Thread started\n";
        auto last_print = chrono::steady_clock::now();
        auto last_gc = chrono::steady_clock::now();

        RawPacket rp;
        unordered_set<FlowKey, FlowHash> seen_flows;
        unordered_map<FlowKey, chrono::steady_clock::time_point, FlowHash> last_lookup_attempt;

        while (packetQueue.pop(rp)) {
            if (rp.header.caplen < 34) continue;

            const u_char* packet = rp.data.data();

            uint16_t eth_type = ntohs(*(uint16_t*)(packet + 12));
            if (eth_type != 0x0800) continue;

            const u_char* ip = packet + 14;
            uint8_t ihl = (ip[0] & 0x0F) * 4;

            if (rp.header.caplen < 14 + ihl + 4) continue;

            uint8_t proto = ip[9];
            if (proto != 6 && proto != 17) continue;

            uint32_t sip = 0, dip = 0;
            memcpy(&sip, ip + 12, sizeof(sip));
            memcpy(&dip, ip + 16, sizeof(dip));

            const u_char* l4 = ip + ihl;

            uint16_t sport = ntohs(*(uint16_t*)l4);
            uint16_t dport = ntohs(*(uint16_t*)(l4 + 2));

            bool tcp_syn = false, tcp_fin_rst = false;
            if (proto == 6 && rp.header.caplen >= 14 + ihl + 14) {
                TCPFlags tcp_flags = parse_tcp_flags(l4);
                tcp_syn = tcp_flags.syn;
                tcp_fin_rst = (tcp_flags.fin || tcp_flags.rst);
            }

            FlowKey key = make_key(sip, dip, sport, dport, proto);
            auto now = chrono::steady_clock::now();

            bool is_new_flow = (seen_flows.find(key) == seen_flows.end());
            auto cached = manager.get_cached_process(key);
            bool should_attempt_lookup = false;

            if (!cached) {
                auto last_attempt = last_lookup_attempt.find(key);
                if (is_new_flow || last_attempt == last_lookup_attempt.end() ||
                    chrono::duration_cast<chrono::seconds>(now - last_attempt->second).count() >= 1) {
                    should_attempt_lookup = true;
                    last_lookup_attempt[key] = now;
                }
            }

            if (is_new_flow) {
                seen_flows.insert(key);
            }

            if (should_attempt_lookup) {
                parser.refresh();

                optional<TcpEntry> entry = parser.find(sip, sport, dip, dport);

                if (!entry) {
                    char sipbuf[INET_ADDRSTRLEN], dipbuf[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &sip, sipbuf, sizeof(sipbuf));
                    inet_ntop(AF_INET, &dip, dipbuf, sizeof(dipbuf));
                    cerr << "[DEBUG] No /proc/net/tcp entry for "
                         << sipbuf << ":" << sport << " -> "
                         << dipbuf << ":" << dport << "\n";
                }

                if (entry && entry->inode != 0) {
                    if (cached) {
                        char ipbuf[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET, &sip, ipbuf, sizeof(ipbuf));
                        cout << "[FLOW->SOCKET] "
                             << ipbuf << ":" << sport
                             << " -> inode=" << entry->inode
                             << " -> pid=" << cached->pid;
                        if (!cached->name.empty()) {
                            cout << " (" << cached->name << ")";
                        }
                        cout << "\n";
                    } else {
                        char ipbuf[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET, &sip, ipbuf, sizeof(ipbuf));

                        cout << "[FLOW->SOCKET] "
                             << ipbuf << ":" << sport
                             << " -> inode=" << entry->inode;

                        auto pid_opt = parser.inode_to_pid(entry->inode);
                        if (pid_opt) {
                            pid_t pid = *pid_opt;
                            cout << " -> pid=" << pid;

                            string proc_name = read_process_name(pid);
                            if (!proc_name.empty()) {
                                cout << " (" << proc_name << ")";
                            }
                            cout << "\n";

                            ProcessInfo pinfo;
                            pinfo.pid = pid;
                            pinfo.name = proc_name;
                            manager.cache_process(key, pinfo);
                            last_lookup_attempt.erase(key);
                        } else {
                            cout << " -> pid=UNKNOWN (permission or transient)\n";
                            cerr << "[DEBUG] inode->pid failed for inode=" << entry->inode
                                 << ". Are you root? mount /proc hidepid?\n";
                        }
                    }
                }
            }

            manager.update(key, rp.header.len, tcp_syn, tcp_fin_rst);

            if (chrono::duration_cast<chrono::seconds>(now - last_print).count() >= 1) {
                system("clear");
                cout << "Queue Size: " << packetQueue.size() << " packets\n";
                manager.print();
                last_print = now;
            }

            if (chrono::duration_cast<chrono::seconds>(now - last_gc).count() >= 10) {
                manager.garbage_collect();
                last_gc = now;
            }
        }

        cout << "[Worker] Thread exiting\n";
    });

    sniffer.join();
    worker.join();

    pcap_close(handle);
    pcap_freealldevs(alldevs);

    return 0;
}
