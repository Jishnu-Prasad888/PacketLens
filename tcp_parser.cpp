#include "tcp_parser.h"
#include <fstream>
#include <sstream>
#include <string>
#include <iostream>
#include <arpa/inet.h>
#include <algorithm>
#include <dirent.h>
#include <unistd.h>
#include <limits.h>
#include <cstring>
#include <cctype>

using namespace std;

// Convert a /proc/net/tcp IPv4 hex string (e.g., "0100007F") into the same
// in-memory uint32_t layout produced by memcpy() from packet bytes.
static uint32_t hex_to_ip_network_order(const string& hex) {
    try {
        // /proc/net/tcp already prints IPv4 addresses in the byte order that
        // matches the packet-side memcpy() representation on little-endian Linux.
        // Do not byte-swap here, or tuple matching against captured packets fails.
        return static_cast<uint32_t>(stoul(hex, nullptr, 16));
    } catch (...) {
        return 0;
    }
}

// Convert hex port -> host-order uint16_t
static uint16_t hex_to_port_host_order(const string& hex) {
    uint16_t p = 0;
    try {
        p = static_cast<uint16_t>(stoul(hex, nullptr, 16));
    } catch (...) {
        return 0;
    }
    return p;
}

// Split "IP:PORT"
static pair<string, string> split_ip_port(const string& s) {
    size_t pos = s.find(':');
    if (pos == string::npos) return {"", ""};
    return {s.substr(0, pos), s.substr(pos + 1)};
}

void TcpParser::refresh() {
    entries.clear();

    ifstream file("/proc/net/tcp");
    if (!file.is_open()) {
        cerr << "Failed to open /proc/net/tcp\n";
        return;
    }

    string line;

    // Skip header
    getline(file, line);

    while (getline(file, line)) {
        auto start = line.find_first_not_of(" \t\r\n");
        if (start == string::npos) continue;
        string trimmed = line.substr(start);

        istringstream iss(trimmed);
        vector<string> tokens;
        string temp;

        while (iss >> temp) {
            tokens.push_back(temp);
        }

        if (tokens.size() < 10) continue;

        auto [lip_hex, lport_hex] = split_ip_port(tokens[1]);
        auto [rip_hex, rport_hex] = split_ip_port(tokens[2]);

        if (lip_hex.empty() || rip_hex.empty()) continue;

        TcpEntry entry;

        try {
            entry.local_ip = hex_to_ip_network_order(lip_hex);
            entry.local_port = hex_to_port_host_order(lport_hex);
            entry.remote_ip = hex_to_ip_network_order(rip_hex);
            entry.remote_port = hex_to_port_host_order(rport_hex);
            entry.inode = stoull(tokens[9]);
        } catch (...) {
            continue;
        }

        if (entry.local_ip == 0 && entry.remote_ip == 0) continue;

        entries.push_back(entry);
    }
}

optional<TcpEntry> TcpParser::find(uint32_t src_ip, uint16_t src_port,
                                   uint32_t dst_ip, uint16_t dst_port) {
    for (const auto& e : entries) {
        const bool packet_matches_socket =
            e.local_ip == src_ip && e.local_port == src_port &&
            e.remote_ip == dst_ip && e.remote_port == dst_port;

        const bool reverse_packet_matches_socket =
            e.local_ip == dst_ip && e.local_port == dst_port &&
            e.remote_ip == src_ip && e.remote_port == src_port;

        if (packet_matches_socket || reverse_packet_matches_socket) {
            return e;
        }
    }
    return nullopt;
}

optional<pid_t> TcpParser::inode_to_pid(uint64_t inode) {
    DIR* proc_dir = opendir("/proc");
    if (!proc_dir) {
        return nullopt;
    }

    struct dirent* dent;
    while ((dent = readdir(proc_dir)) != nullptr) {
        if (!isdigit(static_cast<unsigned char>(dent->d_name[0]))) continue;

        string pid_str = dent->d_name;
        string fd_dir_path = string("/proc/") + pid_str + "/fd";

        DIR* fd_dir = opendir(fd_dir_path.c_str());
        if (!fd_dir) {
            continue;
        }

        struct dirent* fdent;
        while ((fdent = readdir(fd_dir)) != nullptr) {
            if (fdent->d_name[0] == '.') continue;

            string fd_path = fd_dir_path + "/" + fdent->d_name;
            char linkbuf[PATH_MAX];
            ssize_t r = readlink(fd_path.c_str(), linkbuf, sizeof(linkbuf) - 1);
            if (r <= 0) continue;
            linkbuf[r] = '\0';
            string target(linkbuf);

            if (target.size() >= 9 && target.rfind("socket:[", 0) == 0) {
                size_t lb = target.find('[');
                size_t rb = target.find(']');
                if (lb != string::npos && rb != string::npos && rb > lb + 1) {
                    string num = target.substr(lb + 1, rb - lb - 1);
                    try {
                        unsigned long long found_inode = stoull(num);
                        if (found_inode == inode) {
                            closedir(fd_dir);
                            closedir(proc_dir);
                            pid_t pid = static_cast<pid_t>(stoi(pid_str));
                            return pid;
                        }
                    } catch (...) {
                    }
                }
            }
        }

        closedir(fd_dir);
    }

    closedir(proc_dir);
    return nullopt;
}
