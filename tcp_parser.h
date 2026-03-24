// D:\PacketLens\tcp_parser.h
#ifndef TCP_PARSER_H
#define TCP_PARSER_H

#include <vector>
#include <cstdint>
#include <optional>
#include <sys/types.h>

struct TcpEntry {
    uint32_t local_ip;   // stored in network byte order (big-endian, as in packet)
    uint16_t local_port; // host byte order numeric
    uint32_t remote_ip;  // network byte order
    uint16_t remote_port;
    uint64_t inode;
};

class TcpParser {
public:
    std::vector<TcpEntry> entries;

    void refresh();

    std::optional<TcpEntry> find(uint32_t src_ip, uint16_t src_port,
                                 uint32_t dst_ip, uint16_t dst_port);

    std::optional<pid_t> inode_to_pid(uint64_t inode);
};

#endif
