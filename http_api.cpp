// http_api.cpp
#include "http_api.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include <sstream>
#include <iostream>
#include <algorithm>
#include <chrono>
#include <ctime>

// ── Constructor / Destructor ──────────────────────────────────────────────────
HttpApi::HttpApi(uint16_t port, SnapshotFn snapFn, StatsFn statsFn)
    : port_(port), snapFn_(std::move(snapFn)), statsFn_(std::move(statsFn))
{}

HttpApi::~HttpApi() { stop(); }

// ── Start ─────────────────────────────────────────────────────────────────────
bool HttpApi::start() {
    serverFd_ = ::socket(AF_INET, SOCK_STREAM, 0);
    if (serverFd_ < 0) {
        std::cerr << "[HttpApi] socket() failed\n";
        return false;
    }

    int opt = 1;
    ::setsockopt(serverFd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); // 127.0.0.1 only
    addr.sin_port        = htons(port_);

    if (::bind(serverFd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        std::cerr << "[HttpApi] bind() failed on port " << port_ << "\n";
        ::close(serverFd_);
        serverFd_ = -1;
        return false;
    }

    ::listen(serverFd_, 8);
    running_.store(true);
    thread_ = std::thread(&HttpApi::serverLoop, this);
    std::cout << "[HttpApi] Listening on http://127.0.0.1:" << port_ << "\n";
    return true;
}

// ── Stop ──────────────────────────────────────────────────────────────────────
void HttpApi::stop() {
    if (!running_.exchange(false)) return;
    if (serverFd_ >= 0) {
        ::shutdown(serverFd_, SHUT_RDWR);
        ::close(serverFd_);
        serverFd_ = -1;
    }
    if (thread_.joinable()) thread_.join();
}

// ── Server loop ───────────────────────────────────────────────────────────────
void HttpApi::serverLoop() {
    while (running_.load()) {
        // Use select() with a 500ms timeout so stop() wakes us cleanly
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(serverFd_, &fds);
        timeval tv{ 0, 500000 };
        int ready = ::select(serverFd_ + 1, &fds, nullptr, nullptr, &tv);
        if (ready <= 0) continue;

        sockaddr_in clientAddr{};
        socklen_t   clientLen = sizeof(clientAddr);
        int clientFd = ::accept(serverFd_,
                                reinterpret_cast<sockaddr*>(&clientAddr),
                                &clientLen);
        if (clientFd < 0) continue;

        // Handle inline (connections are short-lived GET requests)
        handleClient(clientFd);
        ::close(clientFd);
    }
}

// ── Handle one HTTP request ───────────────────────────────────────────────────
void HttpApi::handleClient(int fd) {
    // Read request (up to 4 KB — we only need the first line)
    char buf[4096] = {};
    ssize_t n = ::recv(fd, buf, sizeof(buf) - 1, 0);
    if (n <= 0) return;

    std::string req(buf, static_cast<size_t>(n));

    // Parse method + path from first line
    std::istringstream ss(req);
    std::string method, path;
    ss >> method >> path;

    // Strip query string
    auto qpos = path.find('?');
    if (qpos != std::string::npos) path = path.substr(0, qpos);

    std::string response;

    if (path == "/health") {
        response = httpOk("{\"status\":\"ok\"}");
    } else if (path == "/flows") {
        response = httpOk(buildFlowsJson());
    } else if (path == "/stats") {
        response = httpOk(buildStatsJson());
    } else {
        response = httpNotFound();
    }

    // Add CORS headers so browser-based tools can also query
    // (MCP server is localhost-only so this is safe)
    size_t hdrEnd = response.find("\r\n\r\n");
    if (hdrEnd != std::string::npos) {
        response.insert(hdrEnd, "\r\nAccess-Control-Allow-Origin: *");
    }

    ::send(fd, response.c_str(), response.size(), MSG_NOSIGNAL);
}

// ── JSON builders ─────────────────────────────────────────────────────────────
std::string HttpApi::escapeJson(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char esc[8];
                    snprintf(esc, sizeof(esc), "\\u%04x", c);
                    out += esc;
                } else {
                    out += c;
                }
        }
    }
    return out;
}

std::string HttpApi::buildFlowsJson() {
    auto snap = snapFn_();
    std::ostringstream j;
    j << "[\n";
    for (size_t i = 0; i < snap.size(); ++i) {
        const auto& f = snap[i];
        j << "  {"
          << "\"src_ip\":\""   << escapeJson(f.src_ip)   << "\","
          << "\"src_port\":"   << f.src_port              << ","
          << "\"dst_ip\":\""   << escapeJson(f.dst_ip)   << "\","
          << "\"dst_port\":"   << f.dst_port              << ","
          << "\"protocol\":\"" << escapeJson(f.protocol)  << "\","
          << "\"packets\":"    << f.packets               << ","
          << "\"bytes\":"      << f.bytes                 << ","
          << "\"process\":\""  << escapeJson(f.process)   << "\","
          << "\"state\":\""    << escapeJson(f.state)     << "\""
          << "}";
        if (i + 1 < snap.size()) j << ",";
        j << "\n";
    }
    j << "]";
    return j.str();
}

std::string HttpApi::buildStatsJson() {
    uint64_t pkts = 0, bytes = 0;
    size_t   flows = 0;
    statsFn_(pkts, bytes, flows);

    // ISO-8601 timestamp
    auto now  = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    char tsbuf[32];
    std::strftime(tsbuf, sizeof(tsbuf), "%Y-%m-%dT%H:%M:%SZ", std::gmtime(&t));

    std::ostringstream j;
    j << "{"
      << "\"total_packets\":"  << pkts  << ","
      << "\"total_bytes\":"    << bytes << ","
      << "\"active_flows\":"   << flows << ","
      << "\"timestamp\":\""    << tsbuf << "\""
      << "}";
    return j.str();
}

// ── HTTP response helpers ─────────────────────────────────────────────────────
std::string HttpApi::httpOk(const std::string& body, const std::string& ct) {
    std::ostringstream r;
    r << "HTTP/1.1 200 OK\r\n"
      << "Content-Type: " << ct << "; charset=utf-8\r\n"
      << "Content-Length: " << body.size() << "\r\n"
      << "Connection: close\r\n"
      << "\r\n"
      << body;
    return r.str();
}

std::string HttpApi::httpNotFound() {
    std::string body = "{\"error\":\"not found\"}";
    std::ostringstream r;
    r << "HTTP/1.1 404 Not Found\r\n"
      << "Content-Type: application/json\r\n"
      << "Content-Length: " << body.size() << "\r\n"
      << "Connection: close\r\n"
      << "\r\n"
      << body;
    return r.str();
}
