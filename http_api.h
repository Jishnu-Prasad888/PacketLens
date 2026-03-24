#pragma once
#ifndef HTTP_API_H
#define HTTP_API_H

// http_api.h
//
// Tiny HTTP/JSON API server that runs inside PacketLens on a background thread.
// Exposes live flow data so external tools (MCP server, dashboards, scripts)
// can query it without touching libpcap or Qt internals.
//
// Default port: 8765  (configurable via constructor)
//
// Endpoints:
//   GET /flows       — JSON array of all current FlowSnapshot rows
//   GET /stats       — total packets, bytes, flow count
//   GET /health      — {"status":"ok"}
//
// No external dependencies — uses raw POSIX sockets + std::thread.
// This runs only on Linux (same platform as the rest of the project).

#include <string>
#include <thread>
#include <atomic>
#include <functional>
#include <vector>
#include "flow_manager.h"

class HttpApi {
public:
    // snapshotFn is called on each request to get the current flow data.
    // It must be thread-safe (FlowManager::get_snapshot() already is).
    using SnapshotFn = std::function<std::vector<FlowSnapshot>()>;
    using StatsFn    = std::function<void(uint64_t& pkts, uint64_t& bytes, size_t& flows)>;

    explicit HttpApi(uint16_t port, SnapshotFn snapFn, StatsFn statsFn);
    ~HttpApi();

    bool start();  // returns false on bind failure
    void stop();

    uint16_t port() const { return port_; }

private:
    void serverLoop();
    void handleClient(int clientFd);

    // Response builders
    std::string buildFlowsJson();
    std::string buildStatsJson();
    static std::string httpOk(const std::string& body,
                              const std::string& contentType = "application/json");
    static std::string httpNotFound();
    static std::string escapeJson(const std::string& s);

    uint16_t     port_;
    SnapshotFn   snapFn_;
    StatsFn      statsFn_;
    int          serverFd_ = -1;
    std::thread  thread_;
    std::atomic<bool> running_{ false };
};

#endif // HTTP_API_H
