#pragma once
// sniffer_backend.h  (updated — adds embedded HTTP API)

#include <QObject>
#include <QString>
#include <memory>
#include <thread>
#include <atomic>

#include "flow_manager.h"
#include "http_api.h"

class TcpParser;

class SnifferBackend : public QObject {
    Q_OBJECT

public:
    explicit SnifferBackend(QObject* parent = nullptr);
    ~SnifferBackend() override;

    bool start();
    void stop();

    std::vector<FlowSnapshot> snapshot() const { return manager_.get_snapshot(); }

    uint64_t totalPackets() const { return const_cast<FlowManager&>(manager_).total_packets(); }
    uint64_t totalBytes()   const { return const_cast<FlowManager&>(manager_).total_bytes();   }

    // Port the HTTP API is listening on (0 if not started yet)
    uint16_t apiPort() const { return httpApi_ ? httpApi_->port() : 0; }

signals:
    void newConnectionFound(QString srcIp, QString dstIp,
                            quint16 srcPort, quint16 dstPort,
                            QString protocol, QString process);
    void errorOccurred(QString message);

private:
    void snifferThread();
    void workerThread();

    mutable FlowManager manager_;

    void*              pcap_handle_  = nullptr;

    struct RawPacket;
    struct PacketQueue;
    std::unique_ptr<PacketQueue> queue_;

    std::thread sniffer_thread_;
    std::thread worker_thread_;
    std::atomic<bool> running_{ false };

    // Embedded HTTP REST API
    std::unique_ptr<HttpApi> httpApi_;
    static constexpr uint16_t HTTP_API_PORT = 8765;
};
