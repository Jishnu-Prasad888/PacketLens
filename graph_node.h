#pragma once
#ifndef GRAPH_NODE_H
#define GRAPH_NODE_H

// graph_node.h — v2
//
// Each node:
//  • Draws itself as a glowing circle whose radius grows with traffic
//  • On hover OR when pinned (clicked), draws a floating info card above
//    the node showing IP, process, bytes, port, state
//  • Physics: velocity QPointF; advance() integrates + damps each frame

#include <QGraphicsItem>
#include <QString>
#include <QColor>
#include <cstdint>

class GraphNode : public QGraphicsItem {
public:
    enum NodeType { Master, Remote };

    explicit GraphNode(NodeType type, const QString& ip = {},
                       QGraphicsItem* parent = nullptr);

    // ── Identity ──────────────────────────────────────────────────────────────
    const QString& ip()       const { return ip_; }
    bool           isMaster() const { return type_ == Master; }

    // ── Flow data (refreshed every second) ───────────────────────────────────
    void     setFlowData(uint64_t packets, uint64_t bytes,
                         const QString& process,
                         uint16_t dstPort,
                         const QString& state);

    uint64_t bytes()    const { return bytes_; }
    uint64_t packets()  const { return packets_; }
    QString  process()  const { return process_; }
    uint16_t dstPort()  const { return dstPort_; }
    QString  state()    const { return state_; }
    QColor   edgeColor()const { return edgeColor_; }
    float    edgeWidth()const { return edgeWidth_; }

    // ── Physics ───────────────────────────────────────────────────────────────
    QPointF vel_{ 0, 0 };
    bool    pinned_ = false;   // pinned nodes ignore physics (user-clicked)

    void advance(int phase) override;

    // ── QGraphicsItem ─────────────────────────────────────────────────────────
    QRectF boundingRect() const override;
    void   paint(QPainter*, const QStyleOptionGraphicsItem*, QWidget* = nullptr) override;

    void hoverEnterEvent(QGraphicsSceneHoverEvent*) override;
    void hoverLeaveEvent(QGraphicsSceneHoverEvent*) override;
    void mousePressEvent(QGraphicsSceneMouseEvent*) override;

    // Node circle radius (grows slightly with bytes)
    qreal radius() const;

    // Card size constants
    static constexpr qreal CARD_W = 194.0;
    static constexpr qreal CARD_H = 118.0;

private:
    void  drawInfoCard(QPainter* p) const;
    static QString fmtBytes(uint64_t b);
    static QString truncate(const QString& s, int maxLen);

    NodeType type_;
    QString  ip_;
    uint64_t packets_ = 0;
    uint64_t bytes_   = 0;
    QString  process_;
    uint16_t dstPort_ = 0;
    QString  state_;

    QColor   edgeColor_{ 0xff, 0xe0, 0x33 };
    float    edgeWidth_ = 1.5f;
    bool     hovered_   = false;
};

#endif // GRAPH_NODE_H
