#pragma once
#ifndef NETWORK_GRAPH_WIDGET_H
#define NETWORK_GRAPH_WIDGET_H

// network_graph_widget.h — v2
//
// Force-directed graph using a proper spring-embedder:
//
//  Repulsion:  Coulomb  F = Kr / d²        (all node pairs)
//  Attraction: Hooke    F = Ks * (d - L0)  (connected pairs only)
//  Centering:  Weak     F = Kc * dist_from_origin  (prevents drift)
//  Damping:    0.80× per tick
//
// Nodes are QGraphicsItems; the scene's advance() drives physics.
// Edges are QGraphicsLineItems redrawn every tick.

#include <QGraphicsView>
#include <QGraphicsScene>
#include <QMap>
#include <QTimer>
#include <QString>
#include <cstdint>
#include "flow_manager.h"

class GraphNode;
class QGraphicsLineItem;

struct GraphEdge {
    GraphNode*         remote = nullptr;
    QGraphicsLineItem* line   = nullptr;
};

class NetworkGraphWidget : public QGraphicsView {
    Q_OBJECT

public:
    explicit NetworkGraphWidget(QWidget* parent = nullptr);

    void updateFromSnapshot(const std::vector<FlowSnapshot>& snap);

signals:
    void nodeSelected(QString ip, uint64_t bytes, uint64_t packets,
                      QString process, quint16 port, QString state);

protected:
    void mousePressEvent(QMouseEvent*)  override;
    void wheelEvent(QWheelEvent*)       override;
    void resizeEvent(QResizeEvent*)     override;

private slots:
    void physicsStep();

private:
    GraphNode* spawnNode(const QString& ip);
    void       syncEdge(GraphEdge& edge);
    QPointF    randomOrbitPos() const;

    QGraphicsScene* scene_  = nullptr;
    GraphNode*      master_ = nullptr;
    QMap<QString, GraphEdge> edges_;
    QTimer* physTimer_ = nullptr;

    // Scene logical bounds
    static constexpr qreal W = 1400.0;
    static constexpr qreal H =  900.0;

    // Physics tuning
    static constexpr double Kr = 12000.0;  // repulsion strength
    static constexpr double Ks = 0.035;    // spring constant
    static constexpr double L0 = 240.0;    // spring rest length
    static constexpr double Kc = 0.004;    // centering pull
    static constexpr double DAMP = 0.78;   // velocity damping per tick
    static constexpr double MAX_F = 18.0;  // force clamp (pixels/tick²)
};

#endif // NETWORK_GRAPH_WIDGET_H
