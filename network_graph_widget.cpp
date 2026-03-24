// network_graph_widget.cpp — v2
#include "network_graph_widget.h"
#include "graph_node.h"
#include "port_config.h"

#include <QGraphicsScene>
#include <QGraphicsLineItem>
#include <QMouseEvent>
#include <QWheelEvent>
#include <QResizeEvent>
#include <QTimer>
#include <QPen>
#include <QColor>
#include <QRandomGenerator>
#include <QApplication>
#include <QVector>
#include <QtMath>
#include <cmath>

// ── Constructor ───────────────────────────────────────────────────────────────
NetworkGraphWidget::NetworkGraphWidget(QWidget* parent)
    : QGraphicsView(parent)
{
    scene_ = new QGraphicsScene(this);
    scene_->setSceneRect(-W/2, -H/2, W, H);
    setScene(scene_);

    setRenderHints(QPainter::Antialiasing | QPainter::TextAntialiasing |
                   QPainter::SmoothPixmapTransform);
    setDragMode(QGraphicsView::ScrollHandDrag);
    setTransformationAnchor(AnchorUnderMouse);
    setResizeAnchor(AnchorViewCenter);
    setBackgroundBrush(QColor(10, 12, 20));
    setFrameShape(QFrame::NoFrame);
    setOptimizationFlag(DontAdjustForAntialiasing, false);

    // ── Decorative background: radar rings + crosshairs ───────────────────────
    QPen ringPen(QColor(255, 255, 255, 10), 0.8, Qt::SolidLine);
    for (int r = 100; r <= 560; r += 100) {
        auto* ring = scene_->addEllipse(-r, -r, 2*r, 2*r, ringPen, Qt::NoBrush);
        ring->setZValue(-10);
    }
    // Tick marks on outermost ring
    QPen tickPen(QColor(255,255,255,20), 1.0);
    for (int deg = 0; deg < 360; deg += 30) {
        double a = deg * M_PI / 180.0;
        double r1 = 555, r2 = 565;
        scene_->addLine(r1*cos(a), r1*sin(a), r2*cos(a), r2*sin(a), tickPen)->setZValue(-10);
    }

    // Crosshairs
    QPen crossPen(QColor(255, 255, 255, 6), 0.6, Qt::DashLine);
    scene_->addLine(-W/2, 0, W/2, 0, crossPen)->setZValue(-10);
    scene_->addLine(0, -H/2, 0, H/2, crossPen)->setZValue(-10);

    // ── Master node ───────────────────────────────────────────────────────────
    master_ = new GraphNode(GraphNode::Master);
    master_->setPos(0, 0);
    scene_->addItem(master_);

    // ── Physics at 25 fps ─────────────────────────────────────────────────────
    physTimer_ = new QTimer(this);
    connect(physTimer_, &QTimer::timeout, this, &NetworkGraphWidget::physicsStep);
    physTimer_->start(40);
}

// ── Snapshot update ───────────────────────────────────────────────────────────
void NetworkGraphWidget::updateFromSnapshot(const std::vector<FlowSnapshot>& snap) {
    // Aggregate by dst_ip — keep dominant port (highest bytes)
    struct AggRow {
        uint64_t packets = 0, bytes = 0, portBytes = 0;
        QString  process, state;
        uint16_t port = 0;
    };

    QMap<QString, AggRow> agg;
    for (const auto& s : snap) {
        QString dip = QString::fromStdString(s.dst_ip);
        auto& a     = agg[dip];
        a.packets  += s.packets;
        a.bytes    += s.bytes;
        if (s.bytes > a.portBytes) {
            a.portBytes = s.bytes;
            a.port      = s.dst_port;
            a.process   = QString::fromStdString(s.process);
            a.state     = QString::fromStdString(s.state);
        }
    }

    // Add new nodes / update existing
    for (auto it = agg.begin(); it != agg.end(); ++it) {
        const QString& dip = it.key();
        const AggRow&  row = it.value();

        if (!edges_.contains(dip)) {
            GraphNode* node = spawnNode(dip);
            QGraphicsLineItem* line = scene_->addLine(0, 0, node->pos().x(), node->pos().y());
            line->setZValue(1);
            edges_[dip] = { node, line };
        }

        GraphEdge& edge = edges_[dip];
        edge.remote->setFlowData(row.packets, row.bytes, row.process, row.port, row.state);
        syncEdge(edge);
    }

    // Mark flows that vanished as CLOSED
    for (auto it = edges_.begin(); it != edges_.end(); ++it) {
        if (!agg.contains(it.key())) {
            GraphEdge& edge = it.value();
            edge.remote->setFlowData(
                edge.remote->packets(), edge.remote->bytes(),
                edge.remote->process(), edge.remote->dstPort(), "CLOSED");
            syncEdge(edge);
        }
    }
}

// ── Spawn ─────────────────────────────────────────────────────────────────────
GraphNode* NetworkGraphWidget::spawnNode(const QString& ip) {
    auto* node = new GraphNode(GraphNode::Remote, ip);
    node->setPos(randomOrbitPos());
    // Give it a small random kick so nodes immediately start separating
    node->vel_ = QPointF(
        (QRandomGenerator::global()->bounded(20) - 10),
        (QRandomGenerator::global()->bounded(20) - 10));
    scene_->addItem(node);
    return node;
}

QPointF NetworkGraphWidget::randomOrbitPos() const {
    auto* rng  = QRandomGenerator::global();
    double ang = rng->bounded(360) * M_PI / 180.0;
    double r   = 200.0 + rng->bounded(120);
    return QPointF(r * std::cos(ang), r * std::sin(ang));
}

// ── Edge sync ─────────────────────────────────────────────────────────────────
void NetworkGraphWidget::syncEdge(GraphEdge& edge) {
    if (!edge.remote || !edge.line) return;

    QPointF rp = edge.remote->pos();
    edge.line->setLine(0, 0, rp.x(), rp.y());

    QColor col = edge.remote->edgeColor();
    float  w   = edge.remote->edgeWidth();

    bool closed = (edge.remote->state() == "CLOSED");
    col.setAlpha(closed ? 45 : 160);

    Qt::PenStyle style = closed ? Qt::DashLine : Qt::SolidLine;
    edge.line->setPen(QPen(col, w, style, Qt::RoundCap));
}

// ── Force-directed physics ────────────────────────────────────────────────────
//
// Per tick, for every non-pinned remote node n:
//
//  Force = Σ repulsion(n, all others)        [push apart]
//        + spring(n, master)                 [pull toward center]
//        + centering(n)                      [weak drift correction]
//
// velocity += force; velocity *= DAMP; position += velocity
//
// All forces clamped to MAX_F to prevent explosion on first frame.

void NetworkGraphWidget::physicsStep() {
    // Gather all remote nodes
    QVector<GraphNode*> nodes;
    nodes.reserve(edges_.size());
    for (auto it = edges_.begin(); it != edges_.end(); ++it) {
        GraphNode* n = it.value().remote;
        if (n) nodes.append(n);
    }

    const QPointF origin(0, 0);

    for (GraphNode* n : nodes) {
        if (n->pinned_) continue;

        QPointF pos  = n->pos();
        QPointF force(0, 0);

        // ── Repulsion: every node repels every other node ─────────────────────
        // Including master (origin)
        auto applyRepulsion = [&](QPointF other) {
            QPointF d    = pos - other;
            double dist2 = d.x()*d.x() + d.y()*d.y();
            if (dist2 < 1.0) { d = QPointF(1,1); dist2 = 2.0; }
            double dist  = std::sqrt(dist2);
            double f     = Kr / dist2;
            force += QPointF(d.x()/dist * f, d.y()/dist * f);
        };

        applyRepulsion(origin);  // repel from master
        for (GraphNode* other : nodes) {
            if (other == n) continue;
            applyRepulsion(other->pos());
        }

        // ── Spring: attraction toward master ──────────────────────────────────
        {
            QPointF d    = origin - pos;
            double  dist = std::sqrt(d.x()*d.x() + d.y()*d.y());
            if (dist > 0.5) {
                double stretch = dist - L0;           // positive → too far
                double f       = Ks * stretch;
                force += QPointF(d.x()/dist * f, d.y()/dist * f);
            }
        }

        // ── Centering: weak pull toward scene centre (prevents runaway drift) ─
        {
            force += QPointF(-Kc * pos.x(), -Kc * pos.y());
        }

        // ── Clamp force ───────────────────────────────────────────────────────
        double fmag = std::sqrt(force.x()*force.x() + force.y()*force.y());
        if (fmag > MAX_F)
            force *= MAX_F / fmag;

        n->vel_ += force;
        n->vel_ *= DAMP;
    }

    // Integrate positions
    scene_->advance();

    // Redraw edges
    for (auto it = edges_.begin(); it != edges_.end(); ++it) {
        syncEdge(it.value());
    }

    scene_->update();
}

// ── Mouse: click on node → emit signal + forward to item for pinning ──────────
void NetworkGraphWidget::mousePressEvent(QMouseEvent* event) {
    if (event->button() == Qt::LeftButton) {
        QPointF sp   = mapToScene(event->pos());
        auto*   item = scene_->itemAt(sp, transform());
        if (auto* node = dynamic_cast<GraphNode*>(item)) {
            if (!node->isMaster()) {
                emit nodeSelected(
                    node->ip(), node->bytes(), node->packets(),
                    node->process(), node->dstPort(), node->state());
            }
        }
    }
    QGraphicsView::mousePressEvent(event);
}

void NetworkGraphWidget::wheelEvent(QWheelEvent* event) {
    if (event->modifiers() & Qt::ControlModifier) {
        double f = event->angleDelta().y() > 0 ? 1.13 : (1.0/1.13);
        scale(f, f);
        event->accept();
    } else {
        QGraphicsView::wheelEvent(event);
    }
}

void NetworkGraphWidget::resizeEvent(QResizeEvent* e) {
    QGraphicsView::resizeEvent(e);
    fitInView(scene_->sceneRect(), Qt::KeepAspectRatio);
}
