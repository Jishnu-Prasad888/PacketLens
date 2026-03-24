// graph_node.cpp — v2
#include "graph_node.h"
#include "port_config.h"

#include <QPainter>
#include <QPainterPath>
#include <QGraphicsSceneHoverEvent>
#include <QGraphicsSceneMouseEvent>
#include <QStyleOptionGraphicsItem>
#include <QFont>
#include <QFontMetricsF>
#include <QtMath>
#include <cmath>

// ── Helpers ───────────────────────────────────────────────────────────────────
QString GraphNode::fmtBytes(uint64_t b) {
    if (b < 1024)            return QString("%1 B").arg(b);
    if (b < 1024*1024)       return QString("%1 KB").arg(b/1024.0, 0,'f',1);
    if (b < 1024*1024*1024)  return QString("%1 MB").arg(b/(1024.0*1024),0,'f',2);
    return                          QString("%1 GB").arg(b/(1024.0*1024*1024),0,'f',2);
}

QString GraphNode::truncate(const QString& s, int maxLen) {
    if (s.length() <= maxLen) return s;
    return s.left(maxLen - 1) + "…";
}

// ── Constructor ───────────────────────────────────────────────────────────────
GraphNode::GraphNode(NodeType type, const QString& ip, QGraphicsItem* parent)
    : QGraphicsItem(parent), type_(type), ip_(ip)
{
    setFlag(ItemSendsScenePositionChanges, true);
    setFlag(ItemIsSelectable, true);
    setAcceptHoverEvents(true);
    setZValue(3);
}

// ── Radius ────────────────────────────────────────────────────────────────────
qreal GraphNode::radius() const {
    if (type_ == Master) return 26.0;
    // Scale: base 16, grows up to 28 with traffic (log10 of bytes)
    if (bytes_ == 0) return 16.0;
    double scale = std::log10(static_cast<double>(bytes_) + 1.0) * 1.8;
    return qBound(16.0, 16.0 + scale, 28.0);
}

// ── Flow data ─────────────────────────────────────────────────────────────────
void GraphNode::setFlowData(uint64_t packets, uint64_t bytes,
                             const QString& process, uint16_t dstPort,
                             const QString& state) {
    bool changed = (bytes_ != bytes || dstPort_ != dstPort || state_ != state);
    packets_ = packets;
    bytes_   = bytes;
    process_ = process;
    dstPort_ = dstPort;
    state_   = state;

    edgeColor_ = PortConfig::instance().colorForPort(dstPort);

    float w = 1.0f;
    if (bytes_ > 0)
        w = 1.0f + std::min(8.0f,
            static_cast<float>(std::log10(static_cast<double>(bytes_) + 1.0)));
    edgeWidth_ = w;

    if (changed) update();
}

// ── Physics ───────────────────────────────────────────────────────────────────
void GraphNode::advance(int phase) {
    if (phase == 0) return;
    if (type_ == Master || pinned_) return;

    QPointF newPos = pos() + vel_;
    vel_ *= 0.82;  // damping

    // Hard boundary — keep nodes inside a comfortable orbit
    newPos.setX(qBound(-620.0, newPos.x(), 620.0));
    newPos.setY(qBound(-400.0, newPos.y(), 400.0));

    setPos(newPos);
}

// ── Bounding rect — must include the card when shown ─────────────────────────
QRectF GraphNode::boundingRect() const {
    qreal r = radius() + 8.0;  // +8 for glow rings
    QRectF base(-r, -r, 2*r, 2*r);

    if (hovered_ || pinned_) {
        // Card sits above the node: x offset so it's centered, y is above
        qreal cardX = -CARD_W / 2.0;
        qreal cardY = -(r + 10.0 + CARD_H);
        QRectF cardRect(cardX, cardY, CARD_W, CARD_H);
        return base.united(cardRect);
    }
    return base;
}

// ── Paint ─────────────────────────────────────────────────────────────────────
void GraphNode::paint(QPainter* p,
                      const QStyleOptionGraphicsItem*,
                      QWidget*)
{
    p->setRenderHint(QPainter::Antialiasing, true);
    p->setRenderHint(QPainter::TextAntialiasing, true);

    qreal r = radius();
    bool showCard = hovered_ || pinned_;

    // ── 1. Glow rings ─────────────────────────────────────────────────────────
    QColor glowBase = (type_ == Master) ? QColor(0x7e, 0xb8, 0xf7) : edgeColor_;
    for (int i = 3; i >= 1; --i) {
        QColor gc = glowBase;
        gc.setAlpha(showCard ? 90 / i : 45 / i);
        p->setPen(Qt::NoPen);
        p->setBrush(gc);
        p->drawEllipse(QPointF(0,0), r + i*6, r + i*6);
    }

    // ── 2. Node body ──────────────────────────────────────────────────────────
    QRadialGradient grad(QPointF(-r*0.28, -r*0.28), r * 1.6);
    if (type_ == Master) {
        grad.setColorAt(0.0, QColor(0xc0, 0xdf, 0xff));
        grad.setColorAt(0.6, QColor(0x30, 0x70, 0xc0));
        grad.setColorAt(1.0, QColor(0x10, 0x28, 0x60));
    } else {
        QColor base = edgeColor_;
        grad.setColorAt(0.0, base.lighter(200));
        grad.setColorAt(0.5, base);
        grad.setColorAt(1.0, base.darker(220));
    }

    QPen borderPen(showCard ? Qt::white : QColor(255,255,255,80),
                   showCard ? 1.8 : 1.0);
    p->setPen(borderPen);
    p->setBrush(grad);
    p->drawEllipse(QPointF(0,0), r, r);

    // ── 3. Label inside node ──────────────────────────────────────────────────
    p->setPen(QColor(230, 240, 255, 220));
    QFont labelFont("Courier New", type_ == Master ? 8 : 7);
    labelFont.setBold(true);
    p->setFont(labelFont);

    QString lbl;
    if (type_ == Master) {
        lbl = "LOCAL";
    } else {
        // Show last two octets of IP to fit in circle
        QStringList parts = ip_.split('.');
        lbl = parts.size() == 4
            ? parts[2] + ".\n" + parts[3]
            : ip_;
    }
    p->drawText(QRectF(-r, -r, 2*r, 2*r), Qt::AlignCenter, lbl);

    // ── 4. Floating info card ─────────────────────────────────────────────────
    if (showCard && type_ != Master) {
        drawInfoCard(p);
    }

    // ── 5. Pin indicator ──────────────────────────────────────────────────────
    if (pinned_) {
        p->setPen(QPen(QColor(0xff, 0xe0, 0x33), 2));
        p->setBrush(Qt::NoBrush);
        p->drawEllipse(QPointF(0,0), r + 4, r + 4);
    }
}

// ── Info card drawn above the node ───────────────────────────────────────────
void GraphNode::drawInfoCard(QPainter* p) const {
    qreal r = radius();
    qreal gap = 12.0;          // gap between top of node and bottom of card
    qreal cardX = -CARD_W / 2.0;
    qreal cardY = -(r + gap + CARD_H);

    // ── Card shadow ───────────────────────────────────────────────────────────
    for (int i = 4; i >= 1; --i) {
        QColor shadow(0, 0, 0, 35 * i);
        p->setPen(Qt::NoPen);
        p->setBrush(shadow);
        QPainterPath sh;
        sh.addRoundedRect(cardX + i, cardY + i, CARD_W, CARD_H, 8, 8);
        p->drawPath(sh);
    }

    // ── Card background ───────────────────────────────────────────────────────
    QPainterPath cardPath;
    cardPath.addRoundedRect(cardX, cardY, CARD_W, CARD_H, 8, 8);

    // Dark glass fill
    QLinearGradient cardGrad(cardX, cardY, cardX, cardY + CARD_H);
    cardGrad.setColorAt(0.0, QColor(18, 24, 40, 230));
    cardGrad.setColorAt(1.0, QColor(10, 14, 26, 245));
    p->fillPath(cardPath, cardGrad);

    // Border — coloured by port category
    p->setPen(QPen(edgeColor_.darker(110), 1.2));
    p->setBrush(Qt::NoBrush);
    p->drawPath(cardPath);

    // Accent top bar
    QPainterPath topBar;
    topBar.addRoundedRect(cardX, cardY, CARD_W, 22, 8, 8);
    // Clip the bottom corners of topBar to square them
    QPainterPath topBarClip;
    topBarClip.addRect(cardX, cardY + 11, CARD_W, 11);
    topBar = topBar.united(topBarClip);

    QLinearGradient barGrad(cardX, cardY, cardX + CARD_W, cardY);
    barGrad.setColorAt(0.0, edgeColor_.darker(130));
    barGrad.setColorAt(1.0, edgeColor_.darker(180));
    p->fillPath(topBar, barGrad);

    // ── Connector stem from card to node ──────────────────────────────────────
    p->setPen(QPen(edgeColor_, 1.5, Qt::DotLine));
    p->drawLine(QPointF(0, -(r + 2)),
                QPointF(0, cardY + CARD_H));

    // ── Text content ─────────────────────────────────────────────────────────
    // Title: full IP
    p->setPen(QColor(220, 235, 255));
    QFont titleFont("Courier New", 9);
    titleFont.setBold(true);
    p->setFont(titleFont);
    p->drawText(QRectF(cardX + 8, cardY + 3, CARD_W - 16, 18),
                Qt::AlignVCenter | Qt::AlignLeft, ip_);

    // Port category badge (top right of header)
    PortRule rule = PortConfig::instance().classify(dstPort_);
    QColor catCol = PortConfig::colorFor(rule.category);
    QString portLabel = rule.label.isEmpty() ? QString(":%1").arg(dstPort_) : rule.label;
    QFont badgeFont("Courier New", 7);
    badgeFont.setBold(true);
    p->setFont(badgeFont);
    QFontMetricsF bfm(badgeFont);
    qreal bw = bfm.horizontalAdvance(portLabel) + 10;
    qreal bx = cardX + CARD_W - bw - 6;
    QPainterPath badge;
    badge.addRoundedRect(bx, cardY + 4, bw, 14, 3, 3);
    p->fillPath(badge, catCol.darker(160));
    p->setPen(catCol);
    p->drawPath(badge);
    p->drawText(QRectF(bx, cardY + 4, bw, 14), Qt::AlignCenter, portLabel);

    // ── Rows: Process / Bytes / Port / State ─────────────────────────────────
    struct Row { QString label; QString value; QColor valColor; };

    // State colour
    QColor stateCol = QColor(0x88, 0xb0, 0xd8);
    if (state_ == "EST")    stateCol = QColor(0x3a, 0xff, 0xb0);
    if (state_ == "CLOSED") stateCol = QColor(0xff, 0x3a, 0x3a);
    if (state_ == "NEW")    stateCol = QColor(0xff, 0xb0, 0x3a);

    QVector<Row> rows = {
        { "Process", truncate(process_.isEmpty() ? "(unknown)" : process_, 20),
          QColor(0xc8, 0xde, 0xff) },
        { "Bytes",   fmtBytes(bytes_),     QColor(0xff, 0xd0, 0x60) },
        { "Port",    QString(":%1").arg(dstPort_), catCol },
        { "State",   state_,               stateCol },
    };

    QFont labelFont2("Courier New", 7);
    QFont valueFont("Courier New", 8);
    valueFont.setBold(true);

    qreal rowY = cardY + 26;
    qreal rowH = (CARD_H - 30) / rows.size();

    for (const auto& row : rows) {
        // Subtle row separator
        p->setPen(QColor(255, 255, 255, 12));
        p->drawLine(QPointF(cardX + 8, rowY), QPointF(cardX + CARD_W - 8, rowY));

        // Label
        p->setFont(labelFont2);
        p->setPen(QColor(0x5a, 0x7a, 0x9a));
        p->drawText(QRectF(cardX + 10, rowY + 2, 54, rowH - 4),
                    Qt::AlignVCenter | Qt::AlignLeft, row.label);

        // Value
        p->setFont(valueFont);
        p->setPen(row.valColor);
        p->drawText(QRectF(cardX + 66, rowY + 2, CARD_W - 76, rowH - 4),
                    Qt::AlignVCenter | Qt::AlignLeft, row.value);

        rowY += rowH;
    }
}

// ── Hover ─────────────────────────────────────────────────────────────────────
void GraphNode::hoverEnterEvent(QGraphicsSceneHoverEvent* e) {
    prepareGeometryChange();
    hovered_ = true;
    setZValue(10);  // float above all other nodes when hovered
    update();
    QGraphicsItem::hoverEnterEvent(e);
}

void GraphNode::hoverLeaveEvent(QGraphicsSceneHoverEvent* e) {
    prepareGeometryChange();
    hovered_ = false;
    setZValue(pinned_ ? 9 : 3);
    update();
    QGraphicsItem::hoverLeaveEvent(e);
}

// ── Click: toggle pin ─────────────────────────────────────────────────────────
void GraphNode::mousePressEvent(QGraphicsSceneMouseEvent* e) {
    if (type_ != Master) {
        prepareGeometryChange();
        pinned_ = !pinned_;
        setZValue(pinned_ ? 9 : 3);
        update();
    }
    QGraphicsItem::mousePressEvent(e);
}
