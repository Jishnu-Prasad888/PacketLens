// connection_model.cpp
#include "connection_model.h"
#include <QColor>
#include <QFont>
#include <QBrush>

ConnectionModel::ConnectionModel(QObject* parent)
    : QAbstractTableModel(parent)
{}

int ConnectionModel::rowCount(const QModelIndex& parent) const {
    if (parent.isValid()) return 0;
    return static_cast<int>(rows_.size());
}

int ConnectionModel::columnCount(const QModelIndex& parent) const {
    if (parent.isValid()) return 0;
    return COL_COUNT;
}

QVariant ConnectionModel::headerData(int section, Qt::Orientation orientation,
                                     int role) const {
    if (orientation != Qt::Horizontal || role != Qt::DisplayRole)
        return {};

    switch (section) {
        case COL_SRC_IP:   return "Src IP";
        case COL_SRC_PORT: return "SPort";
        case COL_DST_IP:   return "Dst IP";
        case COL_DST_PORT: return "DPort";
        case COL_PROTO:    return "Proto";
        case COL_PACKETS:  return "Packets";
        case COL_BYTES:    return "Bytes";
        case COL_PROCESS:  return "Process";
        case COL_STATE:    return "State";
        default:           return {};
    }
}

QVariant ConnectionModel::data(const QModelIndex& index, int role) const {
    if (!index.isValid() || index.row() >= (int)rows_.size())
        return {};

    const FlowSnapshot& r = rows_[static_cast<size_t>(index.row())];

    // ── Background colour by state ─────────────────────────────────────────
    if (role == Qt::BackgroundRole) {
        if (r.state == "CLOSED")
            return QBrush(QColor(60, 20, 20));       // dark red tint
        if (r.state == "EST")
            return QBrush(QColor(20, 40, 60));        // dark blue-tint
        return QBrush(QColor(30, 30, 30));            // neutral
    }

    // ── Foreground colour by protocol ──────────────────────────────────────
    if (role == Qt::ForegroundRole) {
        if (r.protocol == "TCP") return QBrush(QColor(100, 200, 255));
        if (r.protocol == "UDP") return QBrush(QColor(255, 190, 80));
        return QBrush(Qt::white);
    }

    if (role == Qt::TextAlignmentRole) {
        if (index.column() == COL_SRC_PORT ||
            index.column() == COL_DST_PORT ||
            index.column() == COL_PACKETS  ||
            index.column() == COL_BYTES)
            return int(Qt::AlignRight | Qt::AlignVCenter);
        return int(Qt::AlignLeft | Qt::AlignVCenter);
    }

    if (role != Qt::DisplayRole) return {};

    switch (index.column()) {
        case COL_SRC_IP:   return QString::fromStdString(r.src_ip);
        case COL_SRC_PORT: return static_cast<int>(r.src_port);
        case COL_DST_IP:   return QString::fromStdString(r.dst_ip);
        case COL_DST_PORT: return static_cast<int>(r.dst_port);
        case COL_PROTO:    return QString::fromStdString(r.protocol);
        case COL_PACKETS:  return static_cast<qlonglong>(r.packets);
        case COL_BYTES:    return static_cast<qlonglong>(r.bytes);
        case COL_PROCESS:  return QString::fromStdString(r.process);
        case COL_STATE:    return QString::fromStdString(r.state);
        default:           return {};
    }
}

// ── Batch refresh — O(n), single beginResetModel/endResetModel ───────────────
void ConnectionModel::refresh(std::vector<FlowSnapshot> snapshot) {
    beginResetModel();
    rows_ = std::move(snapshot);
    endResetModel();
}
