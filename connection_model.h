#pragma once
// connection_model.h
//
// QAbstractTableModel that wraps a vector<FlowSnapshot>.
// The GUI calls refresh(snapshot) every ~1 s; the model rebuilds the
// display in one shot so the view never half-updates.

#include <QAbstractTableModel>
#include <QVariant>
#include <vector>
#include "flow_manager.h"

class ConnectionModel : public QAbstractTableModel {
    Q_OBJECT

public:
    explicit ConnectionModel(QObject* parent = nullptr);

    // ── QAbstractTableModel interface ─────────────────────────────────────────
    int rowCount   (const QModelIndex& parent = {}) const override;
    int columnCount(const QModelIndex& parent = {}) const override;
    QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;
    QVariant headerData(int section, Qt::Orientation orientation,
                        int role = Qt::DisplayRole) const override;

    // Called by the QTimer slot — O(n) rebuild, model notifies view.
    void refresh(std::vector<FlowSnapshot> snapshot);

private:
    std::vector<FlowSnapshot> rows_;

    static constexpr int COL_SRC_IP   = 0;
    static constexpr int COL_SRC_PORT = 1;
    static constexpr int COL_DST_IP   = 2;
    static constexpr int COL_DST_PORT = 3;
    static constexpr int COL_PROTO    = 4;
    static constexpr int COL_PACKETS  = 5;
    static constexpr int COL_BYTES    = 6;
    static constexpr int COL_PROCESS  = 7;
    static constexpr int COL_STATE    = 8;
    static constexpr int COL_COUNT    = 9;
};
