#pragma once
// side_panel.h
//
// Slide-in panel on the right of MainWindow.
// Populated when the user clicks a node in the graph.

#ifndef SIDE_PANEL_H
#define SIDE_PANEL_H

#include <QWidget>
#include <QLabel>
#include <QString>
#include <cstdint>

class QFrame;
class QProgressBar;

class SidePanel : public QWidget {
    Q_OBJECT

public:
    explicit SidePanel(QWidget* parent = nullptr);

    // Populate with node details
    void showNode(const QString& ip,
                  uint64_t bytes, uint64_t packets,
                  const QString& process, uint16_t port,
                  const QString& state);

    // Clear back to placeholder
    void clear();

private:
    void buildUi();

    QFrame*  card_        = nullptr;

    QLabel*  ipLbl_       = nullptr;
    QLabel*  stateLbl_    = nullptr;
    QLabel*  portLbl_     = nullptr;
    QLabel*  processLbl_  = nullptr;
    QLabel*  bytesLbl_    = nullptr;
    QLabel*  packetsLbl_  = nullptr;
    QLabel*  portCatLbl_  = nullptr;
    QLabel*  placeholderLbl_ = nullptr;
};

#endif // SIDE_PANEL_H
