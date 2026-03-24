// side_panel.cpp
#include "side_panel.h"
#include "port_config.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFrame>
#include <QLabel>
#include <QFont>
#include <QColor>
#include <QLocale>

static QString formatBytes(uint64_t b) {
    if (b < 1024)             return QString("%1 B").arg(b);
    if (b < 1024 * 1024)     return QString("%1 KB").arg(b / 1024.0, 0, 'f', 1);
    if (b < 1024*1024*1024)  return QString("%1 MB").arg(b / (1024.0*1024), 0, 'f', 2);
    return QString("%1 GB").arg(b / (1024.0*1024*1024), 0, 'f', 2);
}

// ── Helper: a labelled value row ─────────────────────────────────────────────
static void addRow(QVBoxLayout* layout, const QString& caption, QLabel*& valueOut) {
    auto* row = new QWidget;
    auto* rl  = new QHBoxLayout(row);
    rl->setContentsMargins(0, 2, 0, 2);
    rl->setSpacing(6);

    auto* capLbl = new QLabel(caption + ":");
    capLbl->setStyleSheet("color:#5a7a9a; font-size:10px; font-weight:bold;");
    capLbl->setFixedWidth(72);
    capLbl->setAlignment(Qt::AlignRight | Qt::AlignVCenter);

    valueOut = new QLabel("—");
    valueOut->setStyleSheet("color:#c8deff; font-size:12px;");
    valueOut->setWordWrap(true);

    rl->addWidget(capLbl);
    rl->addWidget(valueOut, 1);
    layout->addWidget(row);
}

// ── Constructor ───────────────────────────────────────────────────────────────
SidePanel::SidePanel(QWidget* parent) : QWidget(parent) {
    buildUi();
}

void SidePanel::buildUi() {
    setMinimumWidth(220);
    setMaximumWidth(260);
    setStyleSheet(R"(
        SidePanel {
            background: #0e0e18;
            border-left: 1px solid #2a2a4a;
        }
    )");

    auto* outer = new QVBoxLayout(this);
    outer->setContentsMargins(10, 12, 10, 12);
    outer->setSpacing(8);

    // Header
    auto* header = new QLabel("● Node Inspector");
    header->setStyleSheet(
        "color:#7eb8f7; font-size:13px; font-weight:bold; "
        "border-bottom:1px solid #2a2a4a; padding-bottom:6px;");
    outer->addWidget(header);

    // Card
    card_ = new QFrame;
    card_->setObjectName("nodeCard");
    card_->setStyleSheet(R"(
        #nodeCard {
            background: #14141f;
            border: 1px solid #2a2a4a;
            border-radius: 8px;
        }
    )");
    auto* cardLayout = new QVBoxLayout(card_);
    cardLayout->setContentsMargins(10, 10, 10, 10);
    cardLayout->setSpacing(2);

    // IP (large)
    ipLbl_ = new QLabel("—");
    ipLbl_->setStyleSheet(
        "color:#7eb8f7; font-size:15px; font-weight:bold; "
        "font-family:'Cascadia Code','Consolas',monospace;");
    ipLbl_->setAlignment(Qt::AlignCenter);
    cardLayout->addWidget(ipLbl_);

    // State badge
    stateLbl_ = new QLabel("—");
    stateLbl_->setAlignment(Qt::AlignCenter);
    stateLbl_->setStyleSheet(
        "background:#1e2a3a; color:#88b0d8; border-radius:4px; "
        "font-size:10px; padding:2px 6px;");
    cardLayout->addWidget(stateLbl_);
    cardLayout->addSpacing(8);

    addRow(cardLayout, "Port",    portLbl_);
    addRow(cardLayout, "Service", portCatLbl_);
    addRow(cardLayout, "Process", processLbl_);
    addRow(cardLayout, "Bytes",   bytesLbl_);
    addRow(cardLayout, "Packets", packetsLbl_);

    outer->addWidget(card_);

    // Placeholder shown when nothing selected
    placeholderLbl_ = new QLabel("Click a node\nin the graph\nto inspect it.");
    placeholderLbl_->setAlignment(Qt::AlignCenter);
    placeholderLbl_->setStyleSheet("color:#3a4a6a; font-size:11px; padding:20px;");
    outer->addWidget(placeholderLbl_);

    outer->addStretch();

    // Legend
    auto* legendTitle = new QLabel("Port Legend");
    legendTitle->setStyleSheet("color:#4a6a8a; font-size:10px; font-weight:bold;");
    outer->addWidget(legendTitle);

    struct LegEntry { QString col; QString text; };
    for (auto [col, text] : QVector<LegEntry>{
            {"#3affb0", "Secure (HTTPS/SSH)"},
            {"#ff3a3a", "Danger (HTTP/Telnet)"},
            {"#ffb03a", "Caution (DNS/DB)"},
            {"#ffe033", "Unknown Port"} })
    {
        auto* row = new QWidget;
        auto* rl  = new QHBoxLayout(row);
        rl->setContentsMargins(0, 1, 0, 1);
        rl->setSpacing(6);

        auto* dot = new QLabel("●");
        dot->setStyleSheet(QString("color:%1; font-size:14px;").arg(col));
        dot->setFixedWidth(16);

        auto* txt = new QLabel(text);
        txt->setStyleSheet("color:#6080a0; font-size:10px;");

        rl->addWidget(dot);
        rl->addWidget(txt, 1);
        outer->addWidget(row);
    }

    card_->setVisible(false);
}

// ── Public API ────────────────────────────────────────────────────────────────
void SidePanel::showNode(const QString& ip,
                          uint64_t bytes, uint64_t packets,
                          const QString& process, uint16_t port,
                          const QString& state)
{
    card_->setVisible(true);
    placeholderLbl_->setVisible(false);

    ipLbl_->setText(ip);

    // State badge colour
    QString stateCol = "#88b0d8";
    if (state == "EST")    stateCol = "#3affb0";
    if (state == "CLOSED") stateCol = "#ff3a3a";
    if (state == "NEW")    stateCol = "#ffb03a";
    stateLbl_->setText(state);
    stateLbl_->setStyleSheet(
        QString("background:#1e2a3a; color:%1; border-radius:4px; "
                "font-size:10px; padding:2px 6px;").arg(stateCol));

    portLbl_->setText(QString::number(port));

    PortRule rule = PortConfig::instance().classify(port);
    QColor catCol = PortConfig::colorFor(rule.category);
    portCatLbl_->setText(rule.label.isEmpty() ? "—" : rule.label);
    portCatLbl_->setStyleSheet(
        QString("color:%1; font-size:12px;").arg(catCol.name()));

    processLbl_->setText(process.isEmpty() ? "(unknown)" : process);
    bytesLbl_->setText(formatBytes(bytes));
    packetsLbl_->setText(QLocale().toString(static_cast<qlonglong>(packets)));
}

void SidePanel::clear() {
    card_->setVisible(false);
    placeholderLbl_->setVisible(true);
}
