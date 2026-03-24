// port_config.cpp
#include "port_config.h"

#include <QFile>
#include <QTextStream>
#include <QStringList>

// ── Constructor ───────────────────────────────────────────────────────────────
PortConfig::PortConfig() {
    loadDefaults();
}

// ── Built-in defaults (used when ports.txt is absent) ────────────────────────
void PortConfig::loadDefaults() {
    rules_.clear();
    // danger
    for (uint16_t p : {80, 8080, 8000, 21, 23, 25, 110, 143})
        rules_[p] = { p == 80 ? "HTTP" : p == 21 ? "FTP" : p == 23 ? "Telnet" : "Mail/HTTP-Alt", PortCategory::Danger };

    // secure
    for (uint16_t p : {443, 8443, 22, 993, 995, 465, 587})
        rules_[p] = { p == 443 ? "HTTPS" : p == 22 ? "SSH" : "Secure-Mail", PortCategory::Secure };

    // caution
    for (uint16_t p : {53, 123, 67, 68, 137, 138, 139, 445, 3306, 5432, 27017})
        rules_[p] = { p == 53 ? "DNS" : p == 3306 ? "MySQL" : p == 5432 ? "Postgres" : "System/DB", PortCategory::Caution };
}

// ── File loader ───────────────────────────────────────────────────────────────
void PortConfig::reload(const QString& path) {
    loadDefaults(); // reset to defaults first

    QFile f(path);
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text)) {
        // ports.txt missing — silently use defaults
        return;
    }

    QTextStream ts(&f);
    while (!ts.atEnd()) {
        QString line = ts.readLine().trimmed();
        if (line.isEmpty() || line.startsWith('#'))
            continue;

        // Tokens: port  label  category
        QStringList parts = line.split(' ', Qt::SkipEmptyParts);
        if (parts.size() < 3) continue;

        bool ok = false;
        uint16_t port = static_cast<uint16_t>(parts[0].toUShort(&ok));
        if (!ok) continue;

        QString label    = parts[1];
        QString catStr   = parts[2].toLower();

        PortCategory cat = PortCategory::Unknown;
        if      (catStr == "danger")  cat = PortCategory::Danger;
        else if (catStr == "secure")  cat = PortCategory::Secure;
        else if (catStr == "caution") cat = PortCategory::Caution;

        rules_[port] = { label, cat };
    }
}

// ── Classify ─────────────────────────────────────────────────────────────────
PortRule PortConfig::classify(uint16_t port) const {
    auto it = rules_.find(port);
    if (it != rules_.end()) return it.value();
    return { "Unknown", PortCategory::Unknown };
}

// ── Color mapping ─────────────────────────────────────────────────────────────
QColor PortConfig::colorFor(PortCategory cat) {
    switch (cat) {
        case PortCategory::Secure:  return QColor(0x3a, 0xff, 0xb0); // teal-green
        case PortCategory::Danger:  return QColor(0xff, 0x3a, 0x3a); // red
        case PortCategory::Caution: return QColor(0xff, 0xb0, 0x3a); // amber
        case PortCategory::Unknown: return QColor(0xff, 0xe0, 0x33); // yellow
    }
    return QColor(0xff, 0xe0, 0x33);
}