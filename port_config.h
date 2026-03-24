#pragma once
// port_config.h
//
// Loads a human-editable ports.txt from the working directory.
// Format (one rule per line, # is comment):
//
//   80    HTTP     danger
//   443   HTTPS    secure
//   22    SSH      secure
//   8080  HTTP-ALT caution
//
// Categories map to colours:
//   danger  → bright red   #ff3a3a
//   secure  → teal/green   #3affb0
//   caution → amber        #ffb03a
//   (anything else / not listed) → yellow #ffe033

#ifndef PORT_CONFIG_H
#define PORT_CONFIG_H

#include <QColor>
#include <QMap>
#include <QString>
#include <cstdint>

enum class PortCategory { Secure, Danger, Caution, Unknown };

struct PortRule {
    QString      label;
    PortCategory category = PortCategory::Unknown;
};

class PortConfig {
public:
    // Singleton — reloaded at startup (and on demand).
    static PortConfig& instance() {
        static PortConfig inst;
        return inst;
    }

    // Call once at startup (and whenever the user edits ports.txt).
    void reload(const QString& path = "ports.txt");

    // Returns the rule for the given port (or Unknown if not listed).
    PortRule classify(uint16_t port) const;

    // Convenience colour lookup.
    static QColor colorFor(PortCategory cat);
    QColor colorForPort(uint16_t port) const { return colorFor(classify(port).category); }

private:
    PortConfig();
    void loadDefaults();

    QMap<uint16_t, PortRule> rules_;
};

#endif // PORT_CONFIG_H
