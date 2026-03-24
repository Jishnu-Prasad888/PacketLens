// main.cpp  —  PacketLens Qt entry point
#include <QApplication>
#include "main_window.h"

int main(int argc, char* argv[]) {
    QApplication app(argc, argv);
    app.setApplicationName("PacketLens");
    app.setApplicationVersion("2.0");
    app.setOrganizationName("PacketLens");

    MainWindow w;
    w.show();

    return app.exec();
}
