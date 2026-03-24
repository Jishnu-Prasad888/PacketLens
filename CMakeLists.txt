cmake_minimum_required(VERSION 3.16)
project(PacketLens LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ── Qt MOC / RCC / UIC ───────────────────────────────────────────────────────
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

# ── Qt6 ──────────────────────────────────────────────────────────────────────
find_package(Qt6 COMPONENTS Widgets REQUIRED)

# ── libpcap ───────────────────────────────────────────────────────────────────
find_library(PCAP_LIB pcap REQUIRED)

# ── Sources ───────────────────────────────────────────────────────────────────
set(SOURCES
    main.cpp
    tcp_parser.cpp
    sniffer_backend.cpp
    connection_model.cpp
    main_window.cpp

    # ── v2: graph view ────────────────────────────────────────────────────────
    port_config.cpp
    graph_node.cpp
    network_graph_widget.cpp
    side_panel.cpp

    # ── v3: embedded HTTP API (MCP bridge) ────────────────────────────────────
    http_api.cpp
)

set(HEADERS
    tcp_parser.h
    flow_manager.h
    sniffer_backend.h
    connection_model.h
    main_window.h

    # ── v2: graph view ────────────────────────────────────────────────────────
    port_config.h
    graph_node.h
    network_graph_widget.h
    side_panel.h

    # ── v3: embedded HTTP API ─────────────────────────────────────────────────
    http_api.h
)

# ── Executable ────────────────────────────────────────────────────────────────
add_executable(packetlens ${SOURCES} ${HEADERS})

target_link_libraries(packetlens
    PRIVATE
        Qt6::Widgets
        ${PCAP_LIB}
        pthread
)

target_compile_options(packetlens PRIVATE -Wall -Wextra)
