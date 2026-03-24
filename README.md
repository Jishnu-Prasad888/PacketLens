# PacketLens Technical Documentation

## Introduction

PacketLens is a network flow monitoring tool that combines real-time packet capture with process-level attribution, graph visualization, and a built‑in HTTP API. It runs on Linux and uses Qt for the graphical interface, libpcap for packet sniffing, and the Linux /proc filesystem to map network connections to running processes.

The application presents network flows in two complementary views: a tabular list of all active flows (with filtering and sorting) and a force‑directed graph where each remote host is a node sized by traffic volume, colour‑coded by port security, and hovering or clicking reveals detailed information.

A lightweight HTTP API (listening on localhost:8765) exposes flow data and statistics in JSON format, enabling integration with external tools. An included Python script implements an MCP (Model Context Protocol) server, allowing Claude Desktop to query PacketLens using natural language.

This document describes the architecture, components, and usage of PacketLens, as inferred directly from the source code.

---

## System Overview

PacketLens is a multi‑threaded Qt application. The main process consists of:

- **Sniffer thread** – captures raw packets using libpcap, filters for TCP/UDP, and pushes them into a thread‑safe queue.
- **Worker thread** – consumes packets, extracts flow keys, and performs process lookup by reading `/proc/net/tcp` and scanning `/proc/*/fd` (Linux‑specific).
- **Flow manager** – stores aggregated flow statistics, tracks connection state (NEW, ESTABLISHED, CLOSED), and caches process information.
- **Main window** – hosts a `QTabWidget` with two tabs: a `QTableView` (flow table) and a `QGraphicsView` (network graph). A side panel displays details of a selected graph node.
- **Background timers** – refresh the GUI every second and run physics updates for the graph every 40 ms.
- **HTTP server** – runs in its own thread, serves `/health`, `/flows`, and `/stats` endpoints.

All packet processing, process resolution, and flow aggregation happen in the background, ensuring the UI remains responsive.

---

## Core Components

### 1. FlowManager (`flow_manager.h`)

The central data structure for flows. It stores:

- `flows_`: an unordered map from `FlowKey` (normalised 5‑tuple) to `FlowData` (packet/byte counts, state, timestamps).
- `proc_cache_`: an unordered map from `FlowKey` to `ProcessInfo` (PID and process name).
- A mutex to protect concurrent access.

The manager provides methods:

- `update()` – increments packet/byte counters and updates TCP state flags.
- `get_snapshot()` – returns a vector of `FlowSnapshot` structures, each containing all data needed for the GUI (IP addresses, ports, protocol, counts, process name, state). This is called by the GUI timer.
- `garbage_collect()` – removes flows that have not seen traffic for TCP_TIMEOUT_SEC (60s) or UDP_TIMEOUT_SEC (30s).
- Process cache retrieval and storage.

The `FlowKey` normalises the tuple (sip, dip, sport, dport, proto) so that the direction of the flow does not matter; the smaller IP and port come first.

### 2. SnifferBackend (`sniffer_backend.cpp/h`)

Manages the two background threads and coordinates the flow manager.

- **snifferThread()** – runs `pcap_next_ex()` in a loop, creates `RawPacket` objects, and pushes them into the packet queue.
- **workerThread()** – pops packets, parses Ethernet/IP headers, extracts the flow key, and calls `TcpParser` to find the corresponding socket inode and PID. It then updates the flow manager and emits a signal `newConnectionFound` when a process is identified.
- Contains a `PacketQueue` with a mutex and condition variable to decouple the threads.
- Starts the HTTP API on port 8765 after capture begins.

### 3. TcpParser (`tcp_parser.cpp/h`)

A helper class that reads `/proc/net/tcp` to get all listening/established TCP sockets. Each entry contains local/remote IPs (in network byte order), ports (host order), and an inode number.

- `refresh()` – re‑reads the file and stores entries in a vector.
- `find(src_ip, src_port, dst_ip, dst_port)` – returns the matching `TcpEntry` if the 4‑tuple matches either direction.
- `inode_to_pid(inode)` – walks `/proc/<pid>/fd` looking for a socket link that matches the given inode. Returns the PID if found.

This is the Linux‑specific part; on Windows a completely different mechanism would be needed.

### 4. MainWindow (`main_window.cpp/h`)

Sets up the main UI:

- **Header** with application title, search bar, and status label.
- **QTabWidget** containing two tabs:
  - Table tab: a `QTableView` with a `QSortFilterProxyModel` on top of `ConnectionModel`.
  - Graph tab: a `QSplitter` with `NetworkGraphWidget` (graph view) and `SidePanel` (details).
- A `QTimer` that fires every second, calling `backend_->snapshot()` to obtain the latest flow data, then refreshing the table model and, if the graph tab is visible, the graph widget.

The window also connects signals from the backend (new connections, errors) and the graph (node selection) to appropriate slots.

### 5. ConnectionModel (`connection_model.cpp/h`)

A `QAbstractTableModel` that holds a vector of `FlowSnapshot`. It has a single `refresh()` method that replaces the entire vector and calls `beginResetModel()`/`endResetModel()`. This ensures the table view updates in one go without flicker.

The model supports nine columns: source IP, source port, destination IP, destination port, protocol, packets, bytes, process, state. Background colours vary by state, and foreground colours by protocol.

### 6. NetworkGraphWidget (`network_graph_widget.cpp/h`)

A `QGraphicsView` that displays a force‑directed graph of remote hosts, with a fixed master node at the centre representing the local machine.

- **Graph construction**: From the snapshot, it aggregates flows by destination IP. For each unique remote IP, it creates a `GraphNode` (if not already present) and a `QGraphicsLineItem` connecting it to the master.
- **Physics**: A timer runs every 40 ms, applying forces:
  - **Repulsion** between every pair of nodes (including the master) using a Coulomb‑like force `Kr / d²`.
  - **Spring attraction** between each remote node and the master, modelled as a Hooke force `Ks * (d - L0)`.
  - A weak centering force `-Kc * pos` to prevent drift.
  - Velocity damping and force clamping to keep movements stable.
- **Interaction**: Clicking a node toggles its “pinned” state (stops physics movement) and emits a signal with the node’s details, which the side panel displays. Hovering over a node reveals a floating information card (IP, process, bytes, port, state) above the node.

The graph uses `QGraphicsScene` and the nodes themselves are `QGraphicsItem` subclasses (`GraphNode`).

### 7. GraphNode (`graph_node.cpp/h`)

A custom graphics item representing a single host.

- **Appearance**: Circle radius grows logarithmically with total bytes transferred. Colour is determined by the port category of the most significant flow (derived from `PortConfig`). A glow effect indicates activity, and a thicker edge line connects to the master.
- **Information card**: When the node is hovered or pinned, a semi‑transparent card is drawn above it, showing the full IP, process name, formatted bytes, destination port (with category badge), and connection state.
- **Physics**: Stores a velocity vector; the `advance()` method integrates movement and applies damping. Pinned nodes are ignored in physics updates.

### 8. SidePanel (`side_panel.cpp/h`)

A panel that sits on the right side of the graph tab. It displays detailed information about a selected node: IP address, state (with coloured badge), port number, service label (from port classification), process name, total bytes (formatted), and packet count.

The panel is initially hidden; it appears when a node is clicked and cleared when no node is selected.

### 9. PortConfig (`port_config.cpp/h`)

A singleton that loads port classification rules from `ports.txt` in the working directory. Each rule specifies a port number, a human‑readable label, and a category (`danger`, `secure`, `caution`). Categories map to colours:

- Danger → bright red (#ff3a3a)
- Secure → teal/green (#3affb0)
- Caution → amber (#ffb03a)
- Unknown → yellow (#ffe033)

If `ports.txt` is missing, built‑in defaults are used (common ports like 80 → danger, 443 → secure, etc.). The file is reloaded at startup (or can be reloaded manually, though the code currently only loads once).

### 10. HttpApi (`http_api.cpp/h`)

A minimal, single‑threaded HTTP server that runs on a background thread. It listens on localhost:8765 and supports three endpoints:

- `GET /health` → returns `{"status":"ok"}`
- `GET /flows` → returns a JSON array of all current `FlowSnapshot` objects
- `GET /stats` → returns `{"total_packets":..., "total_bytes":..., "active_flows":..., "timestamp":...}`

The server uses POSIX sockets and `select()` to handle connections. It is started by `SnifferBackend` and stopped when the backend stops.

### 11. MCP Bridge (`packetlens_mcp.py`)

A standalone Python script that implements an MCP server (Model Context Protocol) using stdio transport. It communicates with the PacketLens HTTP API and exposes the following tools to an MCP client (like Claude Desktop):

- `get_flows` – returns flows with optional filters (IP, process, state, protocol, port)
- `get_stats` – returns totals
- `get_top_talkers` – lists top N flows by bytes
- `check_health` – checks API reachability
- `find_process` – finds flows for a given process name
- `security_summary` – highlights unencrypted protocols and suspicious connections

The script uses only Python’s standard library (`urllib`, `json`). It reads JSON‑RPC 2.0 requests from stdin and writes responses to stdout. The configuration for Claude Desktop is provided in a comment at the top of the file.

---

## Data Flow

1. **Packet capture**  
   `SnifferBackend::snifferThread()` uses `pcap_next_ex()` to grab raw packets and places them in the thread‑safe queue.

2. **Packet processing**  
   `workerThread()` pops packets, parses Ethernet/IP headers, extracts the 5‑tuple, and builds a `FlowKey`. It then:
   - Checks if a process is already cached for this key.
   - If not, calls `TcpParser::refresh()` and `find()` to get the socket inode, then `inode_to_pid()` to find the PID, and finally reads the process name from `/proc/<pid>/comm`.
   - Caches the result.
   - Calls `FlowManager::update()` to increment counters and update state.

3. **GUI refresh**  
   Every second, a `QTimer` triggers `MainWindow::onRefreshTimer()`, which:
   - Calls `backend_->snapshot()` to get a fresh vector of `FlowSnapshot`.
   - Passes the snapshot to `ConnectionModel::refresh()`, which updates the table.
   - If the graph tab is active, passes the snapshot to `NetworkGraphWidget::updateFromSnapshot()`.

4. **Graph physics**  
   A separate timer (40 ms) calls `NetworkGraphWidget::physicsStep()`, which:
   - Iterates over all remote nodes, applies repulsion, spring, and centering forces, updates velocities, and advances positions.
   - Updates the position of each edge line to match the node position.

5. **HTTP API**  
   The `HttpApi` thread listens for incoming connections. On a request, it calls `snapFn_` (which in turn calls `FlowManager::get_snapshot()`), builds the JSON response, and sends it.

6. **MCP interaction**  
   Claude Desktop spawns `packetlens_mcp.py`. When the user asks a question, Claude sends a JSON‑RPC request to the script, which queries the HTTP API, formats the result as text, and returns it to Claude.

---

## Build and Run

### Dependencies

- **Qt6** (Widgets, Core) – tested with version 6.x
- **libpcap** – packet capture library (development headers)
- **CMake** – version 3.16 or newer
- A **Linux** system with `/proc` filesystem (required for process lookup)

### Build instructions

```bash
mkdir build && cd build
cmake ..
cmake --build . -j$(nproc)
```

### Running

Because the application requires raw packet capture privileges, it must be run as root or with the `cap_net_raw` capability:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip ./packetlens
./packetlens   # now runs without sudo, display works normally
```

Alternatively, if you still use `sudo`, ensure the display environment is preserved:

```bash
sudo -E DISPLAY=$DISPLAY XAUTHORITY=$XAUTHORITY ./packetlens
```

### Port configuration

Edit `ports.txt` in the working directory to customise port labels and categories. The format is:

```
<port>  <label>  <category>
```

Example:

```
80    HTTP     danger
443   HTTPS    secure
3306  MySQL    caution
```

Lines starting with `#` are comments. If the file is missing, built‑in defaults are used.

### HTTP API

Once PacketLens is running, the API is available at `http://127.0.0.1:8765`. Use `curl` to test:

```bash
curl http://127.0.0.1:8765/health
curl http://127.0.0.1:8765/stats
curl http://127.0.0.1:8765/flows | python3 -m json.tool
```

### MCP Integration

To enable Claude Desktop to query PacketLens:

1. Copy `packetlens_mcp.py` to a convenient location (e.g., `/home/user/packetlens_mcp.py`).
2. Edit Claude Desktop’s configuration file (`~/.config/claude/claude_desktop_config.json`) to add:

```json
{
  "mcpServers": {
    "packetlens": {
      "command": "python3",
      "args": ["/home/user/packetlens_mcp.py"]
    }
  }
}
```

3. Restart Claude Desktop. You should then be able to ask questions like “What are the top talkers right now?” or “Show me HTTP connections.”

---

## Future Considerations

- **Windows port** – The current code relies on `/proc/net/tcp` and scanning `/proc/*/fd`. A Windows port would require using `GetExtendedTcpTable` and `Toolhelp32Snapshot` for process association. The HTTP API and Qt parts would remain largely unchanged.
- **Performance** – The worker thread refreshes `TcpParser` by reading `/proc/net/tcp` on every lookup attempt (limited to once per flow per second). For large numbers of flows, this could become a bottleneck. A more efficient approach would be to monitor `/proc/net/tcp` changes via inotify and update an in‑memory index.
- **Graph scalability** – The force‑directed graph redraws every 40 ms. With hundreds of nodes, performance may degrade. Future improvements could use spatial hashing for repulsion or reduce the update rate.
- **Security** – The HTTP API currently allows any origin (CORS: `*`). Because it only listens on localhost, this is safe, but for remote access one would need to add authentication and encryption.

---

## Conclusion

PacketLens is a self‑contained network flow monitor that combines packet‑level insight with process attribution and a modern Qt interface. Its design separates packet capture, flow processing, and UI refresh, ensuring a responsive experience even under moderate network load. The inclusion of an HTTP API and an MCP bridge makes it extensible and usable within AI‑assisted workflows.

The code is structured into clear, cohesive modules, each with a single responsibility. This documentation, drawn directly from the source, should serve as a reference for understanding, maintaining, and extending the application.
