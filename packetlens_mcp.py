#!/usr/bin/env python3
"""
packetlens_mcp.py
─────────────────
MCP server (stdio transport) that bridges Claude to the PacketLens HTTP API.

PacketLens exposes:
  GET http://127.0.0.1:8765/flows   → JSON array of active network flows
  GET http://127.0.0.1:8765/stats   → totals (packets, bytes, flow count)
  GET http://127.0.0.1:8765/health  → {"status":"ok"}

This script reads JSON-RPC 2.0 from stdin, writes responses to stdout.
Claude Desktop spawns it as a subprocess — no installation needed beyond
Python 3.8+ (stdlib only, no pip packages required).

Claude Desktop config  (~/.config/claude/claude_desktop_config.json):
{
  "mcpServers": {
    "packetlens": {
      "command": "python3",
      "args": ["/path/to/packetlens_mcp.py"]
    }
  }
}
"""

import sys
import json
import urllib.request
import urllib.error
import traceback

# ── Config ────────────────────────────────────────────────────────────────────
API_BASE = "http://127.0.0.1:8765"
TIMEOUT  = 3  # seconds

# ── HTTP helpers ──────────────────────────────────────────────────────────────
def api_get(path: str):
    """Fetch JSON from PacketLens API. Returns parsed object or raises."""
    url = API_BASE + path
    try:
        with urllib.request.urlopen(url, timeout=TIMEOUT) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.URLError as e:
        raise RuntimeError(
            f"Cannot reach PacketLens at {API_BASE}. "
            f"Is PacketLens running? Error: {e.reason}"
        )

# ── Tool implementations ──────────────────────────────────────────────────────
def tool_get_flows(args: dict) -> str:
    """Return all active network flows, optionally filtered."""
    flows = api_get("/flows")

    # Optional filters
    ip_filter      = args.get("ip")
    process_filter = args.get("process")
    state_filter   = args.get("state")
    proto_filter   = args.get("protocol")
    port_filter    = args.get("port")

    if ip_filter:
        flows = [f for f in flows
                 if ip_filter in f.get("src_ip","") or ip_filter in f.get("dst_ip","")]
    if process_filter:
        flows = [f for f in flows
                 if process_filter.lower() in f.get("process","").lower()]
    if state_filter:
        flows = [f for f in flows
                 if f.get("state","").upper() == state_filter.upper()]
    if proto_filter:
        flows = [f for f in flows
                 if f.get("protocol","").upper() == proto_filter.upper()]
    if port_filter is not None:
        port_filter = int(port_filter)
        flows = [f for f in flows
                 if f.get("src_port") == port_filter or f.get("dst_port") == port_filter]

    if not flows:
        return "No flows match the given filters."

    # Format as readable table
    lines = [
        f"{'SRC IP':<18} {'SP':>5}  {'DST IP':<18} {'DP':>5}  "
        f"{'PROTO':<5}  {'STATE':<8}  {'BYTES':>10}  {'PKTS':>8}  PROCESS"
    ]
    lines.append("─" * 100)
    for f in flows:
        lines.append(
            f"{f.get('src_ip','?'):<18} {f.get('src_port',0):>5}  "
            f"{f.get('dst_ip','?'):<18} {f.get('dst_port',0):>5}  "
            f"{f.get('protocol','?'):<5}  "
            f"{f.get('state','?'):<8}  "
            f"{f.get('bytes',0):>10,}  "
            f"{f.get('packets',0):>8,}  "
            f"{f.get('process','(unknown)')}"
        )
    lines.append(f"\nTotal: {len(flows)} flow(s)")
    return "\n".join(lines)


def tool_get_stats(_args: dict) -> str:
    stats = api_get("/stats")
    pkts  = stats.get("total_packets", 0)
    byt   = stats.get("total_bytes",   0)
    flows = stats.get("active_flows",  0)
    ts    = stats.get("timestamp", "unknown")

    def fmt_bytes(n):
        if n < 1024:         return f"{n} B"
        if n < 1024**2:      return f"{n/1024:.1f} KB"
        if n < 1024**3:      return f"{n/1024**2:.2f} MB"
        return f"{n/1024**3:.2f} GB"

    return (
        f"PacketLens Statistics  [{ts}]\n"
        f"  Active flows   : {flows:,}\n"
        f"  Total packets  : {pkts:,}\n"
        f"  Total bytes    : {fmt_bytes(byt)}  ({byt:,} B)\n"
    )


def tool_get_top_talkers(args: dict) -> str:
    """Return the top N flows by bytes transferred."""
    flows = api_get("/flows")
    n = int(args.get("n", 10))
    flows.sort(key=lambda f: f.get("bytes", 0), reverse=True)
    top = flows[:n]

    if not top:
        return "No flows found."

    def fmt_bytes(b):
        if b < 1024:    return f"{b} B"
        if b < 1048576: return f"{b/1024:.1f} KB"
        return f"{b/1048576:.2f} MB"

    lines = [f"Top {len(top)} flows by bytes:"]
    lines.append(f"  {'#':>3}  {'DST IP':<18} {'PORT':>5}  {'BYTES':>10}  PROCESS")
    lines.append("  " + "─" * 60)
    for i, f in enumerate(top, 1):
        lines.append(
            f"  {i:>3}. {f.get('dst_ip','?'):<18} {f.get('dst_port',0):>5}  "
            f"{fmt_bytes(f.get('bytes',0)):>10}  {f.get('process','(unknown)')}"
        )
    return "\n".join(lines)


def tool_check_health(_args: dict) -> str:
    try:
        result = api_get("/health")
        if result.get("status") == "ok":
            return "PacketLens is running and the API is healthy."
        return f"Unexpected health response: {result}"
    except RuntimeError as e:
        return f"PacketLens is NOT reachable: {e}"


def tool_find_process(args: dict) -> str:
    """Find all flows belonging to a named process."""
    name = args.get("name", "")
    if not name:
        return "Please provide a process name."
    return tool_get_flows({"process": name})


def tool_security_summary(_args: dict) -> str:
    """Highlight potentially concerning connections."""
    flows = api_get("/flows")

    DANGER_PORTS = {21: "FTP", 23: "Telnet", 80: "HTTP", 8080: "HTTP-alt",
                    25: "SMTP", 110: "POP3", 143: "IMAP"}
    KNOWN_SECURE = {443, 22, 993, 995, 465, 587, 8443}

    unencrypted = []
    unknown_high = []
    established  = []

    for f in flows:
        dst_port = f.get("dst_port", 0)
        state    = f.get("state", "")

        if dst_port in DANGER_PORTS:
            unencrypted.append(
                f"  ⚠  {f['dst_ip']}:{dst_port} ({DANGER_PORTS[dst_port]}) "
                f"← {f.get('process','?')}"
            )
        elif dst_port not in KNOWN_SECURE and dst_port > 1024 and state == "EST":
            unknown_high.append(
                f"  ?  {f['dst_ip']}:{dst_port} ← {f.get('process','?')} "
                f"[{f.get('bytes',0):,} B]"
            )
        if state == "EST":
            established.append(f)

    lines = ["PacketLens Security Summary", "=" * 40]
    lines.append(f"Established flows: {len(established)}")

    if unencrypted:
        lines.append(f"\nUnencrypted/legacy protocols ({len(unencrypted)}):")
        lines.extend(unencrypted)
    else:
        lines.append("\nNo unencrypted protocol connections detected.")

    if unknown_high:
        lines.append(f"\nUnknown high-port connections ({len(unknown_high)}):")
        lines.extend(unknown_high[:10])
        if len(unknown_high) > 10:
            lines.append(f"  … and {len(unknown_high)-10} more")
    else:
        lines.append("\nNo suspicious high-port connections.")

    return "\n".join(lines)


# ── Tool registry ─────────────────────────────────────────────────────────────
TOOLS = {
    "get_flows": {
        "fn": tool_get_flows,
        "description": (
            "Get all active network flows from PacketLens. "
            "Optionally filter by ip (string), process (string), "
            "state (NEW/EST/CLOSED), protocol (TCP/UDP), or port (integer)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "ip":       {"type": "string",  "description": "Filter by IP address (src or dst)"},
                "process":  {"type": "string",  "description": "Filter by process name (partial match)"},
                "state":    {"type": "string",  "description": "Filter by state: NEW, EST, or CLOSED"},
                "protocol": {"type": "string",  "description": "Filter by protocol: TCP or UDP"},
                "port":     {"type": "integer", "description": "Filter by port number (src or dst)"},
            },
        },
    },
    "get_stats": {
        "fn": tool_get_stats,
        "description": "Get PacketLens summary statistics: total packets, bytes, and active flow count.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    "get_top_talkers": {
        "fn": tool_get_top_talkers,
        "description": "Return the top N flows sorted by bytes transferred (most traffic first).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "n": {"type": "integer", "description": "Number of top flows to return (default: 10)"},
            },
        },
    },
    "check_health": {
        "fn": tool_check_health,
        "description": "Check whether PacketLens is running and its API is reachable.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    "find_process": {
        "fn": tool_find_process,
        "description": "Find all network flows belonging to a specific process by name.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Process name to search for"},
            },
            "required": ["name"],
        },
    },
    "security_summary": {
        "fn": tool_security_summary,
        "description": (
            "Generate a security-focused summary of current network activity. "
            "Highlights unencrypted protocols, unknown high-port connections, and active flows."
        ),
        "inputSchema": {"type": "object", "properties": {}},
    },
}

# ── JSON-RPC dispatch ─────────────────────────────────────────────────────────
def make_response(id_, result=None, error=None):
    msg = {"jsonrpc": "2.0", "id": id_}
    if error is not None:
        msg["error"] = error
    else:
        msg["result"] = result
    return msg


def handle_request(req: dict) -> dict | None:
    """Handle one JSON-RPC request. Returns None for notifications (no id)."""
    id_     = req.get("id")
    method  = req.get("method", "")
    params  = req.get("params", {})

    # Notifications (no id) — just handle initialize/initialized silently
    if id_ is None:
        return None

    # ── initialize ────────────────────────────────────────────────────────────
    if method == "initialize":
        return make_response(id_, {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "packetlens-mcp", "version": "1.0.0"},
        })

    # ── tools/list ────────────────────────────────────────────────────────────
    if method == "tools/list":
        tool_list = [
            {
                "name": name,
                "description": spec["description"],
                "inputSchema": spec["inputSchema"],
            }
            for name, spec in TOOLS.items()
        ]
        return make_response(id_, {"tools": tool_list})

    # ── tools/call ────────────────────────────────────────────────────────────
    if method == "tools/call":
        tool_name = params.get("name", "")
        tool_args = params.get("arguments", {})

        if tool_name not in TOOLS:
            return make_response(id_, error={
                "code": -32601,
                "message": f"Unknown tool: {tool_name}",
            })

        try:
            result_text = TOOLS[tool_name]["fn"](tool_args)
            return make_response(id_, {
                "content": [{"type": "text", "text": result_text}],
                "isError": False,
            })
        except Exception as e:
            return make_response(id_, {
                "content": [{"type": "text", "text": f"Error: {e}"}],
                "isError": True,
            })

    # ── ping ──────────────────────────────────────────────────────────────────
    if method == "ping":
        return make_response(id_, {})

    # ── unknown method ────────────────────────────────────────────────────────
    return make_response(id_, error={"code": -32601, "message": f"Method not found: {method}"})


# ── Main loop ─────────────────────────────────────────────────────────────────
def main():
    # Unbuffered stdout is critical for stdio MCP transport
    sys.stdout.reconfigure(line_buffering=True)  # type: ignore[attr-defined]

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue

        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            # Malformed input — send parse error
            resp = {"jsonrpc": "2.0", "id": None,
                    "error": {"code": -32700, "message": "Parse error"}}
            print(json.dumps(resp), flush=True)
            continue

        try:
            resp = handle_request(req)
        except Exception:
            resp = make_response(req.get("id"), error={
                "code": -32603,
                "message": "Internal error",
                "data": traceback.format_exc(),
            })

        if resp is not None:
            print(json.dumps(resp), flush=True)


if __name__ == "__main__":
    main()
