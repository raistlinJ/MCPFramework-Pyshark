# mcppython MCP Server

A minimal Python MCP server (stdio) with example tools for general use and packet capture analysis (pyshark), ready for Claude Desktop.

## Features
- Tools:
  - `analyze_pcap(file_path: str, display_filter: str | None = None, packet_limit: int = 200, progress_every: int = 500)`
  - `top_protocols(file_path: str, display_filter: str | None = None, packet_limit: int = 5000, top_n: int = 10)`
  - `tcp_handshake_stats(file_path: str, display_filter: str | None = None, packet_limit: int = 10000)`
  - `top_ports(file_path: str, display_filter: str | None = None, packet_limit: int = 10000, top_n: int = 20)`
- Resource: `greeting://{name}`
- Prompt: `Friendly Greeting`

## Requirements
- Python >= 3.12 (recommended)
- `tshark` installed and on PATH (required by `pyshark`)
  - macOS: `brew install wireshark`

## Setup

Using uv (recommended):

```zsh
uv sync
```

Using pip:

```zsh
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Quick check

```zsh
uv run python -m py_compile server.py
```

## Develop with MCP Inspector

```zsh
uv run mcp dev server.py
```

This launches the MCP Inspector in your browser and runs the server over stdio.

## Install into Claude Desktop (with deps)

Install via MCP CLI so Claude uses your project environment and dependencies:

```zsh
uv run mcp install server.py -n "TestMCPPython" --with-editable . --with 'pyshark>=0.6.0'
```

Notes:
- `--with-editable .` ensures Claude installs your project package (declared in `pyproject.toml`).
- The explicit `--with 'pyshark>=0.6.0'` guarantees `pyshark` is installed even if Claude cached an older command.
- If you update the server, run the install command again or restart Claude Desktop.

## Tools reference

### analyze_pcap
Arguments:
- `file_path`: path to `.pcap`/`.pcapng`
- `display_filter` (optional): Wireshark display filter
- `packet_limit`: caps the number of packets scanned (soft cap)
- `progress_every`: report progress every N packets

Returns:
- `total_packets`: scanned packets
- `protocols`: map of highest-layer protocol counts
- `top_sources`: list of `{ip, count}`
- `top_destinations`: list of `{ip, count}`

Progress updates are emitted in supporting clients.

### top_protocols
Returns a list of `{protocol, count, percentage}`.

### tcp_handshake_stats
Counts SYN, SYN-ACK, ACK per TCP stream and totals complete 3-way handshakes.

### top_ports
Returns per-protocol top destination ports as `{port, count, percentage}` plus
`total_packets` and `analyzed_packets` with periodic progress.

## Sample prompts for Claude Desktop

You can ask Claude in natural language; it will call the appropriate MCP tools.

- In the file `/path/to/capture.pcapng`, how many packets are there?
  - Hint for Claude: call `analyze_pcap` with a high `packet_limit` and report `total_packets`.

- For `/path/to/capture.pcapng`, list the 10 most common highest-layer protocols with percentages.
  - Hint: call `top_protocols` with `top_n=10`.

- Scan `/path/to/capture.pcapng` and show the top 10 TCP destination ports and top 10 UDP destination ports.
  - Hint: call `top_ports` with `top_n=10`.

- For `/path/to/capture.pcapng`, estimate how many complete TCP three-way handshakes occurred.
  - Hint: call `tcp_handshake_stats` and report `complete_handshakes`.

- Filter to TLS traffic in `/path/to/capture.pcapng` and show the top source and destination talkers.
  - Hint: call `analyze_pcap` with `display_filter="tls"` and summarize `top_sources` and `top_destinations`.

- In the file `/path/to/capture.pcapng`, how many packets are there; what subnetworks are in the RIP packets?
  - Hint: first call `analyze_pcap` to get `total_packets`. Then call `analyze_pcap` again with `display_filter="rip"` to count RIP packets. Note: enumerating advertised RIP subnetworks (route entries) isn’t exposed yet by this server; if needed, ask to add a `rip_routes` tool to parse RIP route entries.

## Troubleshooting
- `pyshark` not found: Reinstall the server into Claude with `--with-editable .` and `--with 'pyshark>=0.6.0'`.
- `tshark` missing: `brew install wireshark` and restart the server.
- Event loop errors: These tools offload `pyshark` work to a background thread; ensure you’re on the latest server code.

## License
TBD
