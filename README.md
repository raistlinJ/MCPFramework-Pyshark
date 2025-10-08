# mcppython MCP Server

A minimal Python MCP server (stdio) with example tools for general use and packet capture analysis (pyshark), ready for Claude Desktop.

## Features
- Tools:
  - `analyze_pcap(file_path: str, display_filter: str | None = None, packet_limit: int = 200, progress_every: int = 500)`
  - `top_protocols(file_path: str, display_filter: str | None = None, packet_limit: int = 5000, top_n: int = 10)`
  - `tcp_handshake_stats(file_path: str, display_filter: str | None = None, packet_limit: int = 10000)`
  - `top_ports(file_path: str, display_filter: str | None = None, packet_limit: int = 10000, top_n: int = 20)`
  - `expert_info_summary(file_path: str, display_filter: str | None = None, packet_limit: int = 10000, top_n: int = 20)`
  - `http_stats(file_path: str, display_filter: str | None = None, packet_limit: int = 20000, top_n: int = 20)`
  - `dns_stats(file_path: str, display_filter: str | None = None, packet_limit: int = 20000, top_n: int = 20)`
  - `tls_stats(file_path: str, display_filter: str | None = None, packet_limit: int = 20000, top_n: int = 20)`
  - `extract_payload_strings(file_path: str, display_filter: str | None = None, packet_limit: int = 20000, min_length: int = 6, top_n: int = 50, exclude_tls: bool = True)`
  - `tcp_flow_stats(file_path: str, display_filter: str | None = None, packet_limit: int = 50000, top_n: int = 20)`
  - `udp_flow_stats(file_path: str, display_filter: str | None = None, packet_limit: int = 50000, top_n: int = 20)`
  - `icmp_stats(file_path: str, display_filter: str | None = None, packet_limit: int = 50000)`
  - `dns_deep_stats(file_path: str, display_filter: str | None = None, packet_limit: int = 50000, top_n: int = 20)`
  - `ssh_stats(file_path: str, display_filter: str | None = None, packet_limit: int = 50000, top_n: int = 20)`
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
# Run this from the project root so a relative script path is used (avoids
# duplicating the absolute path inside Claude's MCP config JSON).
uv run mcp install server.py \
  -n "TestMCPPython" \
  --with-editable /absolute/path/to/MCPFramework-Pyshark \
  --with 'pyshark>=0.6.0'
```

Notes:
- Prefer a relative path (`server.py`) for the script when you run the install command from the project root. Claude stores the script path in its JSON; using an absolute path there plus again in `--with-editable` leads to redundancy.
- Still use an absolute path for the `--with-editable` argument so Claude can locate your package source regardless of its working directory (e.g., `/Users/you/path/to/MCPFramework-Pyshark`).
- The explicit `--with 'pyshark>=0.6.0'` guarantees `pyshark` is installed even if Claude cached an older command.
- If you update the server, re-run the install command or restart Claude Desktop.
- IMPORTANT (Claude Desktop File System Connector): Enable the File System connector in Claude Desktop so tools can read your local `.pcap` / `.pcapng` files. In Claude Desktop: Settings > Connectors > toggle on "File System" (grant access if prompted). If it's disabled, Claude cannot pass your file paths to MCP tools and you'll see file-not-found errors even when paths are correct.

Tip (macOS zsh): set and reuse your absolute repo path

```zsh
# From the repo root
export PYSHARK_MCP_REPO_PATH="$(pwd)"

# Install into Claude Desktop (relative script path, absolute editable path)
cd "$PYSHARK_MCP_REPO_PATH" && \
uv run mcp install server.py \
  -n "TestMCPPython" \
  --with-editable "$PYSHARK_MCP_REPO_PATH" \
  --with 'pyshark>=0.6.0'
```

Other shells:
- bash (same as zsh):
  ```bash
  export PYSHARK_MCP_REPO_PATH="$(pwd)"
  ```
- fish:
  ```fish
  set -x PYSHARK_MCP_REPO_PATH (pwd)
  ```
- PowerShell (Windows):
  ```powershell
  $env:PYSHARK_MCP_REPO_PATH = (Get-Location).Path
  ```

One-liners without a variable (absolute path inline):
- Claude install (run from repo root; relative script path):
  ```zsh
  uv run mcp install server.py -n "TestMCPPython" --with-editable "$(pwd)" --with 'pyshark>=0.6.0'
  ```
  PowerShell:
  ```powershell
  uv run mcp install "$(Get-Location)/server.py" -n "TestMCPPython" --with-editable "$(Get-Location)" --with 'pyshark>=0.6.0'
  ```

## Run with Tome (uvx + MCP CLI)

If you use Tome, you can run this MCP server directly with `uvx` and the MCP CLI without creating a local venv. This ensures the necessary extras and `pyshark` are available at runtime.

Prereqs:
- `uv` installed (`curl -LsSf https://astral.sh/uv/install.sh | sh`)
- `tshark` on your `PATH` (e.g., macOS: `brew install wireshark`)

Run command:

```zsh
uvx \
  --with 'mcp[cli]' \
  --with 'pyshark>=0.6.0' \
  --with-editable /path/to/MCPFramework-Pyshark \
  mcp run /path/to/MCPFramework-Pyshark/server.py
```

Notes:
- `--with 'mcp[cli]'` provides the MCP CLI entrypoint `mcp` for running the server via stdio.
- `--with 'pyshark>=0.6.0'` guarantees a compatible `pyshark` at runtime.
- Use absolute paths for both the editable source and `server.py` so Tome resolves the files correctly regardless of current working directory.
- `--with-editable /path/to/MCPFramework-Pyshark` makes your local package available when Tome loads the server.
- You can append `-- -h` after the run command to see server flags, e.g. `uvx … mcp run /path/to/MCPFramework-Pyshark/server.py -- -h`.

Tip (macOS zsh): reuse the same variable for Tome

```zsh
# From the repo root
export PYSHARK_MCP_REPO_PATH="$(pwd)"

uvx \
  --with 'mcp[cli]' \
  --with 'pyshark>=0.6.0' \
  --with-editable "$PYSHARK_MCP_REPO_PATH" \
  mcp run "$PYSHARK_MCP_REPO_PATH/server.py"
```

Other shells:
- bash (same as zsh):
  ```bash
  export PYSHARK_MCP_REPO_PATH="$(pwd)"
  ```
- fish:
  ```fish
  set -x PYSHARK_MCP_REPO_PATH (pwd)
  ```
- PowerShell (Windows):
  ```powershell
  $env:PYSHARK_MCP_REPO_PATH = (Get-Location).Path
  ```

One-liners without a variable (absolute path inline):
- Tome run:
  ```zsh
  uvx --with 'mcp[cli]' --with 'pyshark>=0.6.0' --with-editable "$(pwd)" mcp run "$(pwd)/server.py"
  ```
  PowerShell:
  ```powershell
  uvx --with 'mcp[cli]' --with 'pyshark>=0.6.0' --with-editable "$(Get-Location)" mcp run "$(Get-Location)/server.py"
  ```

### Windows path specifics for Tome

On Windows (PowerShell or CMD), prefer absolute paths for both the editable directory and the server script when using `uvx` with Tome. Either backslashes (`C:\Users\You\Projects\MCPFramework-Pyshark`) or forward slashes (`C:/Users/You/Projects/MCPFramework-Pyshark`) work with Python and `uvx`. Forward slashes often reduce escaping headaches.

PowerShell (recommended):
```powershell
# From repo root
$env:PYSHARK_MCP_REPO_PATH = (Get-Location).Path

# Use forward slashes (safe & concise)
uvx --with 'mcp[cli]' --with 'pyshark>=0.6.0' \
  --with-editable "$env:PYSHARK_MCP_REPO_PATH" \
  mcp run "$env:PYSHARK_MCP_REPO_PATH/server.py"

# Or with backslashes (also works)
uvx --with 'mcp[cli]' --with 'pyshark>=0.6.0' \
  --with-editable "$env:PYSHARK_MCP_REPO_PATH" \
  mcp run "$env:PYSHARK_MCP_REPO_PATH\server.py"
```

CMD (legacy shell):
```cmd
REM From repo root
set PYSHARK_MCP_REPO_PATH=%cd%

REM Forward slashes version
uvx --with "mcp[cli]" --with "pyshark>=0.6.0" --with-editable "%PYSHARK_MCP_REPO_PATH%" mcp run "%PYSHARK_MCP_REPO_PATH%/server.py"

REM Backslashes version
uvx --with "mcp[cli]" --with "pyshark>=0.6.0" --with-editable "%PYSHARK_MCP_REPO_PATH%" mcp run "%PYSHARK_MCP_REPO_PATH%\server.py"
```

Spaces in path? Always wrap each path in double quotes. Example:
```powershell
uvx --with 'mcp[cli]' --with 'pyshark>=0.6.0' --with-editable "C:/Users/You/OneDrive - Company/MCPFramework-Pyshark" mcp run "C:/Users/You/OneDrive - Company/MCPFramework-Pyshark/server.py"
```

Troubleshooting (Windows):
- If `tshark` is not found, install Wireshark and ensure its install dir (e.g. `C:\Program Files\Wireshark`) is in PATH, then restart the shell.
- If Tome reports it cannot locate `server.py`, echo the variable to confirm: `echo $env:PYSHARK_MCP_REPO_PATH` (PowerShell) or `echo %PYSHARK_MCP_REPO_PATH%` (CMD).
- If you see event loop errors, update to the latest server code (a worker thread loop initializer was added) and re-run.

## Use with `mcp-client-for-ollama`

You can run this MCP server alongside [jonigl/mcp-client-for-ollama](https://github.com/jonigl/mcp-client-for-ollama) to expose packet-analysis tools directly inside the Ollama web UI.

### Setup steps
1. Clone the Ollama MCP client repo and install its dependencies:
   ```zsh
   git clone https://github.com/jonigl/mcp-client-for-ollama.git
   cd mcp-client-for-ollama
   npm install
   ```
2. Install the official filesystem MCP server (provides file access to your captures). The npm package is published from the [modelcontextprotocol/servers](https://github.com/modelcontextprotocol/servers/) repo:
   ```zsh
   npm install
   ```
   (Optional) You can test run it with `npx @modelcontextprotocol/server-filesystem <path1> <path2> …` or add it directly to the config below.
3. Create or update the MCP config file consumed by `mcp-client-for-ollama` (defaults to `config.json` in the project root). Use absolute paths for the editable checkout and any directories you want to expose via the filesystem server.

### Sample `config.json`

```jsonc
{
  "mcpServers": {
    "pyshark-tools": {
      "command": "uv",
      "args": [
        "run",
        "--with",
        "mcp[cli]",
        "--with",
        "pyshark>=0.6.0",
        "--with-editable",
        "/absolute/path/to/MCPFramework-Pyshark",
        "mcp",
        "run",
        "/absolute/path/to/MCPFramework-Pyshark/server.py"
      ]
    },
    "filesystem": {
      "command": "/absolute/path/to/npx",
      "args": [
        "@modelcontextprotocol/server-filesystem",
        "/absolute/path/to/captures",
        "/another/path/you/want/to/browse"
      ]
    }
  }
}
```

Adjust the paths to match your environment (Windows users: forward slashes work fine, e.g. `C:/Users/you/MCPFramework-Pyshark`). 

### Launching
- Invoke the module and tell it which config/model to use:
  ```zsh
  uv run -m mcp_client_for_ollama \
    -j /absolute/path/to/your/config.json \
    --model your-model-id
  ```
  Replace the path and model placeholders with your own values, e.g. `uv run -m mcp_client_for_ollama -j ../MCPFramework-Pyshark/claude_desktop_config.json --model gpt-oss:20b`.

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

### expert_info_summary
Scans Wireshark Expert Info items and returns:
- `total_packets`, `expert_items`, `severities` (counts by severity),
- `top_messages`: list of `{message, count}`.

### http_stats
Summarizes HTTP traffic:
- Counts `requests`, `responses`; maps of `methods` and `status_codes`.
- `top_hosts`: list of `{host, count}`.

### dns_stats
Summarizes DNS traffic:
- Counts `queries`, `responses`; maps of `qtypes` and `rcodes`.
- `top_query_names`: list of `{name, count}` (most frequent query names).

### tls_stats
Summarizes TLS traffic:
- Counts `handshakes`; maps of TLS `versions` and `cipher_suites`.
- `top_sni`: list of `{sni, count}` from Server Name Indication.

### extract_payload_strings
Extracts cleartext strings from non-encrypted payload bytes using the Wireshark `data` layer.
Arguments:
- `file_path`: pcap/pcapng path
- `display_filter` (optional): additional filter to narrow scope
- `packet_limit`: max packets to scan
- `min_length`: minimum string length (default 6)
- `top_n`: number of most frequent strings to return (default 50)
- `exclude_tls`: when true (default), adds `not tls` to the filter
- `include_utf8`: also attempt to extract UTF-8 strings (default true)
- `regex_filter`: optional regex to filter discovered strings (applied to text)
- `case_insensitive`: when true (default), `regex_filter` uses case-insensitive matching
- `max_strings`: optional hard cap on total retained strings before ranking

Returns:
- `total_packets`, `payload_packets`, `total_strings`
- `encodings`: counts by encoding (`ascii`, `utf-16le`, `utf-16be`)
- `top_strings`: list of `{text, encoding, count}`

### tcp_flow_stats
Deep TCP analysis per stream:
- Aggregates by `tcp.stream` when available; reports `streams` count.
- Counts `syn`, `syn_ack`, `fin`, `rst`, `retransmissions`, `out_of_order`.
- RTT stats from `tcp.analysis.ack_rtt` (ms): `rtt_ms_min`, `rtt_ms_avg`, `rtt_ms_max`.
- Returns `top_src`/`top_dst` by packets as `{ip, count}`.
- Returns `top_flows_by_packets`/`top_flows_by_bytes` as lists of `{stream, src, sport, dst, dport, packets, bytes, fwd_packets, fwd_bytes, rev_packets, rev_bytes, retransmissions, out_of_order}`.

### udp_flow_stats
UDP flow analysis (5-tuple):
- Counts total `flows`, returns `top_src`/`top_dst` by packets.
- Returns `top_flows_by_packets`/`top_flows_by_bytes` as lists of `{src, sport, dst, dport, packets, bytes}`.

### icmp_stats
ICMP and ICMPv6 summary:
- Counts by `types` and `codes` (prefixed with protocol, e.g., `icmp:8`).
- Totals for `echo_request`, `echo_reply`, `unreachable`, `time_exceeded`, `redirects`.
- Unique `unique_sources` and `unique_destinations` hosts.

### dns_deep_stats
Deeper DNS metrics:
- Transport counts: `udp` vs `tcp` usage; `truncated` messages.
- Error stats: `nxdomain`, `servfail`.
- RTT metrics from `dns.time` in milliseconds: `rtt_ms_min`, `rtt_ms_avg`, `rtt_ms_max`.
- `top_servers`: responding server IPs; `top_nxdomain_names` for failed queries.

### ssh_stats
SSH protocol summary:
- `versions` (banners), `kex_algorithms`, `host_key_algorithms`, `encryption_algorithms`, `mac_algorithms`, `auth_methods`.
- `connections`: unique TCP streams; `top_banners` lists `{banner, count}`.

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

- Summarize TLS usage in `/path/to/capture.pcapng`: show TLS versions, top SNI, and common cipher suites.
  - Hint: call `tls_stats` and report `versions`, `top_sni`, and `cipher_suites`.

- For `/path/to/capture.pcapng`, list the most common HTTP methods and top hostnames.
  - Hint: call `http_stats` and report `methods`, `status_codes`, and `top_hosts`.

- For `/path/to/capture.pcapng`, show DNS query types and most frequent query names.
  - Hint: call `dns_stats` and report `qtypes`, `rcodes`, and `top_query_names`.

- For `/path/to/capture.pcapng`, show deep DNS metrics including NXDOMAINs, truncation, UDP vs TCP usage, and response time stats.
  - Hint: call `dns_deep_stats` and report `nxdomain`, `truncated`, `udp`, `tcp`, and RTT stats.

- Are there any Wireshark Expert Info warnings or errors in `/path/to/capture.pcapng`? Summarize by severity and show the top messages.
  - Hint: call `expert_info_summary` and report `severities` and `top_messages`.

- Find readable application payload in `/path/to/capture.pcapng` and list common strings.
  - Hint: call `extract_payload_strings` (default `exclude_tls=true`) and show `top_strings`.

- Look for credentials or tokens in HTTP payload (only if present) in `/path/to/capture.pcapng`.
  - Hint: call `extract_payload_strings` with `display_filter="http"` and surface frequent `top_strings`.

- Search for API keys or JWTs in `/path/to/capture.pcapng` payloads.
  - Hint: call `extract_payload_strings` with `regex_filter="(api[_-]?key|bearer|eyJ[a-zA-Z0-9_\-]{10,})"` and possibly `include_utf8=true`.

- For `/path/to/capture.pcapng`, analyze TCP behavior: retransmissions, out-of-order segments, and top flows by packets and bytes.
  - Hint: call `tcp_flow_stats` and summarize `retransmissions`, `out_of_order`, `top_flows_by_packets`, `top_flows_by_bytes`.

- For `/path/to/capture.pcapng`, summarize UDP flows and top talkers.
  - Hint: call `udp_flow_stats` and report `flows`, `top_src`, `top_dst`.

- For `/path/to/capture.pcapng`, summarize ICMP/ICMPv6 traffic: echo requests/replies, unreachable, time exceeded.
  - Hint: call `icmp_stats` and report `echo_request`, `echo_reply`, `unreachable`, `time_exceeded`.

- For `/path/to/capture.pcapng`, show SSH versions and algorithms used.
  - Hint: call `ssh_stats` and report `versions`, `kex_algorithms`, `host_key_algorithms`, `encryption_algorithms`, `mac_algorithms`.

## Troubleshooting
- `pyshark` not found: Reinstall the server into Claude with `--with-editable .` and `--with 'pyshark>=0.6.0'`.
- `tshark` missing: `brew install wireshark` and restart the server.
- Event loop errors: These tools offload `pyshark` work to a background thread; ensure you’re on the latest server code.

Diagnostics tips:
- View stderr logs while developing: run `uv run mcp dev /path/to/MCPFramework-Pyshark/server.py` or `uvx --with 'mcp[cli]' --with 'pyshark>=0.6.0' --with-editable /path/to/MCPFramework-Pyshark mcp run /path/to/MCPFramework-Pyshark/server.py`.
- Confirm `tshark` is available:
  ```zsh
  tshark -v
  ```
  If missing on macOS: `brew install wireshark`.

## License
TBD
