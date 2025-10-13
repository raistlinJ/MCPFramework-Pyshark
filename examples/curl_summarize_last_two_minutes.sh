#!/usr/bin/env bash
# Send a prompt to mcp-client-for-ollama asking it to summarize the last two minutes of a capture.
# Customize via environment variables before running:
#   MCP_BRIDGE_HOST  - Base URL for the bridge (default http://localhost:8000)
#   OLLAMA_MODEL     - Model identifier the bridge should use (default gpt-oss:20b)
#   PCAP_PATH        - Absolute path to the capture to analyze (required)
#   DISPLAY_FILTER   - Wireshark display filter that isolates the final two minutes of traffic

set -euo pipefail

HOST="${MCP_BRIDGE_HOST:-http://localhost:8000}"
MODEL="${OLLAMA_MODEL:-gpt-oss:20b}"
PCAP_PATH="${PCAP_PATH:-/absolute/path/to/capture.pcapng}"
DISPLAY_FILTER="${DISPLAY_FILTER:-frame.time_relative >= 0 && frame.time_relative <= 120}"

if [[ "${PCAP_PATH}" == "/absolute/path/to/capture.pcapng" ]]; then
  >&2 echo "[error] Set PCAP_PATH to the capture you want to analyze before running this script."
  exit 1
fi

>&2 echo "[info] Target bridge: ${HOST}"
>&2 echo "[info] Model:        ${MODEL}"
>&2 echo "[info] Capture:      ${PCAP_PATH}"
>&2 echo "[info] Filter:       ${DISPLAY_FILTER}"

payload=$(MODEL="${MODEL}" CAPTURE="${PCAP_PATH}" DISPLAY_FILTER="${DISPLAY_FILTER}" python - <<'PY'
import json
import os

model = os.environ["MODEL"]
capture = os.environ["CAPTURE"]
display_filter = os.environ["DISPLAY_FILTER"]

prompt = (
    f"Summarize the last 2 minutes of traffic captured in {capture}. "
    f"Start by calling analyze_pcap with file_path '{capture}', packet_limit 20000, "
    f"display_filter '{display_filter}'. "
    "Then call tcp_flow_stats with the same display_filter to report dominant flows, retransmissions, and RTT. "
    "If helpful, call extract_payload_strings with the same filter to surface cleartext. "
    "Close with a concise summary of key protocols, talkers, and anomalies within that two-minute window."
)

payload = {
    "model": model,
    "stream": False,
    "messages": [
        {
            "role": "system",
            "content": (
                "You are a network traffic analyst who relies on available MCP tools "
                "such as analyze_pcap, tcp_flow_stats, dns_deep_stats, and extract_payload_strings "
                "to justify conclusions."
            ),
        },
        {"role": "user", "content": prompt},
    ],
}

print(json.dumps(payload))
PY
)

curl -sS "${HOST}/api/chat" \
  -H 'Content-Type: application/json' \
  --data "${payload}" | jq
