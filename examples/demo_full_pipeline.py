#!/usr/bin/env python3
"""End-to-end demo:

1. Capture live traffic into a PCAPNG (or reuse an existing file).
2. Launch mcp-client-for-ollama so it can reach this PyShark MCP server.
3. Invoke the curl helper that asks the model to "summarize the last 2 minutes".

This script assumes you already installed:
- tshark (for live capture)
- curl & jq (for the helper script)
- uv (to run mcp-client-for-ollama)
- mcp-client-for-ollama and @modelcontextprotocol/server-filesystem configured via a JSON file.

It exits with an error message if any prerequisite is missing.
"""
from __future__ import annotations

import argparse
import json
import os
import signal
import shutil
import subprocess
import sys
import time
from pathlib import Path

import httpx

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent

DEFAULT_CONFIG = ROOT / "mcp_config.json"
DEFAULT_CAPTURE_DIR = ROOT / "captures"


def build_prompt(prompt_type: int, capture: Path, duration: int, display_filter: str) -> str:
    capture_str = str(capture)
    if prompt_type == 1:
        return (
            "Provide a fast size snapshot of the capture. "
            f"Call analyze_pcap with file_path '{capture_str}', packet_limit 0, display_filter '' to obtain metadata. "
            "Report only three bullet points: total packet count, file size in megabytes, and the approximate duration in seconds. "
            "Do not invoke any other tools and keep the response under 100 words."
        )
    if prompt_type == 2:
        return (
            "Deliver minimal protocol counts for the most recent traffic window. "
            f"Start by calling analyze_pcap with file_path '{capture_str}', packet_limit 5000, display_filter '{display_filter}'. "
            "Summarize the top five protocols by packet count and note the overall packet/byte totals. "
            "Keep the narrative concise—no more than four sentences—and skip deeper investigation."
        )
    if prompt_type == 3:
        return (
            f"Summarize the final window of traffic captured in {capture_str}. The capture duration is approximately {duration} seconds, so "
            f"focus on frames where {display_filter}. "
            f"Start by calling analyze_pcap with file_path '{capture_str}', packet_limit 20000, display_filter '{display_filter}'. "
            "Then call tcp_flow_stats with the same display_filter to report dominant flows, retransmissions, and RTT. "
            "If helpful, call extract_payload_strings with the same filter to surface cleartext. "
            "Even if the window is shorter than 120 seconds, proceed with these tool calls and provide a concise summary of key protocols, talkers, and anomalies."
        )
    if prompt_type == 4:
        return (
            "Produce an in-depth protocol review for the last activity window. "
            f"Begin with analyze_pcap using file_path '{capture_str}', packet_limit 25000, display_filter '{display_filter}'. "
            "Follow with tcp_flow_stats and dns_deep_stats using the same filter. When relevant, also call http_stats or tls_stats to characterize application behavior. "
            "Structure the answer with sections for Protocol Highlights, Dominant Flows, DNS Observations, and Issues/Anomalies. "
            "If evidence is sparse, state that explicitly before concluding."
        )
    if prompt_type == 5:
        return (
            "Generate a detailed investigative summary for the capture's final window. "
            f"Run analyze_pcap (file_path '{capture_str}', packet_limit 40000, display_filter '{display_filter}') followed by tcp_flow_stats, dns_deep_stats, top_ports, and top_protocols. "
            "If suspicious payload exists, also invoke extract_payload_strings; if encrypted flows dominate, discuss tls_stats. "
            "Incorporate any relevant context from environment_diagnostics if it aids interpretation. "
            "Deliver a narrative covering topology, protocol breakdown, flow health, security signals, and recommended follow-up actions."
        )
    raise ValueError(f"Unsupported prompt type: {prompt_type}")

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run capture → launch mcp bridge → summarize via curl")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG, help="Path to mcp-client-for-ollama JSON config")
    parser.add_argument("--model", default="gpt-oss:20b", help="Model identifier to request from Ollama")
    parser.add_argument("--ollama-host", default="http://localhost:11434", help="Base URL for the Ollama server")
    parser.add_argument("--bridge-host", default="127.0.0.1", help="Host for the HTTP bridge to bind to")
    parser.add_argument("--bridge-port", type=int, default=8000, help="Port for the HTTP bridge to bind to")
    parser.add_argument("--pcap", type=Path, help="Existing PCAP/PCAPNG file to reuse (skip live capture)")
    parser.add_argument("--interface", help="Network interface to capture from (required if no --pcap)")
    parser.add_argument("--duration", type=int, default=120, help="Capture duration in seconds when live capturing")
    parser.add_argument("--keep-bridge", action="store_true", help="Leave the bridge running after the script exits")
    parser.add_argument(
        "--prompt-type",
        type=int,
        choices=range(1, 6),
        default=3,
        help="Prompt preset: 1=filesize snapshot, 2=protocol counts, 3=quick summary, 4=in-depth review, 5=investigative report",
    )
    parser.add_argument(
        "--client-path",
        type=Path,
        help="Path to a local clone of mcp-client-for-ollama (uses uv --with-editable)",
    )
    return parser.parse_args()

def ensure_exists(path: Path, description: str) -> None:
    if not path.exists():
        sys.exit(f"[error] {description} not found: {path}")

def ensure_executable(binary: str) -> None:
    if shutil.which(binary) is None:
        sys.exit(f"[error] Required executable '{binary}' not found on PATH")


def stop_bridge(process: subprocess.Popen[bytes], *, timeout: float = 10.0) -> None:
    if process.poll() is not None:
        return
    try:
        process.send_signal(signal.SIGINT)
        process.wait(timeout=timeout)
    except (ProcessLookupError, PermissionError):
        return
    except subprocess.TimeoutExpired:
        process.kill()
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            pass

def run_capture(interface: str, duration: int, output: Path) -> None:
    ensure_executable("tshark")
    output.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        "tshark",
        "-i",
        interface,
        "-a",
        f"duration:{duration}",
        "-w",
        str(output),
    ]
    print(f"[info] Starting tshark capture on {interface} for {duration}s → {output}")
    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as exc:
        sys.exit(f"[error] tshark capture failed: {exc}")

def start_bridge(
    config: Path,
    model: str,
    ollama_host: str,
    bridge_host: str,
    bridge_port: int,
    client_path: Path | None,
) -> subprocess.Popen[bytes]:
    ensure_executable("uv")
    cmd = [
        "uv",
        "run",
        "--with",
        "fastapi>=0.111.0",
        "--with",
        "uvicorn[standard]",
    ]

    if client_path:
        resolved = client_path.resolve()
        if not resolved.exists():
            sys.exit(f"[error] Provided --client-path does not exist: {resolved}")
        cmd.extend(["--with-editable", str(resolved)])
    else:
        cmd.extend(["--with", "mcp-client-for-ollama"])

    cmd.extend([
        "-m",
        "mcppython.bridge_server",
        "--config",
        str(config),
        "--model",
        model,
        "--ollama-host",
        ollama_host,
        "--host",
        bridge_host,
        "--port",
        str(bridge_port),
    ])
    env = os.environ.copy()
    print(f"[info] Launching bridge server: {' '.join(cmd)}")
    process = subprocess.Popen(cmd, env=env, cwd=str(ROOT))
    return process

def wait_for_health(host: str, port: int, timeout: int = 30) -> None:
    base_url = f"http://{host}:{port}"
    print(f"[info] Waiting for bridge health at {base_url}/health …")
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            resp = httpx.get(f"{base_url}/health", timeout=2.0)
            if resp.status_code == 200:
                print("[info] Bridge is healthy")
                return
        except httpx.HTTPError:
            pass
        time.sleep(1)
    raise TimeoutError(f"Bridge did not report healthy within {timeout}s")

def call_bridge_direct(bridge_url: str, model: str, capture: Path, duration: int, prompt_type: int) -> str:
    window_start = max(0, duration - 120)
    display_filter = f"frame.time_relative >= {window_start} && frame.time_relative <= {duration}"
    prompt = build_prompt(prompt_type, capture, duration, display_filter)

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

    print(f"[info] Requesting summary from bridge at {bridge_url}")
    print(f"[info] Using prompt preset {prompt_type}")
    print("[debug] Prompt payload:")
    print(json.dumps(payload, indent=2))
    timeout = httpx.Timeout(connect=30.0, read=None, write=30.0, pool=30.0)
    resp = httpx.post(f"{bridge_url}/api/chat", json=payload, timeout=timeout)
    try:
        resp.raise_for_status()
    except httpx.HTTPStatusError as exc:
        print(f"[warn] Bridge returned {exc.response.status_code}; showing raw response body")
        return exc.response.text

    data = resp.json()
    if isinstance(data, dict) and "content" in data:
        return data["content"]
    return resp.text

def main() -> None:
    args = parse_args()

    if args.pcap:
        capture_path = args.pcap.resolve()
        ensure_exists(capture_path, "Provided PCAP")
        assumed_duration = args.duration
    else:
        if not args.interface:
            sys.exit("[error] --interface is required for live capture")
        capture_path = (DEFAULT_CAPTURE_DIR / f"capture_{int(time.time())}.pcapng").resolve()
        run_capture(args.interface, args.duration, capture_path)
        assumed_duration = args.duration

    config_path = args.config.resolve()
    ensure_exists(config_path, "Config file")

    bridge_process: subprocess.Popen[bytes] | None = None
    bridge_url = f"http://{args.bridge_host}:{args.bridge_port}"
    encountered_error = False
    interrupted = False

    try:
        bridge_process = start_bridge(
            config_path,
            args.model,
            args.ollama_host,
            args.bridge_host,
            args.bridge_port,
            args.client_path,
        )
        wait_for_health(args.bridge_host, args.bridge_port)
        output = call_bridge_direct(
            bridge_url,
            args.model,
            capture_path,
            assumed_duration,
            args.prompt_type,
        )
        print("\n=== Model Response ===")
        print(output)
    except KeyboardInterrupt:
        interrupted = True
        print("\n[warn] Interrupted by user; stopping services…")
        return
    except Exception:
        encountered_error = True
        raise
    finally:
        if bridge_process and bridge_process.poll() is None:
            if args.keep_bridge and not encountered_error and not interrupted:
                print("[info] Leaving bridge running (pid %d)" % bridge_process.pid)
            else:
                print("[info] Stopping bridge …")
                stop_bridge(bridge_process)

if __name__ == "__main__":
    main()
