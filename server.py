"""
Minimal Python MCP server for Claude Desktop (stdio transport).

Tools provided:
- echo(text): echoes the text
- add(a, b): adds two numbers
- get_time(tz): returns ISO timestamp in local time or UTC

Also exposes:
- Resource: greeting://{name}
- Prompt: Friendly Greeting

Run directly (stdio):
    python server.py

Dev with MCP Inspector (after installing mcp[cli]):
    mcp dev server.py

Install into Claude Desktop automatically:
    mcp install server.py --name "TestMCPPython"
"""

from __future__ import annotations

import datetime as _dt
from collections import Counter
from typing import TypedDict
import asyncio as _asyncio

from mcp.server.fastmcp import Context, FastMCP
from mcp.server.session import ServerSession


# Create the FastMCP server instance
mcp = FastMCP(
    name="TestMCPPython",
    instructions=(
        "A tiny demo MCP server written in Python. It has a few example tools, "
        "a resource, and a prompt."
    ),
)







@mcp.resource("greeting://{name}")
def greeting(name: str) -> str:
    """A simple resource returning a greeting for the provided name."""

    return f"Hello, {name}!"


@mcp.prompt(title="Friendly Greeting")
def friendly_greeting(name: str) -> str:
    """Return a prompt template to generate a friendly greeting."""

    return f"Please write a short, friendly greeting for {name}."


# -------- PCAP analysis (pyshark) --------
class Talker(TypedDict):
    ip: str
    count: int


class PcapAnalysis(TypedDict):
    total_packets: int
    protocols: dict[str, int]
    top_sources: list[dict[str, str | int]]
    top_destinations: list[dict[str, str | int]]


@mcp.tool()
async def analyze_pcap(
    file_path: str,
    display_filter: str | None = None,
    packet_limit: int = 200,
    progress_every: int = 500,
    ctx: Context[ServerSession, None] | None = None,
) -> PcapAnalysis:
    """Analyze a pcap file and return high-level stats.

    Requirements:
    - pyshark (installed via dependencies)
    - tshark available on PATH (install via Homebrew: `brew install wireshark`)

    Parameters:
    - file_path: Absolute or relative path to a .pcap or .pcapng file
    - display_filter: Optional Wireshark display filter (e.g., "tcp.port==443")
    - packet_limit: Max packets to inspect (soft cap, defaults to 200; max 10000)
    """

    import os

    # Import locally to avoid module error if the tool isn't used
    try:
        import pyshark  # type: ignore
    except Exception as e:  # pragma: no cover - environment dependent
        raise RuntimeError(
            "pyshark is not installed in the current environment. "
            "If using uv: `uv sync`\nIf using pip: `pip install pyshark`"
        ) from e

    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    # Clamp packet_limit
    if packet_limit <= 0:
        packet_limit = 1
    packet_limit = min(packet_limit, 10_000)

    loop = _asyncio.get_running_loop()

    def _worker() -> PcapAnalysis:
        total = 0
        proto_counter: Counter[str] = Counter()
        src_counter: Counter[str] = Counter()
        dst_counter: Counter[str] = Counter()

        # Prefer JSON parsing if available for speed; fall back otherwise
        capture_kwargs = {
            "display_filter": display_filter,
            "keep_packets": False,  # do not store frames in memory
        }
        try:
            capture_kwargs["use_json"] = True  # newer tshark/pyshark
        except Exception:
            pass

        try:
            cap = pyshark.FileCapture(file_path, **capture_kwargs)
        except Exception as e:  # Likely tshark missing or unsupported
            raise RuntimeError(
                "Failed to open pcap with pyshark. Ensure tshark is installed and on PATH.\n"
                "Install on macOS: `brew install wireshark`"
            ) from e

        try:
            for i, pkt in enumerate(cap):
                if i >= packet_limit:
                    break
                total += 1

                # Highest protocol layer label
                proto = getattr(pkt, "highest_layer", None) or "UNKNOWN"
                if isinstance(proto, str):
                    proto_counter[proto] += 1

                # Try IP then IPv6
                src = None
                dst = None
                if hasattr(pkt, "ip"):
                    src = getattr(pkt.ip, "src", None)
                    dst = getattr(pkt.ip, "dst", None)
                if (src is None or dst is None) and hasattr(pkt, "ipv6"):
                    src = src or getattr(pkt.ipv6, "src", None)
                    dst = dst or getattr(pkt.ipv6, "dst", None)

                if isinstance(src, str):
                    src_counter[src] += 1
                if isinstance(dst, str):
                    dst_counter[dst] += 1

                # Progress updates from the worker thread (thread-safe)
                if ctx and progress_every > 0 and (i + 1) % progress_every == 0:
                    try:
                        progress = min((i + 1) / float(packet_limit), 1.0)
                        _asyncio.run_coroutine_threadsafe(
                            ctx.report_progress(
                                progress=progress, total=1.0, message=f"Analyzed {i + 1} packets"
                            ),
                            loop,
                        )
                    except Exception:
                        pass
        finally:
            # Ensure capture is closed even on exceptions
            try:
                cap.close()
            except Exception:
                pass

        def top_n(counter: Counter[str], n: int = 10) -> list[dict[str, str | int]]:
            return [{"ip": str(ip), "count": cnt} for ip, cnt in counter.most_common(n)]

        return PcapAnalysis(
            total_packets=total,
            protocols=dict(proto_counter),
            top_sources=top_n(src_counter),
            top_destinations=top_n(dst_counter),
        )

    result = await _asyncio.to_thread(_worker)
    # Ensure a final 100% progress if context exists
    if ctx:
        try:
            await ctx.report_progress(progress=1.0, total=1.0, message="Analysis complete")
        except Exception:
            pass
    return result


class ProtocolCount(TypedDict):
    protocol: str
    count: int
    percentage: float


@mcp.tool()
async def top_protocols(
    file_path: str,
    display_filter: str | None = None,
    packet_limit: int = 5000,
    top_n: int = 10,
) -> list[ProtocolCount]:
    """Return most common highest-layer protocols with percentages.

    Uses the same fast path as `analyze_pcap` and clamps packet_limit to 10k.
    """

    import os
    try:
        import pyshark  # type: ignore
    except Exception as e:  # pragma: no cover
        raise RuntimeError(
            "pyshark is not installed. Install dependencies and ensure tshark is on PATH."
        ) from e

    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    if packet_limit <= 0:
        packet_limit = 1
    packet_limit = min(packet_limit, 10_000)

    def _worker() -> list[ProtocolCount]:
        total = 0
        proto_counter: Counter[str] = Counter()
        capture_kwargs = {"display_filter": display_filter, "keep_packets": False}
        try:
            capture_kwargs["use_json"] = True
        except Exception:
            pass

        cap = pyshark.FileCapture(file_path, **capture_kwargs)
        try:
            for i, pkt in enumerate(cap):
                if i >= packet_limit:
                    break
                total += 1
                proto = getattr(pkt, "highest_layer", None) or "UNKNOWN"
                if isinstance(proto, str):
                    proto_counter[proto] += 1
        finally:
            try:
                cap.close()
            except Exception:
                pass

        if total == 0:
            return []

        items = proto_counter.most_common(top_n)
        return [
            {
                "protocol": name,
                "count": cnt,
                "percentage": round((cnt / total) * 100.0, 2),
            }
            for name, cnt in items
        ]

    return await _asyncio.to_thread(_worker)


class TcpHandshakeStats(TypedDict):
    streams: int
    syn: int
    syn_ack: int
    ack: int
    complete_handshakes: int


@mcp.tool()
async def tcp_handshake_stats(
    file_path: str,
    display_filter: str | None = None,
    packet_limit: int = 10_000,
) -> TcpHandshakeStats:
    """Compute TCP handshake stats by scanning SYN/SYN-ACK/ACK flags.

    Heuristic per TCP stream:
    - Count packets with SYN (no ACK) as initial SYN
    - Count packets with SYN+ACK as handshake reply
    - Count first pure ACK following SYN+ACK as final ACK
    A stream is considered complete if all three are observed (order tolerant).
    """

    import os
    try:
        import pyshark  # type: ignore
    except Exception as e:  # pragma: no cover
        raise RuntimeError(
            "pyshark is not installed. Install dependencies and ensure tshark is on PATH."
        ) from e

    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    if packet_limit <= 0:
        packet_limit = 1
    packet_limit = min(packet_limit, 50_000)

    def _worker() -> TcpHandshakeStats:
        # tcp.stream id -> flags seen
        syn_seen: set[int] = set()
        syn_ack_seen: set[int] = set()
        ack_seen: set[int] = set()

        display = "tcp" if not display_filter else f"tcp && ({display_filter})"
        capture_kwargs = {"display_filter": display, "keep_packets": False}
        try:
            capture_kwargs["use_json"] = True
        except Exception:
            pass

        cap = pyshark.FileCapture(file_path, **capture_kwargs)
        try:
            for i, pkt in enumerate(cap):
                if i >= packet_limit:
                    break
                if not hasattr(pkt, "tcp"):
                    continue
                tcp = pkt.tcp
                # Stream id can be missing; skip those
                try:
                    stream_id = int(getattr(tcp, "stream", "-1"))
                except Exception:
                    continue
                if stream_id < 0:
                    continue

                # Flags: using boolean fields when available
                # Fallback to flags string if needed
                syn = getattr(tcp, "flags_syn", None)
                ack = getattr(tcp, "flags_ack", None)

                try:
                    syn_b = bool(int(syn)) if syn is not None else False
                    ack_b = bool(int(ack)) if ack is not None else False
                except Exception:
                    syn_b = "S" in getattr(tcp, "flags_str", "")
                    ack_b = "A" in getattr(tcp, "flags_str", "")

                if syn_b and not ack_b:
                    syn_seen.add(stream_id)
                elif syn_b and ack_b:
                    syn_ack_seen.add(stream_id)
                elif (not syn_b) and ack_b:
                    # First pure ACK counts; we only track the fact it's seen
                    ack_seen.add(stream_id)
        finally:
            try:
                cap.close()
            except Exception:
                pass

        streams = len(syn_seen | syn_ack_seen | ack_seen)
        complete = len([sid for sid in syn_seen if sid in syn_ack_seen and sid in ack_seen])

        return TcpHandshakeStats(
            streams=streams,
            syn=len(syn_seen),
            syn_ack=len(syn_ack_seen),
            ack=len(ack_seen),
            complete_handshakes=complete,
        )

    return await _asyncio.to_thread(_worker)


class PortCount(TypedDict):
    port: int
    count: int
    percentage: float


class TopPorts(TypedDict):
    total_packets: int
    analyzed_packets: int
    tcp: list[dict[str, int | float]]
    udp: list[dict[str, int | float]]


@mcp.tool()
async def top_ports(
    file_path: str,
    display_filter: str | None = None,
    packet_limit: int = 10_000,
    top_n: int = 20,
    ctx: Context[ServerSession, None] | None = None,
) -> TopPorts:
    """Compute most common TCP/UDP destination ports with progress.

    Percentages are computed per-protocol (e.g., TCP port counts over total TCP packets seen).
    Requires pyshark and tshark (install on macOS: `brew install wireshark`).
    """

    import os
    try:
        import pyshark  # type: ignore
    except Exception as e:  # pragma: no cover
        raise RuntimeError(
            "pyshark is not installed. Install dependencies and ensure tshark is on PATH."
        ) from e

    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    if packet_limit <= 0:
        packet_limit = 1
    packet_limit = min(packet_limit, 50_000)
    if top_n <= 0:
        top_n = 10
    top_n = min(top_n, 100)

    from collections import Counter as _Counter

    loop = _asyncio.get_running_loop()

    def _worker() -> TopPorts:
        total = 0
        analyzed = 0
        tcp_counter: _Counter[int] = _Counter()
        udp_counter: _Counter[int] = _Counter()

        base_filter = "tcp or udp"
        if display_filter:
            display = f"({base_filter}) and ({display_filter})"
        else:
            display = base_filter

        capture_kwargs = {"display_filter": display, "keep_packets": False}
        try:
            capture_kwargs["use_json"] = True
        except Exception:
            pass

        cap = pyshark.FileCapture(file_path, **capture_kwargs)
        try:
            # Iterate and periodically report progress if ctx is available
            for i, pkt in enumerate(cap):
                if i >= packet_limit:
                    break
                total += 1

                got_any = False
                # TCP destination port
                if hasattr(pkt, "tcp"):
                    try:
                        dport = getattr(pkt.tcp, "dstport", None)
                        if dport is None:
                            dport = getattr(pkt.tcp, "port", None)
                        if dport is not None:
                            tcp_counter[int(dport)] += 1
                            got_any = True
                    except Exception:
                        pass

                # UDP destination port
                if hasattr(pkt, "udp"):
                    try:
                        dport = getattr(pkt.udp, "dstport", None)
                        if dport is None:
                            dport = getattr(pkt.udp, "port", None)
                        if dport is not None:
                            udp_counter[int(dport)] += 1
                            got_any = True
                    except Exception:
                        pass

                if got_any:
                    analyzed += 1

                if ctx and (i + 1) % 500 == 0:
                    # Report progress against the requested limit (not file size)
                    try:
                        progress = min((i + 1) / float(packet_limit), 1.0)
                        _asyncio.run_coroutine_threadsafe(
                            ctx.report_progress(
                                progress=progress, total=1.0, message=f"Scanned {i + 1} packets"
                            ),
                            loop,
                        )
                    except Exception:
                        pass
        finally:
            try:
                cap.close()
            except Exception:
                pass

        def top_list(counter: _Counter[int]) -> list[dict[str, int | float]]:
            if not counter:
                return []
            proto_total = sum(counter.values())
            return [
                {
                    "port": port,
                    "count": cnt,
                    "percentage": round((cnt / proto_total) * 100.0, 2),
                }
                for port, cnt in counter.most_common(top_n)
            ]

        return TopPorts(
            total_packets=total,
            analyzed_packets=analyzed,
            tcp=top_list(tcp_counter),
            udp=top_list(udp_counter),
        )

    result = await _asyncio.to_thread(_worker)
    if ctx:
        try:
            await ctx.report_progress(progress=1.0, total=1.0, message="Port scan complete")
        except Exception:
            pass
    return result


def main() -> None:
    """Run the server using stdio (works with Claude Desktop)."""

    # Defaults to stdio transport when executed directly
    mcp.run()


if __name__ == "__main__":
    main()
