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
from typing import TypedDict, Any
import asyncio as _asyncio

from mcp.server.fastmcp import Context, FastMCP
from mcp.server.session import ServerSession
import sys as _sys
import shutil as _shutil


# Create the FastMCP server instance
mcp = FastMCP(
    name="TestMCPPython",
    instructions=(
        "A tiny demo MCP server written in Python. It has a few example tools, "
        "a resource, and a prompt."
    ),
)
def _log(msg: str) -> None:
    try:
        print(f"[mcppython] {msg}", file=_sys.stderr)
    except Exception:
        pass

_log("Starting server module load")


def _prepare_thread_event_loop() -> None:
    """Ensure a usable asyncio event loop in the current (worker) thread.

    On Windows in some host environments (e.g. Claude Desktop sandbox) threads spawned via
    asyncio.to_thread may not have a default loop, and some libraries (pyshark / asyncio
    utilities they indirectly use) call get_event_loop(). This helper creates and sets a
    new loop if absent. It is a no-op if a loop already exists.
    """
    try:
        import asyncio
        try:
            asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
    except Exception:
        pass








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
        _prepare_thread_event_loop()
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
        _prepare_thread_event_loop()
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
        _prepare_thread_event_loop()
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
        _prepare_thread_event_loop()
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


# -------- Deeper protocol and expert analysis --------

class ExpertInfoSummary(TypedDict):
    total_packets: int
    expert_items: int
    severities: dict[str, int]
    top_messages: list[dict[str, int | str]]


@mcp.tool()
async def expert_info_summary(
    file_path: str,
    display_filter: str | None = None,
    packet_limit: int = 10_000,
    top_n: int = 20,
    progress_every: int = 1000,
    ctx: Context[ServerSession, None] | None = None,
) -> ExpertInfoSummary:
    """Scan packets for Wireshark Expert Info messages and summarize.

    Returns counts by severity and the most common expert messages.
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

    def _as_list(layer: object, name: str) -> list[str]:
        # Try *_all list, then single attribute, else empty
        try:
            vals = getattr(layer, f"{name}_all", None)
            if vals is None:
                val = getattr(layer, name, None)
                if val is None:
                    return []
                return [str(val)]
            # pyshark may return a list-like object; ensure list[str]
            return [str(v) for v in list(vals)]
        except Exception:
            return []

    loop = _asyncio.get_running_loop()

    def _worker() -> ExpertInfoSummary:
        _prepare_thread_event_loop()
        total = 0
        expert_items = 0
        from collections import Counter as _Counter
        sev_counter: _Counter[str] = _Counter()
        msg_counter: _Counter[str] = _Counter()

        display = display_filter  # allow user-provided filter to narrow scope
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
                total += 1

                # Iterate layers to find expert layer; robustly handle naming
                for layer in getattr(pkt, "layers", []) or []:
                    try:
                        lname = getattr(layer, "layer_name", "")
                    except Exception:
                        lname = ""
                    if lname != "expert":
                        continue

                    msgs = _as_list(layer, "message")
                    sevs = _as_list(layer, "severity")
                    # Some tshark versions expose severity as numeric; keep stringified
                    if msgs:
                        expert_items += len(msgs)
                        for m in msgs:
                            msg_counter[m] += 1
                    if sevs:
                        for s in sevs:
                            sev_counter[s] += 1
                # Progress
                if ctx and progress_every > 0 and (i + 1) % progress_every == 0:
                    try:
                        progress = min((i + 1) / float(packet_limit), 1.0)
                        _asyncio.run_coroutine_threadsafe(
                            ctx.report_progress(
                                progress=progress,
                                total=1.0,
                                message=f"Scanned {i + 1} packets for expert info",
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

        top_msgs: list[dict[str, int | str]] = [
            {"message": msg, "count": cnt} for msg, cnt in msg_counter.most_common(top_n)
        ]

        # Convert severities
        return ExpertInfoSummary(
            total_packets=total,
            expert_items=expert_items,
            severities=dict(sev_counter),
            top_messages=top_msgs,
        )

    result = await _asyncio.to_thread(_worker)
    if ctx:
        try:
            await ctx.report_progress(progress=1.0, total=1.0, message="Expert info summary complete")
        except Exception:
            pass
    return result


# -------- Cleartext payload string extraction --------

class PayloadStringsResult(TypedDict):
    total_packets: int
    payload_packets: int
    total_strings: int
    encodings: dict[str, int]
    top_strings: list[dict[str, int | str]]


@mcp.tool()
async def extract_payload_strings(
    file_path: str,
    display_filter: str | None = None,
    packet_limit: int = 20_000,
    min_length: int = 6,
    top_n: int = 50,
    exclude_tls: bool = True,
    include_utf8: bool = True,
    regex_filter: str | None = None,
    case_insensitive: bool = True,
    max_strings: int | None = None,
    progress_every: int = 1000,
    ctx: Context[ServerSession, None] | None = None,
) -> PayloadStringsResult:
    """Extract cleartext strings from non-encrypted payload data (ASCII, UTF-16 LE/BE).

    This scans packet payload bytes from the Wireshark `data` layer and extracts sequences
    of printable characters. It avoids TLS by default (can be disabled), and returns a
    summary of the most frequent strings and encodings detected.
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
    if min_length <= 1:
        min_length = 2
    if top_n <= 0:
        top_n = 10
    top_n = min(top_n, 200)

    loop = _asyncio.get_running_loop()

    def _hex_to_bytes(s: str) -> bytes:
        # pyshark may give hex separated by ':' or none
        h = s.replace(":", "").strip()
        try:
            return bytes.fromhex(h)
        except Exception:
            return b""

    def _worker() -> PayloadStringsResult:
        _prepare_thread_event_loop()
        import re
        from collections import Counter as _Counter

        total = 0
        payload_pkts = 0
        total_strings = 0
        enc_counter: _Counter[str] = _Counter()
        str_counter: _Counter[tuple[str, str]] = _Counter()  # (text, encoding) -> count

        # Build display filter
        parts = ["data"]
        if exclude_tls:
            parts.append("not tls")
        if display_filter:
            parts.append(f"({display_filter})")
        display = " and ".join(parts)

        capture_kwargs = {"display_filter": display, "keep_packets": False}
        try:
            capture_kwargs["use_json"] = True
        except Exception:
            pass

        cap = pyshark.FileCapture(file_path, **capture_kwargs)
        try:
            # Precompile regexes for efficiency
            ascii_re = re.compile(rb"[ -~]{%d,}" % (min_length,))
            wide_le_re = re.compile(rb"(?:(?:[ -~]\x00){%d,})" % (min_length,))
            wide_be_re = re.compile(rb"(?:(?:\x00[ -~]){%d,})" % (min_length,))
            utf8_re = re.compile(rb"(?:[ -~]|\\xc2[\\xa0-\\xbf]|\\xe0[\\xa0-\\xbf].|\\xe1..|\\xe2..|\\xe3..|\\xe4..|\\xe5..|\\xe6..|\\xe7..|\\xe8..|\\xe9..|\\xea..|\\xeb..|\\xec..|\\xed..|\\xee..|\\xef..){%d,}" % (min_length,)) if include_utf8 else None

            # Optional post-filter for discovered strings
            compiled_filter = None
            if regex_filter:
                flags = re.IGNORECASE if case_insensitive else 0
                try:
                    compiled_filter = re.compile(regex_filter, flags)
                except Exception:
                    compiled_filter = None

            for i, pkt in enumerate(cap):
                if i >= packet_limit:
                    break
                total += 1

                if not hasattr(pkt, "data"):
                    # No raw data layer
                    if ctx and progress_every > 0 and (i + 1) % progress_every == 0:
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
                    continue

                data_hex = getattr(pkt.data, "data", None)
                if not data_hex:
                    continue
                b = _hex_to_bytes(str(data_hex))
                if not b:
                    continue
                payload_pkts += 1

                # ASCII strings
                for m in ascii_re.finditer(b):
                    try:
                        text = m.group().decode("ascii", errors="ignore")
                    except Exception:
                        continue
                    if not text:
                        continue
                    if compiled_filter and not compiled_filter.search(text):
                        pass
                    else:
                        str_counter[(text, "ascii")] += 1
                    enc_counter["ascii"] += 1
                    total_strings += 1

                # UTF-16 LE (wide) strings: pattern a\x00b\x00...
                for m in wide_le_re.finditer(b):
                    raw = m.group()
                    # take every other byte (even indices)
                    narrow = raw[0::2]
                    try:
                        text = narrow.decode("ascii", errors="ignore")
                    except Exception:
                        continue
                    if not text:
                        continue
                    if compiled_filter and not compiled_filter.search(text):
                        pass
                    else:
                        str_counter[(text, "utf-16le") ] += 1
                    enc_counter["utf-16le"] += 1
                    total_strings += 1

                # UTF-16 BE strings: pattern \x00a\x00b...
                for m in wide_be_re.finditer(b):
                    raw = m.group()
                    narrow = raw[1::2]
                    try:
                        text = narrow.decode("ascii", errors="ignore")
                    except Exception:
                        continue
                    if not text:
                        continue
                    if compiled_filter and not compiled_filter.search(text):
                        pass
                    else:
                        str_counter[(text, "utf-16be")] += 1
                    enc_counter["utf-16be"] += 1
                    total_strings += 1

                # UTF-8 strings (optional)
                if utf8_re is not None:
                    for m in utf8_re.finditer(b):
                        try:
                            text = m.group().decode("utf-8", errors="ignore")
                        except Exception:
                            continue
                        if not text:
                            continue
                        if compiled_filter and not compiled_filter.search(text):
                            continue
                        str_counter[(text, "utf-8")] += 1
                        enc_counter["utf-8"] += 1
                        total_strings += 1

                # Progress
                if ctx and progress_every > 0 and (i + 1) % progress_every == 0:
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

        limit = top_n if (max_strings is None) else max_strings
        items = str_counter.most_common(limit)
        top_list: list[dict[str, int | str]] = [
            {"text": t, "encoding": enc, "count": cnt}
            for (t, enc), cnt in items[:top_n]
        ]

        return PayloadStringsResult(
            total_packets=total,
            payload_packets=payload_pkts,
            total_strings=total_strings,
            encodings=dict(enc_counter),
            top_strings=top_list,
        )

    result = await _asyncio.to_thread(_worker)
    if ctx:
        try:
            await ctx.report_progress(progress=1.0, total=1.0, message="Payload string extraction complete")
        except Exception:
            pass
    return result


class HTTPStats(TypedDict):
    total_packets: int
    requests: int
    responses: int
    methods: dict[str, int]
    status_codes: dict[str, int]
    top_hosts: list[dict[str, int | str]]


@mcp.tool()
async def http_stats(
    file_path: str,
    display_filter: str | None = None,
    packet_limit: int = 20_000,
    top_n: int = 20,
    progress_every: int = 1000,
    ctx: Context[ServerSession, None] | None = None,
) -> HTTPStats:
    """Summarize HTTP traffic: methods, status codes, and hostnames."""

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

    loop = _asyncio.get_running_loop()

    def _worker() -> HTTPStats:
        _prepare_thread_event_loop()
        total = 0
        reqs = 0
        resps = 0
        from collections import Counter as _Counter
        method_counter: _Counter[str] = _Counter()
        status_counter: _Counter[str] = _Counter()
        host_counter: _Counter[str] = _Counter()

        display = f"http" if not display_filter else f"http and ({display_filter})"
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
                total += 1
                if not hasattr(pkt, "http"):
                    continue
                http = pkt.http
                # Request method
                try:
                    method = getattr(http, "request_method", None)
                    if method:
                        method_counter[str(method)] += 1
                        reqs += 1
                except Exception:
                    pass
                # Progress
                if ctx and progress_every > 0 and (i + 1) % progress_every == 0:
                    try:
                        progress = min((i + 1) / float(packet_limit), 1.0)
                        _asyncio.run_coroutine_threadsafe(
                            ctx.report_progress(
                                progress=progress, total=1.0, message=f"Scanned {i + 1} HTTP packets"
                            ),
                            loop,
                        )
                    except Exception:
                        pass
                # Status code
                try:
                    code = getattr(http, "response_code", None)
                    if code is None:
                        code = getattr(http, "status_code", None)
                    if code:
                        status_counter[str(code)] += 1
                        resps += 1
                except Exception:
                    pass
                # Host header
                try:
                    host = getattr(http, "host", None)
                    if host:
                        host_counter[str(host)] += 1
                except Exception:
                    pass
        finally:
            try:
                cap.close()
            except Exception:
                pass

        top_hosts: list[dict[str, int | str]] = [
            {"host": name, "count": cnt} for name, cnt in host_counter.most_common(top_n)
        ]
        return HTTPStats(
            total_packets=total,
            requests=reqs,
            responses=resps,
            methods=dict(method_counter),
            status_codes=dict(status_counter),
            top_hosts=top_hosts,
        )

    result = await _asyncio.to_thread(_worker)
    if ctx:
        try:
            await ctx.report_progress(progress=1.0, total=1.0, message="HTTP stats complete")
        except Exception:
            pass
    return result


class DNSStats(TypedDict):
    total_packets: int
    queries: int
    responses: int
    qtypes: dict[str, int]
    rcodes: dict[str, int]
    top_query_names: list[dict[str, int | str]]


@mcp.tool()
async def dns_stats(
    file_path: str,
    display_filter: str | None = None,
    packet_limit: int = 20_000,
    top_n: int = 20,
    progress_every: int = 1000,
    ctx: Context[ServerSession, None] | None = None,
) -> DNSStats:
    """Summarize DNS traffic: query types, response codes, and top names."""

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

    loop = _asyncio.get_running_loop()

    def _worker() -> DNSStats:
        _prepare_thread_event_loop()
        total = 0
        q = 0
        r = 0
        from collections import Counter as _Counter
        qtype_counter: _Counter[str] = _Counter()
        rcode_counter: _Counter[str] = _Counter()
        name_counter: _Counter[str] = _Counter()

        display = f"dns" if not display_filter else f"dns and ({display_filter})"
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
                total += 1
                if not hasattr(pkt, "dns"):
                    continue
                dns = pkt.dns
                # Query vs response
                try:
                    qr = getattr(dns, "flags_response", None)
                    qr_b = None
                    if qr is not None:
                        try:
                            qr_b = bool(int(qr))
                        except Exception:
                            qr_b = str(qr).lower() in ("1", "true")
                    if qr_b is False:
                        q += 1
                    elif qr_b is True:
                        r += 1
                except Exception:
                    pass
                # Progress
                if ctx and progress_every > 0 and (i + 1) % progress_every == 0:
                    try:
                        progress = min((i + 1) / float(packet_limit), 1.0)
                        _asyncio.run_coroutine_threadsafe(
                            ctx.report_progress(
                                progress=progress, total=1.0, message=f"Scanned {i + 1} DNS packets"
                            ),
                            loop,
                        )
                    except Exception:
                        pass

                # Query type and name
                try:
                    qtype = getattr(dns, "qry_type", None)
                    if qtype:
                        qtype_counter[str(qtype)] += 1
                except Exception:
                    pass
                try:
                    qname = getattr(dns, "qry_name", None)
                    if qname:
                        name_counter[str(qname)] += 1
                except Exception:
                    pass

                # Response code
                try:
                    rcode = getattr(dns, "flags_rcode", None)
                    if rcode is None:
                        rcode = getattr(dns, "rcode", None)
                    if rcode is not None:
                        rcode_counter[str(rcode)] += 1
                except Exception:
                    pass
        finally:
            try:
                cap.close()
            except Exception:
                pass

        top_names: list[dict[str, int | str]] = [
            {"name": n, "count": c} for n, c in name_counter.most_common(top_n)
        ]
        return DNSStats(
            total_packets=total,
            queries=q,
            responses=r,
            qtypes=dict(qtype_counter),
            rcodes=dict(rcode_counter),
            top_query_names=top_names,
        )

    result = await _asyncio.to_thread(_worker)
    if ctx:
        try:
            await ctx.report_progress(progress=1.0, total=1.0, message="DNS stats complete")
        except Exception:
            pass
    return result


class TLSStats(TypedDict):
    total_packets: int
    handshakes: int
    versions: dict[str, int]
    cipher_suites: dict[str, int]
    top_sni: list[dict[str, int | str]]


@mcp.tool()
async def tls_stats(
    file_path: str,
    display_filter: str | None = None,
    packet_limit: int = 20_000,
    top_n: int = 20,
    progress_every: int = 1000,
    ctx: Context[ServerSession, None] | None = None,
) -> TLSStats:
    """Summarize TLS traffic: versions, cipher suites, and SNI hostnames."""

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

    def _as_list(layer: object, name: str) -> list[str]:
        try:
            vals = getattr(layer, f"{name}_all", None)
            if vals is None:
                val = getattr(layer, name, None)
                if val is None:
                    return []
                return [str(val)]
            return [str(v) for v in list(vals)]
        except Exception:
            return []

    loop = _asyncio.get_running_loop()

    def _worker() -> TLSStats:
        _prepare_thread_event_loop()
        total = 0
        handshakes = 0
        from collections import Counter as _Counter
        ver_counter: _Counter[str] = _Counter()
        cs_counter: _Counter[str] = _Counter()
        sni_counter: _Counter[str] = _Counter()

        display = f"tls" if not display_filter else f"tls and ({display_filter})"
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
                total += 1
                if not hasattr(pkt, "tls"):
                    # Older dissectors may use 'ssl'
                    if hasattr(pkt, "ssl"):
                        layer = pkt.ssl
                    else:
                        continue
                else:
                    layer = pkt.tls

                # TLS version (record or handshake)
                for attr in ("record_version", "handshake_version", "version"):
                    try:
                        val = getattr(layer, attr, None)
                        if val:
                            ver_counter[str(val)] += 1
                            break
                    except Exception:
                        pass

                # Cipher suites (ClientHello offers or ServerHello selected)
                for name in ("handshake_ciphersuite", "handshake_ciphersuite_all", "ciphersuite", "ciphersuite_all"):
                    vals = _as_list(layer, name)
                    for v in vals:
                        cs_counter[v] += 1

                # SNI (server name)
                for name in (
                    "handshake_extensions_server_name",
                    "extensions_server_name",
                    "server_name",
                ):
                    vals = _as_list(layer, name)
                    for v in vals:
                        sni_counter[v] += 1

                # Count handshake records
                try:
                    hstype = getattr(layer, "handshake_type", None)
                    if hstype:
                        handshakes += 1
                except Exception:
                    pass
                # Progress
                if ctx and progress_every > 0 and (i + 1) % progress_every == 0:
                    try:
                        progress = min((i + 1) / float(packet_limit), 1.0)
                        _asyncio.run_coroutine_threadsafe(
                            ctx.report_progress(
                                progress=progress, total=1.0, message=f"Scanned {i + 1} TLS packets"
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

        top_sni: list[dict[str, int | str]] = [
            {"sni": name, "count": cnt} for name, cnt in sni_counter.most_common(top_n)
        ]
        return TLSStats(
            total_packets=total,
            handshakes=handshakes,
            versions=dict(ver_counter),
            cipher_suites=dict(cs_counter),
            top_sni=top_sni,
        )

    result = await _asyncio.to_thread(_worker)
    if ctx:
        try:
            await ctx.report_progress(progress=1.0, total=1.0, message="TLS stats complete")
        except Exception:
            pass
    return result


# -------- Deep analyses: TCP, UDP, ICMP, DNS (deep), SSH --------

class TCPFlowStats(TypedDict):
    total_packets: int
    analyzed_packets: int
    streams: int
    syn: int
    syn_ack: int
    fin: int
    rst: int
    retransmissions: int
    out_of_order: int
    rtt_ms_min: float | None
    rtt_ms_avg: float | None
    rtt_ms_max: float | None
    top_src: list[dict[str, int | str]]
    top_dst: list[dict[str, int | str]]
    top_flows_by_packets: list[dict[str, int | str]]
    top_flows_by_bytes: list[dict[str, int | str]]


@mcp.tool()
async def tcp_flow_stats(
    file_path: str,
    display_filter: str | None = None,
    packet_limit: int = 50_000,
    top_n: int = 20,
    progress_every: int = 1000,
    ctx: Context[ServerSession, None] | None = None,
) -> TCPFlowStats:
    """Deep TCP analysis per stream: counts, retransmissions, and top flows.

    Uses `tcp.stream` IDs where available to aggregate packets and bytes.
    Bytes are estimated from `tcp.len` (application payload length); if missing, 0 bytes are added.
    """

    import os
    try:
        import pyshark  # type: ignore
    except Exception as e:
        raise RuntimeError(
            "pyshark is not installed. Install dependencies and ensure tshark is on PATH."
        ) from e

    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    if packet_limit <= 0:
        packet_limit = 1
    packet_limit = min(packet_limit, 200_000)
    if top_n <= 0:
        top_n = 10
    top_n = min(top_n, 200)

    from collections import Counter as _Counter, defaultdict as _defaultdict
    loop = _asyncio.get_running_loop()

    def _worker() -> TCPFlowStats:
        _prepare_thread_event_loop()
        total = 0
        analyzed = 0
        syn = syn_ack = fin = rst = 0
        retrans = ooo = 0

        src_counter: _Counter[str] = _Counter()
        dst_counter: _Counter[str] = _Counter()

        # stream_id -> stats
        flows: dict[int, dict[str, int | str]] = {}
        rtts_ms: list[float] = []

        base_filter = "tcp"
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
            for i, pkt in enumerate(cap):
                if i >= packet_limit:
                    break
                total += 1
                if not hasattr(pkt, "tcp"):
                    continue
                analyzed += 1
                tcp = pkt.tcp

                # Talkers
                src = None
                dst = None
                try:
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
                except Exception:
                    pass

                # Stream id and ports
                try:
                    stream_id = int(getattr(tcp, "stream", "-1"))
                except Exception:
                    stream_id = -1
                try:
                    sport = int(getattr(tcp, "srcport", getattr(tcp, "port", 0)) or 0)
                except Exception:
                    sport = 0
                try:
                    dport = int(getattr(tcp, "dstport", getattr(tcp, "port", 0)) or 0)
                except Exception:
                    dport = 0

                # Flags
                try:
                    f_syn = bool(int(getattr(tcp, "flags_syn", "0")))
                except Exception:
                    f_syn = "S" in getattr(tcp, "flags_str", "")
                try:
                    f_ack = bool(int(getattr(tcp, "flags_ack", "0")))
                except Exception:
                    f_ack = "A" in getattr(tcp, "flags_str", "")
                try:
                    f_fin = bool(int(getattr(tcp, "flags_fin", "0")))
                except Exception:
                    f_fin = "F" in getattr(tcp, "flags_str", "")
                try:
                    f_rst = bool(int(getattr(tcp, "flags_reset", "0")))
                except Exception:
                    f_rst = "R" in getattr(tcp, "flags_str", "")

                if f_syn and not f_ack:
                    syn += 1
                elif f_syn and f_ack:
                    syn_ack += 1
                if f_fin:
                    fin += 1
                if f_rst:
                    rst += 1

                # Analysis flags
                if getattr(tcp, "analysis_retransmission", None) is not None:
                    retrans += 1
                if getattr(tcp, "analysis_out_of_order", None) is not None:
                    ooo += 1

                # Bytes from tcp.len (payload length)
                try:
                    b = int(getattr(tcp, "len", 0) or 0)
                except Exception:
                    b = 0

                # Record per-flow
                key = stream_id if stream_id >= 0 else i  # fallback unique key
                st = flows.get(key)
                if st is None:
                    st = {
                        "stream": stream_id if stream_id >= 0 else -1,
                        "src": str(src) if isinstance(src, str) else "",
                        "sport": sport,
                        "dst": str(dst) if isinstance(dst, str) else "",
                        "dport": dport,
                        "packets": 0,
                        "bytes": 0,
                        "fwd_packets": 0,
                        "fwd_bytes": 0,
                        "rev_packets": 0,
                        "rev_bytes": 0,
                        "retransmissions": 0,
                        "out_of_order": 0,
                    }
                    flows[key] = st
                st["packets"] = int(st.get("packets", 0)) + 1
                st["bytes"] = int(st.get("bytes", 0)) + b

                # Direction: compare tuple (src, sport) vs stored
                try:
                    pkt_src = str(src) if isinstance(src, str) else ""
                    pkt_dst = str(dst) if isinstance(dst, str) else ""
                    if pkt_src == st.get("src") and sport == int(st.get("sport", 0)):
                        st["fwd_packets"] = int(st.get("fwd_packets", 0)) + 1
                        st["fwd_bytes"] = int(st.get("fwd_bytes", 0)) + b
                    elif pkt_dst == st.get("src") and dport == int(st.get("sport", 0)):
                        # Flow may have been seen in reverse first; treat as fwd when matches src:port of first
                        st["fwd_packets"] = int(st.get("fwd_packets", 0)) + 1
                        st["fwd_bytes"] = int(st.get("fwd_bytes", 0)) + b
                    else:
                        st["rev_packets"] = int(st.get("rev_packets", 0)) + 1
                        st["rev_bytes"] = int(st.get("rev_bytes", 0)) + b
                except Exception:
                    pass

                # Progress
                if ctx and progress_every > 0 and (i + 1) % progress_every == 0:
                    try:
                        progress = min((i + 1) / float(packet_limit), 1.0)
                        _asyncio.run_coroutine_threadsafe(
                            ctx.report_progress(
                                progress=progress, total=1.0, message=f"Scanned {i + 1} TCP packets"
                            ),
                            loop,
                        )
                    except Exception:
                        pass
                # Per-flow analysis counters
                try:
                    if getattr(tcp, "analysis_retransmission", None) is not None:
                        st["retransmissions"] = int(st.get("retransmissions", 0)) + 1
                    if getattr(tcp, "analysis_out_of_order", None) is not None:
                        st["out_of_order"] = int(st.get("out_of_order", 0)) + 1
                except Exception:
                    pass

                # RTT (tcp.analysis.ack_rtt) seconds -> ms
                try:
                    rtt = getattr(tcp, "analysis_ack_rtt", None)
                    if rtt is not None:
                        rtts_ms.append(float(str(rtt)) * 1000.0)
                except Exception:
                    pass
        finally:
            try:
                cap.close()
            except Exception:
                pass

        def _top(counter: _Counter[str]) -> list[dict[str, int | str]]:
            return [
                {"ip": ip, "count": cnt}
                for ip, cnt in counter.most_common(top_n)
            ]

        flows_list = list(flows.values())
        top_by_packets = sorted(flows_list, key=lambda x: int(x.get("packets", 0)), reverse=True)[:top_n]
        top_by_bytes = sorted(flows_list, key=lambda x: int(x.get("bytes", 0)), reverse=True)[:top_n]

        # Overall RTT stats
        if rtts_ms:
            rtt_min = min(rtts_ms)
            rtt_max = max(rtts_ms)
            rtt_avg = sum(rtts_ms) / len(rtts_ms)
        else:
            rtt_min = rtt_max = rtt_avg = None

        return TCPFlowStats(
            total_packets=total,
            analyzed_packets=analyzed,
            streams=len(flows),
            syn=syn,
            syn_ack=syn_ack,
            fin=fin,
            rst=rst,
            retransmissions=retrans,
            out_of_order=ooo,
            rtt_ms_min=rtt_min,
            rtt_ms_avg=rtt_avg,
            rtt_ms_max=rtt_max,
            top_src=_top(src_counter),
            top_dst=_top(dst_counter),
            top_flows_by_packets=top_by_packets,
            top_flows_by_bytes=top_by_bytes,
        )

    result = await _asyncio.to_thread(_worker)
    if ctx:
        try:
            await ctx.report_progress(progress=1.0, total=1.0, message="TCP flow stats complete")
        except Exception:
            pass
    return result


class UDPFlowStats(TypedDict):
    total_packets: int
    analyzed_packets: int
    flows: int
    top_src: list[dict[str, int | str]]
    top_dst: list[dict[str, int | str]]
    top_flows_by_packets: list[dict[str, int | str]]
    top_flows_by_bytes: list[dict[str, int | str]]


@mcp.tool()
async def udp_flow_stats(
    file_path: str,
    display_filter: str | None = None,
    packet_limit: int = 50_000,
    top_n: int = 20,
    progress_every: int = 1000,
    ctx: Context[ServerSession, None] | None = None,
) -> UDPFlowStats:
    """Analyze UDP flows (5-tuple) with packet and byte counts and top talkers."""

    import os
    try:
        import pyshark  # type: ignore
    except Exception as e:
        raise RuntimeError(
            "pyshark is not installed. Install dependencies and ensure tshark is on PATH."
        ) from e

    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    if packet_limit <= 0:
        packet_limit = 1
    packet_limit = min(packet_limit, 200_000)
    if top_n <= 0:
        top_n = 10
    top_n = min(top_n, 200)

    from collections import Counter as _Counter
    loop = _asyncio.get_running_loop()

    def _worker() -> UDPFlowStats:
        _prepare_thread_event_loop()
        total = 0
        analyzed = 0
        src_counter: _Counter[str] = _Counter()
        dst_counter: _Counter[str] = _Counter()
        flows: dict[tuple[str, int, str, int], dict[str, int | str]] = {}

        base_filter = "udp"
        display = f"({base_filter}) and ({display_filter})" if display_filter else base_filter
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
                total += 1
                if not hasattr(pkt, "udp"):
                    continue
                analyzed += 1

                # IPs
                src = None
                dst = None
                try:
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
                except Exception:
                    pass

                # Ports
                udp = pkt.udp
                try:
                    sport = int(getattr(udp, "srcport", getattr(udp, "port", 0)) or 0)
                except Exception:
                    sport = 0
                try:
                    dport = int(getattr(udp, "dstport", getattr(udp, "port", 0)) or 0)
                except Exception:
                    dport = 0

                # Bytes (udp.length includes header+data). We approximate using udp.length.
                try:
                    b = int(getattr(udp, "length", 0) or 0)
                except Exception:
                    b = 0

                key = (str(src) if isinstance(src, str) else "", sport, str(dst) if isinstance(dst, str) else "", dport)
                st = flows.get(key)
                if st is None:
                    st = {
                        "src": key[0],
                        "sport": sport,
                        "dst": key[2],
                        "dport": dport,
                        "packets": 0,
                        "bytes": 0,
                    }
                    flows[key] = st
                st["packets"] = int(st.get("packets", 0)) + 1
                st["bytes"] = int(st.get("bytes", 0)) + b

                # Progress
                if ctx and progress_every > 0 and (i + 1) % progress_every == 0:
                    try:
                        progress = min((i + 1) / float(packet_limit), 1.0)
                        _asyncio.run_coroutine_threadsafe(
                            ctx.report_progress(
                                progress=progress, total=1.0, message=f"Scanned {i + 1} UDP packets"
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

        def _top(counter: _Counter[str]) -> list[dict[str, int | str]]:
            return [{"ip": ip, "count": cnt} for ip, cnt in counter.most_common(top_n)]

        flows_list = list(flows.values())
        top_by_packets = sorted(flows_list, key=lambda x: int(x.get("packets", 0)), reverse=True)[:top_n]
        top_by_bytes = sorted(flows_list, key=lambda x: int(x.get("bytes", 0)), reverse=True)[:top_n]

        return UDPFlowStats(
            total_packets=total,
            analyzed_packets=analyzed,
            flows=len(flows),
            top_src=_top(src_counter),
            top_dst=_top(dst_counter),
            top_flows_by_packets=top_by_packets,
            top_flows_by_bytes=top_by_bytes,
        )

    result = await _asyncio.to_thread(_worker)
    if ctx:
        try:
            await ctx.report_progress(progress=1.0, total=1.0, message="UDP flow stats complete")
        except Exception:
            pass
    return result


class ICMPStats(TypedDict):
    total_packets: int
    icmpv4_packets: int
    icmpv6_packets: int
    types: dict[str, int]
    codes: dict[str, int]
    echo_request: int
    echo_reply: int
    unreachable: int
    time_exceeded: int
    redirects: int
    unique_sources: int
    unique_destinations: int


@mcp.tool()
async def icmp_stats(
    file_path: str,
    display_filter: str | None = None,
    packet_limit: int = 50_000,
    progress_every: int = 1000,
    ctx: Context[ServerSession, None] | None = None,
) -> ICMPStats:
    """Summarize ICMP/ICMPv6: counts by type/code, common events, and unique hosts."""

    import os
    try:
        import pyshark  # type: ignore
    except Exception as e:
        raise RuntimeError(
            "pyshark is not installed. Install dependencies and ensure tshark is on PATH."
        ) from e

    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    if packet_limit <= 0:
        packet_limit = 1
    packet_limit = min(packet_limit, 200_000)

    from collections import Counter as _Counter
    loop = _asyncio.get_running_loop()

    def _worker() -> ICMPStats:
        _prepare_thread_event_loop()
        total = 0
        v4 = 0
        v6 = 0
        types: _Counter[str] = _Counter()
        codes: _Counter[str] = _Counter()
        echo_req = echo_rep = 0
        unreach = time_exc = redirects = 0
        srcs: set[str] = set()
        dsts: set[str] = set()

        base = "icmp or icmpv6"
        display = f"({base}) and ({display_filter})" if display_filter else base
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
                total += 1

                # Track IP hosts
                src = None
                dst = None
                try:
                    if hasattr(pkt, "ip"):
                        src = getattr(pkt.ip, "src", None)
                        dst = getattr(pkt.ip, "dst", None)
                    if (src is None or dst is None) and hasattr(pkt, "ipv6"):
                        src = src or getattr(pkt.ipv6, "src", None)
                        dst = dst or getattr(pkt.ipv6, "dst", None)
                    if isinstance(src, str):
                        srcs.add(src)
                    if isinstance(dst, str):
                        dsts.add(dst)
                except Exception:
                    pass

                layer = None
                proto = ""
                if hasattr(pkt, "icmp"):
                    layer = pkt.icmp
                    v4 += 1
                    proto = "icmp"
                elif hasattr(pkt, "icmpv6"):
                    layer = pkt.icmpv6
                    v6 += 1
                    proto = "icmpv6"
                else:
                    continue

                # Type and code
                try:
                    t = getattr(layer, "type", None)
                    if t is not None:
                        types[f"{proto}:{t}"] += 1
                except Exception:
                    pass
                try:
                    c = getattr(layer, "code", None)
                    if c is not None:
                        codes[f"{proto}:{c}"] += 1
                except Exception:
                    pass

                # Common events
                try:
                    t_int = int(getattr(layer, "type", -1))
                except Exception:
                    t_int = -1
                try:
                    c_int = int(getattr(layer, "code", -1))
                except Exception:
                    c_int = -1

                if proto == "icmp":
                    if t_int == 8:
                        echo_req += 1
                    elif t_int == 0:
                        echo_rep += 1
                    elif t_int == 3:
                        unreach += 1
                    elif t_int == 11:
                        time_exc += 1
                    elif t_int == 5:
                        redirects += 1
                else:  # icmpv6
                    if t_int == 128:
                        echo_req += 1
                    elif t_int == 129:
                        echo_rep += 1
                    elif t_int == 1:  # dest unreachable
                        unreach += 1
                    elif t_int == 3:  # time exceeded
                        time_exc += 1
                    elif t_int == 137:  # redirect
                        redirects += 1

                # Progress
                if ctx and progress_every > 0 and (i + 1) % progress_every == 0:
                    try:
                        progress = min((i + 1) / float(packet_limit), 1.0)
                        _asyncio.run_coroutine_threadsafe(
                            ctx.report_progress(
                                progress=progress, total=1.0, message=f"Scanned {i + 1} ICMP packets"
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

        return ICMPStats(
            total_packets=total,
            icmpv4_packets=v4,
            icmpv6_packets=v6,
            types=dict(types),
            codes=dict(codes),
            echo_request=echo_req,
            echo_reply=echo_rep,
            unreachable=unreach,
            time_exceeded=time_exc,
            redirects=redirects,
            unique_sources=len(srcs),
            unique_destinations=len(dsts),
        )

    result = await _asyncio.to_thread(_worker)
    if ctx:
        try:
            await ctx.report_progress(progress=1.0, total=1.0, message="ICMP stats complete")
        except Exception:
            pass
    return result


class DNSDeepStats(TypedDict):
    total_packets: int
    queries: int
    responses: int
    udp: int
    tcp: int
    truncated: int
    nxdomain: int
    servfail: int
    rtt_ms_min: float | None
    rtt_ms_avg: float | None
    rtt_ms_max: float | None
    top_servers: list[dict[str, int | str]]
    top_nxdomain_names: list[dict[str, int | str]]


@mcp.tool()
async def dns_deep_stats(
    file_path: str,
    display_filter: str | None = None,
    packet_limit: int = 50_000,
    top_n: int = 20,
    progress_every: int = 1000,
    ctx: Context[ServerSession, None] | None = None,
) -> DNSDeepStats:
    """Deeper DNS stats: transport usage, truncation, NXDOMAIN/SERVFAIL, and RTT metrics."""

    import os
    try:
        import pyshark  # type: ignore
    except Exception as e:
        raise RuntimeError(
            "pyshark is not installed. Install dependencies and ensure tshark is on PATH."
        ) from e

    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    if packet_limit <= 0:
        packet_limit = 1
    packet_limit = min(packet_limit, 200_000)
    if top_n <= 0:
        top_n = 10
    top_n = min(top_n, 200)

    from collections import Counter as _Counter
    loop = _asyncio.get_running_loop()

    def _worker() -> DNSDeepStats:
        _prepare_thread_event_loop()
        total = 0
        q = r = 0
        udp = tcp = 0
        truncated = 0
        nx = servfail = 0
        rtts_ms: list[float] = []
        servers: _Counter[str] = _Counter()
        nx_names: _Counter[str] = _Counter()

        display = f"dns" if not display_filter else f"dns and ({display_filter})"
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
                total += 1
                if not hasattr(pkt, "dns"):
                    continue
                dns = pkt.dns

                # Transport layer
                try:
                    tl = getattr(pkt, "transport_layer", "")
                    if tl == "UDP":
                        udp += 1
                    elif tl == "TCP":
                        tcp += 1
                except Exception:
                    pass

                # Query vs response
                qr_b = None
                try:
                    qr = getattr(dns, "flags_response", None)
                    if qr is not None:
                        try:
                            qr_b = bool(int(qr))
                        except Exception:
                            qr_b = str(qr).lower() in ("1", "true")
                except Exception:
                    pass
                if qr_b is False:
                    q += 1
                elif qr_b is True:
                    r += 1

                # Truncated
                try:
                    tc = getattr(dns, "flags_truncated", None)
                    if tc is not None:
                        try:
                            if bool(int(tc)):
                                truncated += 1
                        except Exception:
                            if str(tc).lower() in ("1", "true"):
                                truncated += 1
                except Exception:
                    pass

                # Response code and NXDOMAIN/SERVFAIL
                rcode_val = None
                try:
                    rcode = getattr(dns, "flags_rcode", None)
                    if rcode is None:
                        rcode = getattr(dns, "rcode", None)
                    if rcode is not None:
                        rcode_val = int(str(rcode)) if str(rcode).isdigit() else None
                        if str(rcode) == "3" or (rcode_val == 3):
                            nx += 1
                        elif str(rcode) == "2" or (rcode_val == 2):
                            servfail += 1
                except Exception:
                    pass

                # Record server IP for responses
                if qr_b is True:
                    try:
                        ip_src = None
                        if hasattr(pkt, "ip"):
                            ip_src = getattr(pkt.ip, "src", None)
                        if ip_src is None and hasattr(pkt, "ipv6"):
                            ip_src = getattr(pkt.ipv6, "src", None)
                        if isinstance(ip_src, str):
                            servers[ip_src] += 1
                    except Exception:
                        pass

                # RTT (dns.time in seconds)
                try:
                    t = getattr(dns, "time", None)
                    if t is not None:
                        rtts_ms.append(float(str(t)) * 1000.0)
                except Exception:
                    pass

                # NXDOMAIN names
                if rcode_val == 3:
                    try:
                        name = getattr(dns, "qry_name", None)
                        if name:
                            nx_names[str(name)] += 1
                    except Exception:
                        pass

                # Progress
                if ctx and progress_every > 0 and (i + 1) % progress_every == 0:
                    try:
                        progress = min((i + 1) / float(packet_limit), 1.0)
                        _asyncio.run_coroutine_threadsafe(
                            ctx.report_progress(
                                progress=progress, total=1.0, message=f"Scanned {i + 1} DNS packets"
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

        def _top(counter: _Counter[str]) -> list[dict[str, int | str]]:
            return [{"ip": ip, "count": cnt} for ip, cnt in counter.most_common(top_n)]

        top_servers = _top(servers)
        top_nx = [{"name": n, "count": c} for n, c in nx_names.most_common(top_n)]

        if rtts_ms:
            rtt_min = min(rtts_ms)
            rtt_max = max(rtts_ms)
            rtt_avg = sum(rtts_ms) / len(rtts_ms)
        else:
            rtt_min = rtt_max = rtt_avg = None

        return DNSDeepStats(
            total_packets=total,
            queries=q,
            responses=r,
            udp=udp,
            tcp=tcp,
            truncated=truncated,
            nxdomain=nx,
            servfail=servfail,
            rtt_ms_min=rtt_min,
            rtt_ms_avg=rtt_avg,
            rtt_ms_max=rtt_max,
            top_servers=top_servers,
            top_nxdomain_names=top_nx,
        )

    result = await _asyncio.to_thread(_worker)
    if ctx:
        try:
            await ctx.report_progress(progress=1.0, total=1.0, message="DNS deep stats complete")
        except Exception:
            pass
    return result


class SSHStats(TypedDict):
    total_packets: int
    connections: int
    versions: dict[str, int]
    kex_algorithms: dict[str, int]
    host_key_algorithms: dict[str, int]
    encryption_algorithms: dict[str, int]
    mac_algorithms: dict[str, int]
    auth_methods: dict[str, int]
    top_banners: list[dict[str, int | str]]


@mcp.tool()
async def ssh_stats(
    file_path: str,
    display_filter: str | None = None,
    packet_limit: int = 50_000,
    top_n: int = 20,
    progress_every: int = 1000,
    ctx: Context[ServerSession, None] | None = None,
) -> SSHStats:
    """Summarize SSH traffic: versions, algorithms, and banners if present."""

    import os
    try:
        import pyshark  # type: ignore
    except Exception as e:
        raise RuntimeError(
            "pyshark is not installed. Install dependencies and ensure tshark is on PATH."
        ) from e

    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    if packet_limit <= 0:
        packet_limit = 1
    packet_limit = min(packet_limit, 200_000)
    if top_n <= 0:
        top_n = 10
    top_n = min(top_n, 200)

    from collections import Counter as _Counter
    loop = _asyncio.get_running_loop()

    def _as_list(layer: object, name: str) -> list[str]:
        try:
            vals = getattr(layer, f"{name}_all", None)
            if vals is None:
                val = getattr(layer, name, None)
                if val is None:
                    return []
                return [str(val)]
            return [str(v) for v in list(vals)]
        except Exception:
            return []

    def _worker() -> SSHStats:
        _prepare_thread_event_loop()
        total = 0
        versions: _Counter[str] = _Counter()
        kex: _Counter[str] = _Counter()
        hostkey: _Counter[str] = _Counter()
        enc: _Counter[str] = _Counter()
        mac: _Counter[str] = _Counter()
        auth: _Counter[str] = _Counter()
        banners: _Counter[str] = _Counter()
        streams: set[int] = set()

        display = f"ssh" if not display_filter else f"ssh and ({display_filter})"
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
                total += 1
                if not hasattr(pkt, "ssh"):
                    continue
                layer = pkt.ssh

                # Track connection streams
                try:
                    if hasattr(pkt, "tcp"):
                        sid = int(getattr(pkt.tcp, "stream", "-1"))
                        if sid >= 0:
                            streams.add(sid)
                except Exception:
                    pass

                # Version / banner
                try:
                    proto = getattr(layer, "protocol", None)
                    if proto:
                        versions[str(proto)] += 1
                        banners[str(proto)] += 1
                except Exception:
                    pass

                # Algorithms
                for field in ("kex_algorithms", "host_key_algorithms"):
                    vals = _as_list(layer, field)
                    for v in vals:
                        if field.startswith("kex"):
                            kex[v] += 1
                        else:
                            hostkey[v] += 1

                for field in (
                    "encryption_algorithms_client_to_server",
                    "encryption_algorithms_server_to_client",
                ):
                    vals = _as_list(layer, field)
                    for v in vals:
                        enc[v] += 1

                for field in (
                    "mac_algorithms_client_to_server",
                    "mac_algorithms_server_to_client",
                ):
                    vals = _as_list(layer, field)
                    for v in vals:
                        mac[v] += 1

                for field in ("auth_methods",):
                    vals = _as_list(layer, field)
                    for v in vals:
                        auth[v] += 1

                # Progress
                if ctx and progress_every > 0 and (i + 1) % progress_every == 0:
                    try:
                        progress = min((i + 1) / float(packet_limit), 1.0)
                        _asyncio.run_coroutine_threadsafe(
                            ctx.report_progress(
                                progress=progress, total=1.0, message=f"Scanned {i + 1} SSH packets"
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

        top_banners: list[dict[str, int | str]] = [
            {"banner": b, "count": c} for b, c in banners.most_common(top_n)
        ]
        return SSHStats(
            total_packets=total,
            connections=len(streams),
            versions=dict(versions),
            kex_algorithms=dict(kex),
            host_key_algorithms=dict(hostkey),
            encryption_algorithms=dict(enc),
            mac_algorithms=dict(mac),
            auth_methods=dict(auth),
            top_banners=top_banners,
        )

    result = await _asyncio.to_thread(_worker)
    if ctx:
        try:
            await ctx.report_progress(progress=1.0, total=1.0, message="SSH stats complete")
        except Exception:
            pass
    return result


def main() -> None:
    """Run the server using stdio (works with Claude Desktop)."""
    # Basic environment diagnostics
    try:
        tshark_path = _shutil.which("tshark")
        if tshark_path:
            _log(f"tshark found at: {tshark_path}")
        else:
            _log("WARNING: tshark not found on PATH. pyshark tools will fail until installed.")
    except Exception:
        pass

    # Defaults to stdio transport when executed directly
    try:
        _log("Invoking mcp.run() (stdio)")
        mcp.run()
    except Exception as e:
        _log(f"Server crashed: {e!r}")
        raise


if __name__ == "__main__":
    main()

# ---------------- Windows / general environment diagnostics ----------------

@mcp.tool()
async def environment_diagnostics() -> dict[str, Any]:
    """Return environment info to diagnose pyshark/tshark issues.

    Use this when the server (e.g. in Claude on Windows) reports tshark / pyshark errors
    even though tshark is installed locally. This reports:
      - Python version & executable
      - pyshark import status & version
      - Detected tshark path (shutil.which + TSHARK_PATH)
      - tshark version output (first line)
      - Environment variables: PATH, TSHARK_PATH, WIRESHARK_HOME (truncated if huge)
      - Current working directory
    """
    import sys, os, subprocess, json, shutil
    info: dict[str, Any] = {}
    info["python_version"] = sys.version.split()[0]
    info["python_executable"] = sys.executable
    info["cwd"] = os.getcwd()

    # pyshark details
    try:
        import pyshark  # type: ignore
        info["pyshark_import"] = True
        info["pyshark_version"] = getattr(pyshark, "__version__", "unknown")
    except Exception as e:
        info["pyshark_import"] = False
        info["pyshark_error"] = repr(e)

    # tshark detection
    tshark_env = os.environ.get("TSHARK_PATH")
    which_path = shutil.which("tshark")
    info["tshark_env_TSHARK_PATH"] = tshark_env or None
    info["tshark_which"] = which_path or None

    # Attempt version
    tshark_version_line = None
    for candidate in filter(None, [tshark_env, which_path]):
        try:
            proc = subprocess.run([candidate, "-v"], capture_output=True, text=True, timeout=5)
            out = (proc.stdout or proc.stderr or "").splitlines()
            if out:
                tshark_version_line = out[0].strip()
                break
        except Exception as e:
            tshark_version_line = f"error: {e!r}"
    info["tshark_version_line"] = tshark_version_line

    # Environment slices (avoid overwhelming output)
    def _truncate(val: str | None, limit: int = 400) -> str | None:
        if val is None:
            return None
        return val if len(val) <= limit else val[:limit] + "...<truncated>"

    info["PATH"] = _truncate(os.environ.get("PATH"))
    info["WIRESHARK_HOME"] = _truncate(os.environ.get("WIRESHARK_HOME"))

    # Common Windows path guess if not detected
    if not which_path and os.name == "nt":
        possible = r"C:\\Program Files\\Wireshark\\tshark.exe"
        info["windows_default_tshark_exists"] = os.path.exists(possible)
    return info

