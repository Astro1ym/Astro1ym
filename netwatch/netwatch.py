#!/usr/bin/env python3
"""
netwatch - passive network anomaly / flood detector for macOS (also runs on Linux).

    *** AUTHORIZED USE ONLY ***
    Only run this on networks you own or are explicitly authorized to monitor.
    Capturing other people's traffic without permission is illegal in most places.

What it does
------------
Passively sniffs one interface, keeps rolling metrics over two sliding windows,
and raises alerts for SYN floods, UDP/ICMP floods, HTTP floods, port scans and
general traffic spikes. Alerts go to a live terminal dashboard and a JSON-lines
log file.

Passive by construction
-----------------------
This tool opens a *listen-only* capture socket and only ever reads from it.
It never imports or calls any scapy send function (send/sendp/sr/...), never
injects, and never replies to a packet.

Layout (single file, ordered so it can be split into modules later)
-------------------------------------------------------------------
    1. Config        - thresholds + loading from JSON file / CLI flags
    2. Parsing       - raw frame bytes -> small PacketInfo record
    3. Metrics       - per-second buckets, sliding windows, TCP half-open table
    4. Detection     - the five heuristics, alert cooldown, JSONL alert log
    5. Capture       - live capture thread, pcap replay
    6. UI            - rich dashboard, plain-text mode
    6b. Web UI       - optional local browser dashboard (--web)
    7. CLI / main
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import socket
import struct
import sys
import threading
import time
from collections import Counter, OrderedDict, deque
from dataclasses import asdict, dataclass, field, fields
from datetime import datetime, timezone
from typing import Deque, Dict, Iterable, List, Optional, Tuple

# Silence scapy's import-time chatter (missing routes, IPv6 warnings, ...).
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)

__version__ = "0.1.0"

AUTH_NOTICE = (
    "netwatch: passive monitor. Only use on networks you own or are "
    "authorized to monitor."
)


# =============================================================================
# 1. Config
# =============================================================================

@dataclass
class Config:
    """All tunables. Every field is settable from the JSON config file
    (same key names) or from a CLI flag (--syn-rate-threshold 500, etc.).
    Precedence: CLI flag > config file > the defaults below."""

    # --- windows -------------------------------------------------------------
    window_short: int = 10          # seconds; detection + "now" column
    window_long: int = 60           # seconds; context column / history

    # --- SYN flood -----------------------------------------------------------
    syn_rate_threshold: float = 200.0   # new SYNs/sec, averaged over window_short
    half_open_threshold: int = 500      # SYNs still waiting for the final ACK
    half_open_timeout: float = 30.0     # seconds before a half-open entry is forgotten

    # --- UDP / ICMP flood ----------------------------------------------------
    udp_pps_threshold: float = 2000.0   # UDP packets/sec over window_short
    icmp_pps_threshold: float = 200.0   # ICMP + ICMPv6 packets/sec over window_short

    # --- HTTP flood ----------------------------------------------------------
    http_req_rate_threshold: float = 100.0  # requests/sec to ONE host:port
    http_top_sources: int = 5               # "few sources" = this many top requesters...
    http_top_share_min: float = 0.5         # ...must account for >= this share (0 = any)
    http_count_tls_hello: bool = True       # count TLS ClientHellos as requests (HTTPS)

    # --- port scan -----------------------------------------------------------
    scan_ports_threshold: int = 100     # distinct dst ports from one source in window_short
    scan_hosts_threshold: int = 50      # distinct dst hosts from one source in window_short

    # --- traffic spike -------------------------------------------------------
    spike_multiplier: float = 5.0       # alert when rate > baseline * this
    spike_min_pps: float = 500.0        # ...and above this floor (avoids idle-network noise)
    spike_min_bytes_per_sec: float = 1_000_000.0
    baseline_alpha: float = 0.05        # EWMA smoothing for the baseline (per second)
    baseline_warmup: int = 30           # seconds of history before spike detection arms

    # --- alerting / output ---------------------------------------------------
    alert_cooldown: float = 30.0        # seconds before the same alert can re-fire
    alert_log: str = "alerts.jsonl"     # JSON-lines alert file ("" disables)
    top_n: int = 10                     # rows in the top-talker tables
    refresh_interval: float = 0.5       # dashboard redraw period (seconds)

    # --- safety caps (memory protection under spoofed-source floods) ---------
    max_tracked_per_second: int = 20000   # distinct keys per counter per 1s bucket
    max_half_open: int = 200000           # entries in the half-open table


def load_config(path: Optional[str], overrides: Dict[str, object]) -> Config:
    """Build a Config from defaults, then the JSON file, then CLI overrides."""
    cfg = Config()
    known = {f.name: f for f in fields(Config)}
    if path:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        for key, value in data.items():
            if key.startswith("_"):          # allow "_comment" keys in the file
                continue
            if key not in known:
                raise SystemExit(f"config: unknown key {key!r} in {path}")
            setattr(cfg, key, type(getattr(cfg, key))(value))
    for key, value in overrides.items():
        if value is not None:
            setattr(cfg, key, value)
    if cfg.window_short < 1 or cfg.window_long < cfg.window_short:
        raise SystemExit("config: need 1 <= window_short <= window_long")
    return cfg


# =============================================================================
# 2. Parsing: raw frame bytes -> PacketInfo
# =============================================================================
# We parse the handful of header fields we need by hand instead of letting
# scapy dissect every packet. Full dissection is ~10x slower, and a flood is
# exactly when we can least afford to fall behind.

PROTO_TCP, PROTO_UDP, PROTO_ICMP, PROTO_OTHER = "TCP", "UDP", "ICMP", "OTHER"
PROTOS = (PROTO_TCP, PROTO_UDP, PROTO_ICMP, PROTO_OTHER)

TCP_FIN, TCP_SYN, TCP_RST, TCP_ACK = 0x01, 0x02, 0x04, 0x10

# IPv6 extension headers we skip over to reach the transport header.
_IPV6_EXT = {0, 43, 60}          # hop-by-hop, routing, destination options
_IPV6_FRAGMENT = 44

_HTTP_METHODS = (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ",
                 b"OPTIONS ", b"PATCH ")


@dataclass
class PacketInfo:
    ts: float
    length: int                 # bytes on the wire (as captured)
    src: str
    dst: str
    proto: str                  # one of PROTOS
    sport: int = 0
    dport: int = 0
    tcp_flags: int = 0
    is_http_request: bool = False


def _l3_offset(link: str, raw: bytes) -> int:
    """Return the offset of the IP header for the given link type, or -1."""
    if link == "Ether":
        if len(raw) < 14:
            return -1
        off, etype = 14, (raw[12] << 8) | raw[13]
        while etype in (0x8100, 0x88A8) and len(raw) >= off + 4:   # VLAN tags
            etype = (raw[off + 2] << 8) | raw[off + 3]
            off += 4
        return off if etype in (0x0800, 0x86DD) else -1
    if link == "Loopback":       # BSD/macOS lo0, utun*: 4-byte address family
        return 4
    if link == "CookedLinux":    # Linux "any" pseudo-interface
        return 16
    if link in ("IP", "IPv6", "Raw"):
        return 0
    return -1


def parse_frame(link: str, raw: bytes, ts: float) -> Optional[PacketInfo]:
    """Parse one captured frame. Returns None for non-IP or truncated frames."""
    off = _l3_offset(link, raw)
    if off < 0 or len(raw) < off + 20:
        return None
    version = raw[off] >> 4

    if version == 4:
        ihl = (raw[off] & 0x0F) * 4
        proto_num = raw[off + 9]
        frag_offset = ((raw[off + 6] & 0x1F) << 8) | raw[off + 7]
        src = socket.inet_ntoa(raw[off + 12:off + 16])
        dst = socket.inet_ntoa(raw[off + 16:off + 20])
        l4 = off + ihl
        first_fragment = frag_offset == 0
    elif version == 6:
        if len(raw) < off + 40:
            return None
        proto_num = raw[off + 6]
        src = socket.inet_ntop(socket.AF_INET6, raw[off + 8:off + 24])
        dst = socket.inet_ntop(socket.AF_INET6, raw[off + 24:off + 40])
        l4 = off + 40
        first_fragment = True
        # Walk extension headers (bounded) to find the transport protocol.
        for _ in range(8):
            if proto_num in _IPV6_EXT and len(raw) >= l4 + 2:
                proto_num, l4 = raw[l4], l4 + (raw[l4 + 1] + 1) * 8
            elif proto_num == _IPV6_FRAGMENT and len(raw) >= l4 + 8:
                first_fragment = ((raw[l4 + 2] << 8) | raw[l4 + 3]) >> 3 == 0
                proto_num, l4 = raw[l4], l4 + 8
            else:
                break
    else:
        return None

    info = PacketInfo(ts=ts, length=len(raw), src=src, dst=dst, proto=PROTO_OTHER)

    if proto_num == 6:
        info.proto = PROTO_TCP
        if first_fragment and len(raw) >= l4 + 14:
            info.sport, info.dport = struct.unpack_from("!HH", raw, l4)
            info.tcp_flags = raw[l4 + 13]
            payload_off = l4 + (raw[l4 + 12] >> 4) * 4
            head = raw[payload_off:payload_off + 8]
            if head:
                info.is_http_request = head.startswith(_HTTP_METHODS)
                # TLS ClientHello: record type 0x16, version 3.x, handshake type 1.
                if (not info.is_http_request and len(head) >= 6
                        and head[0] == 0x16 and head[1] == 0x03 and head[5] == 0x01):
                    info.is_http_request = None      # tri-state: None = TLS hello
    elif proto_num == 17:
        info.proto = PROTO_UDP
        if first_fragment and len(raw) >= l4 + 4:
            info.sport, info.dport = struct.unpack_from("!HH", raw, l4)
    elif proto_num in (1, 58):                        # ICMP, ICMPv6
        info.proto = PROTO_ICMP
    return info


# =============================================================================
# 3. Metrics: per-second buckets + sliding windows
# =============================================================================

class Bucket:
    """Everything counted during one wall-clock second."""
    __slots__ = ("pkts", "bytes", "proto_pkts", "proto_bytes",
                 "src_pkts", "src_bytes", "dst_pkts", "dst_bytes",
                 "syn", "established", "syn_src", "syn_dst",
                 "scan", "http")

    def __init__(self) -> None:
        self.pkts = 0
        self.bytes = 0
        self.proto_pkts = dict.fromkeys(PROTOS, 0)
        self.proto_bytes = dict.fromkeys(PROTOS, 0)
        self.src_pkts: Counter = Counter()
        self.src_bytes: Counter = Counter()
        self.dst_pkts: Counter = Counter()
        self.dst_bytes: Counter = Counter()
        self.syn = 0                       # connection attempts (SYN, no ACK)
        self.established = 0               # handshakes we saw complete
        self.syn_src: Counter = Counter()  # SYNs per source
        self.syn_dst: Counter = Counter()  # SYNs per target
        self.scan: Dict[str, set] = {}     # src -> {(dst, dport), ...}
        self.http: Dict[Tuple[str, int], Counter] = {}  # (host, port) -> Counter(src)


OTHER_KEY = "(other)"      # overflow key once a counter hits max_tracked_per_second


@dataclass
class WindowStats:
    """Aggregated view of one sliding window (rates are per second)."""
    seconds: float = 1.0
    pps: float = 0.0
    bytes_per_sec: float = 0.0
    proto_pps: Dict[str, float] = field(
        default_factory=lambda: dict.fromkeys(PROTOS, 0.0))
    proto_bytes_per_sec: Dict[str, float] = field(
        default_factory=lambda: dict.fromkeys(PROTOS, 0.0))
    new_conn_per_sec: float = 0.0
    established_per_sec: float = 0.0


@dataclass
class Snapshot:
    """Immutable-ish result of MetricsEngine.snapshot(); consumed by the
    detectors and the UI so neither needs the engine lock."""
    now: float = 0.0
    short: WindowStats = field(default_factory=WindowStats)
    long: WindowStats = field(default_factory=WindowStats)
    half_open: int = 0
    half_open_by_dst: List[Tuple[str, int]] = field(default_factory=list)
    top_src: List[Tuple[str, float, float]] = field(default_factory=list)   # ip, pps, B/s
    top_dst: List[Tuple[str, float, float]] = field(default_factory=list)
    syn_src: List[Tuple[str, float]] = field(default_factory=list)          # ip, syn/s
    syn_dst: List[Tuple[str, float]] = field(default_factory=list)
    syn_src_count: int = 0      # distinct SYN sources (huge => spoofed/distributed)
    # src -> (distinct ports, distinct hosts), only the busiest sources
    scanners: List[Tuple[str, int, int]] = field(default_factory=list)
    # (host, port, req/s, [(src, req/s), ...], share of top-K sources, #sources)
    http_hosts: List[Tuple[str, int, float, List[Tuple[str, float]], float, int]] = \
        field(default_factory=list)
    top_src_by_proto: Dict[str, List[Tuple[str, float]]] = field(default_factory=dict)
    baseline_pps: float = 0.0
    baseline_bytes_per_sec: float = 0.0
    baseline_ready: bool = False
    pps_history: List[float] = field(default_factory=list)   # last window_long seconds
    total_packets: int = 0
    total_bytes: int = 0


class MetricsEngine:
    """Thread-safe rolling metrics. The capture thread calls process();
    the main thread calls snapshot() about once a second."""

    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.lock = threading.Lock()
        self.buckets: Dict[int, Bucket] = {}
        # (src, sport, dst, dport) -> time the SYN was seen. Ordered oldest-first.
        self.half_open: "OrderedDict[Tuple[str, int, str, int], float]" = OrderedDict()
        self.half_open_dst: Counter = Counter()
        self.total_packets = 0
        self.total_bytes = 0
        self.started: Optional[float] = None
        # Per-protocol per-source counters live outside Bucket to keep the hot
        # path small: sec -> proto -> Counter(src)
        self.proto_src: Dict[int, Dict[str, Counter]] = {}
        # Spike baseline (EWMA of per-second rates).
        self.baseline_pps = 0.0
        self.baseline_bps = 0.0
        self.baseline_samples = 0
        self._baseline_sec: Optional[int] = None

    # -- hot path ------------------------------------------------------------

    def _bump(self, counter: Counter, key, n: int = 1) -> None:
        """counter[key] += n, folding new keys into OTHER_KEY once the counter
        is full. Keeps memory bounded when sources are spoofed/randomised."""
        if key not in counter and len(counter) >= self.cfg.max_tracked_per_second:
            key = OTHER_KEY
        counter[key] += n

    def process(self, p: PacketInfo) -> None:
        sec = int(p.ts)
        with self.lock:
            if self.started is None:
                self.started = p.ts
            b = self.buckets.get(sec)
            if b is None:
                b = self.buckets[sec] = Bucket()
                self.proto_src[sec] = {PROTO_TCP: Counter(), PROTO_UDP: Counter(),
                                       PROTO_ICMP: Counter(), PROTO_OTHER: Counter()}
            self.total_packets += 1
            self.total_bytes += p.length

            b.pkts += 1
            b.bytes += p.length
            b.proto_pkts[p.proto] += 1
            b.proto_bytes[p.proto] += p.length
            self._bump(b.src_pkts, p.src)
            self._bump(b.dst_pkts, p.dst)
            if p.src in b.src_pkts:
                b.src_bytes[p.src] += p.length
            if p.dst in b.dst_pkts:
                b.dst_bytes[p.dst] += p.length
            self._bump(self.proto_src[sec][p.proto], p.src)

            if p.proto == PROTO_TCP:
                self._process_tcp(b, p)
            elif p.proto == PROTO_UDP and p.dport:
                # Ignore what looks like a server reply (well-known src port to
                # an ephemeral dst port), otherwise every DNS server is a "scanner".
                if not (p.sport < 1024 <= p.dport):
                    self._note_scan(b, p)

    def _process_tcp(self, b: Bucket, p: PacketInfo) -> None:
        flags = p.tcp_flags
        key = (p.src, p.sport, p.dst, p.dport)
        if flags & TCP_SYN and not flags & TCP_ACK:
            # New connection attempt.
            b.syn += 1
            self._bump(b.syn_src, p.src)
            self._bump(b.syn_dst, p.dst)
            self._note_scan(b, p)
            if key not in self.half_open:
                if len(self.half_open) >= self.cfg.max_half_open:
                    self._drop_half_open(next(iter(self.half_open)))
                self.half_open_dst[p.dst] += 1
            self.half_open[key] = p.ts
            self.half_open.move_to_end(key)
        elif flags & TCP_RST:
            # Either side aborting clears the pending handshake.
            self._drop_half_open(key)
            self._drop_half_open((p.dst, p.dport, p.src, p.sport))
        elif flags & TCP_ACK and not flags & TCP_SYN:
            # ACK from the initiator completes the 3-way handshake.
            if key in self.half_open:
                self._drop_half_open(key)
                b.established += 1
            if p.is_http_request is not False:
                if p.is_http_request or self.cfg.http_count_tls_hello:
                    host = (p.dst, p.dport)
                    counter = b.http.get(host)
                    if counter is None:
                        if len(b.http) >= self.cfg.max_tracked_per_second:
                            return
                        counter = b.http[host] = Counter()
                    self._bump(counter, p.src)

    def _note_scan(self, b: Bucket, p: PacketInfo) -> None:
        targets = b.scan.get(p.src)
        if targets is None:
            if len(b.scan) >= self.cfg.max_tracked_per_second:
                return
            targets = b.scan[p.src] = set()
        if len(targets) < 70000:           # more than every port; plenty
            targets.add((p.dst, p.dport))

    def _drop_half_open(self, key) -> None:
        if self.half_open.pop(key, None) is not None:
            dst = key[2]
            self.half_open_dst[dst] -= 1
            if self.half_open_dst[dst] <= 0:
                del self.half_open_dst[dst]

    # -- periodic work (main thread, ~1/sec) -----------------------------------

    def _expire(self, now: float) -> None:
        """Drop buckets older than the long window and stale half-open entries."""
        horizon = int(now) - self.cfg.window_long - 1
        for sec in [s for s in self.buckets if s < horizon]:
            del self.buckets[sec]
            self.proto_src.pop(sec, None)
        cutoff = now - self.cfg.half_open_timeout
        while self.half_open:
            key, ts = next(iter(self.half_open.items()))
            if ts >= cutoff:
                break
            self._drop_half_open(key)

    def _update_baseline(self, now: float) -> None:
        """Fold every fully elapsed second into the EWMA baseline, exactly once.
        While traffic is far above baseline we learn 10x slower, so an attack
        does not quickly become "the new normal" (but a genuine level shift
        still gets absorbed eventually)."""
        last_complete = int(now) - 1
        if self._baseline_sec is None:
            self._baseline_sec = last_complete - 1
        start = max(self._baseline_sec + 1, last_complete - self.cfg.window_long)
        for sec in range(start, last_complete + 1):
            b = self.buckets.get(sec)
            pps = float(b.pkts) if b else 0.0
            bps = float(b.bytes) if b else 0.0
            if self.baseline_samples == 0:
                self.baseline_pps, self.baseline_bps = pps, bps
            else:
                alpha = self.cfg.baseline_alpha
                if (self.baseline_samples >= self.cfg.baseline_warmup
                        and pps > self.baseline_pps * self.cfg.spike_multiplier
                        and pps > self.cfg.spike_min_pps):
                    alpha /= 10.0
                self.baseline_pps += alpha * (pps - self.baseline_pps)
                self.baseline_bps += alpha * (bps - self.baseline_bps)
            self.baseline_samples += 1
        self._baseline_sec = max(self._baseline_sec, last_complete)

    def _window(self, now: float, length: int) -> Tuple[List[Bucket], List[int], float]:
        """Buckets for the last `length` whole seconds (excluding the current,
        still-filling second) and the divisor to turn sums into rates."""
        end = int(now) - 1
        secs = [s for s in range(end - length + 1, end + 1) if s in self.buckets]
        elapsed = length
        if self.started is not None:
            # During start-up, don't dilute rates over time we weren't running.
            elapsed = max(1, min(length, end - int(self.started) + 1))
        return [self.buckets[s] for s in secs], secs, float(elapsed)

    def _window_stats(self, now: float, length: int) -> WindowStats:
        buckets, _, secs = self._window(now, length)
        ws = WindowStats(seconds=secs)
        ws.pps = sum(b.pkts for b in buckets) / secs
        ws.bytes_per_sec = sum(b.bytes for b in buckets) / secs
        ws.proto_pps = {p: sum(b.proto_pkts[p] for b in buckets) / secs for p in PROTOS}
        ws.proto_bytes_per_sec = {p: sum(b.proto_bytes[p] for b in buckets) / secs
                                  for p in PROTOS}
        ws.new_conn_per_sec = sum(b.syn for b in buckets) / secs
        ws.established_per_sec = sum(b.established for b in buckets) / secs
        return ws

    def snapshot(self, now: float) -> Snapshot:
        cfg, n = self.cfg, self.cfg.top_n
        with self.lock:
            self._expire(now)
            self._update_baseline(now)
            snap = Snapshot(now=now)
            snap.short = self._window_stats(now, cfg.window_short)
            snap.long = self._window_stats(now, cfg.window_long)
            buckets, secs_list, secs = self._window(now, cfg.window_short)

            def merged(attr: str) -> Counter:
                total: Counter = Counter()
                for b in buckets:
                    total.update(getattr(b, attr))
                return total

            src_pkts, src_bytes = merged("src_pkts"), merged("src_bytes")
            dst_pkts, dst_bytes = merged("dst_pkts"), merged("dst_bytes")
            snap.top_src = [(ip, c / secs, src_bytes[ip] / secs)
                            for ip, c in src_pkts.most_common(n)]
            snap.top_dst = [(ip, c / secs, dst_bytes[ip] / secs)
                            for ip, c in dst_pkts.most_common(n)]
            syn_src = merged("syn_src")
            snap.syn_src = [(ip, c / secs) for ip, c in syn_src.most_common(n)]
            snap.syn_src_count = len(syn_src)
            snap.syn_dst = [(ip, c / secs) for ip, c in merged("syn_dst").most_common(n)]

            for proto in (PROTO_UDP, PROTO_ICMP):
                total = Counter()
                for s in secs_list:
                    total.update(self.proto_src[s][proto])
                snap.top_src_by_proto[proto] = [(ip, c / secs)
                                                for ip, c in total.most_common(n)]

            # Port-scan view: union each source's (dst, port) sets over the window.
            scan: Dict[str, set] = {}
            for b in buckets:
                for src, targets in b.scan.items():
                    scan.setdefault(src, set()).update(targets)
            rows = [(src, len({port for _, port in t}), len({dst for dst, _ in t}))
                    for src, t in scan.items()]
            rows.sort(key=lambda r: max(r[1], r[2]), reverse=True)
            snap.scanners = rows[:n]

            # HTTP view: requests per host:port and who is sending them.
            http: Dict[Tuple[str, int], Counter] = {}
            for b in buckets:
                for host, counter in b.http.items():
                    http.setdefault(host, Counter()).update(counter)
            for (host, port), counter in http.items():
                total_req = sum(counter.values())
                top = counter.most_common(cfg.http_top_sources)
                share = sum(c for _, c in top) / total_req if total_req else 0.0
                snap.http_hosts.append((host, port, total_req / secs,
                                        [(ip, c / secs) for ip, c in top],
                                        share, len(counter)))
            snap.http_hosts.sort(key=lambda r: r[2], reverse=True)
            del snap.http_hosts[n:]

            snap.half_open = len(self.half_open)
            snap.half_open_by_dst = self.half_open_dst.most_common(n)
            snap.baseline_pps = self.baseline_pps
            snap.baseline_bytes_per_sec = self.baseline_bps
            snap.baseline_ready = self.baseline_samples >= cfg.baseline_warmup
            end = int(now) - 1
            snap.pps_history = [float(self.buckets[s].pkts) if s in self.buckets else 0.0
                                for s in range(end - cfg.window_long + 1, end + 1)]
            snap.total_packets = self.total_packets
            snap.total_bytes = self.total_bytes
            return snap


# =============================================================================
# 4. Detection + alerting
# =============================================================================

@dataclass
class Alert:
    timestamp: str              # ISO-8601 UTC
    epoch: float
    type: str                   # SYN_FLOOD, UDP_FLOOD, ICMP_FLOOD, HTTP_FLOOD, PORT_SCAN, TRAFFIC_SPIKE
    metric: str                 # which measurement crossed the line
    value: float
    threshold: float
    window_seconds: int
    sources: List[str]          # offending source IP(s), busiest first
    targets: List[str]          # victim host(s), where known
    detail: str                 # one-line human summary


def _mk_alert(now: float, kind: str, metric: str, value: float, threshold: float,
              window: int, sources: Iterable[str], targets: Iterable[str],
              detail: str) -> Alert:
    return Alert(
        timestamp=datetime.fromtimestamp(now, tz=timezone.utc).isoformat(timespec="seconds"),
        epoch=round(now, 3), type=kind, metric=metric, value=round(value, 2),
        threshold=threshold, window_seconds=window,
        sources=[s for s in sources if s != OTHER_KEY][:5],
        targets=[t for t in targets if t != OTHER_KEY][:5], detail=detail)


def detect(snap: Snapshot, cfg: Config) -> List[Tuple[str, Alert]]:
    """Run every heuristic against a snapshot.
    Returns (dedupe_key, alert) pairs; the AlertManager applies the cooldown."""
    out: List[Tuple[str, Alert]] = []
    now, w, s = snap.now, cfg.window_short, snap.short

    # --- SYN flood: SYN rate or half-open count --------------------------------
    syn_sources = [ip for ip, _ in snap.syn_src]
    syn_targets = [ip for ip, _ in snap.syn_dst]
    # With spoofed sources no single IP stands out, so say how many there are
    # and who is being hit.
    syn_who = (f"from {snap.syn_src_count} source(s)"
               + (f" to {syn_targets[0]}" if syn_targets else ""))
    if s.new_conn_per_sec > cfg.syn_rate_threshold:
        out.append(("SYN_FLOOD:rate", _mk_alert(
            now, "SYN_FLOOD", "syn_per_sec", s.new_conn_per_sec, cfg.syn_rate_threshold,
            w, syn_sources, syn_targets,
            f"{s.new_conn_per_sec:.0f} SYN/s (limit {cfg.syn_rate_threshold:g}), "
            f"only {s.established_per_sec:.0f}/s completing, {syn_who}")))
    if snap.half_open > cfg.half_open_threshold:
        out.append(("SYN_FLOOD:half_open", _mk_alert(
            now, "SYN_FLOOD", "half_open_connections", snap.half_open,
            cfg.half_open_threshold, int(cfg.half_open_timeout), syn_sources,
            [ip for ip, _ in snap.half_open_by_dst],
            f"{snap.half_open} half-open connections (limit {cfg.half_open_threshold}), "
            f"{syn_who}")))

    # --- UDP / ICMP flood: protocol packet rate ---------------------------------
    for proto, limit in ((PROTO_UDP, cfg.udp_pps_threshold),
                         (PROTO_ICMP, cfg.icmp_pps_threshold)):
        rate = s.proto_pps.get(proto, 0.0)
        if rate > limit:
            srcs = [ip for ip, _ in snap.top_src_by_proto.get(proto, [])]
            out.append((f"{proto}_FLOOD", _mk_alert(
                now, f"{proto}_FLOOD", f"{proto.lower()}_pps", rate, limit, w, srcs,
                [ip for ip, _, _ in snap.top_dst[:3]],
                f"{rate:.0f} {proto} pkt/s (limit {limit:g})")))

    # --- HTTP flood: many requests to one host from few sources -----------------
    for host, port, rate, top, share, nsrc in snap.http_hosts:
        if rate > cfg.http_req_rate_threshold and share >= cfg.http_top_share_min:
            out.append((f"HTTP_FLOOD:{host}:{port}", _mk_alert(
                now, "HTTP_FLOOD", "http_requests_per_sec", rate,
                cfg.http_req_rate_threshold, w, [ip for ip, _ in top],
                [f"{host}:{port}"],
                f"{rate:.0f} req/s to {host}:{port} from {nsrc} source(s); "
                f"top {len(top)} send {share:.0%}")))

    # --- Port scan: one source, many ports or hosts -----------------------------
    for src, ports, hosts in snap.scanners:
        if src == OTHER_KEY:
            continue
        if ports > cfg.scan_ports_threshold:
            out.append((f"PORT_SCAN:{src}", _mk_alert(
                now, "PORT_SCAN", "unique_dst_ports", ports, cfg.scan_ports_threshold,
                w, [src], [], f"{src} probed {ports} ports on {hosts} host(s)")))
        elif hosts > cfg.scan_hosts_threshold:
            out.append((f"PORT_SCAN:{src}", _mk_alert(
                now, "PORT_SCAN", "unique_dst_hosts", hosts, cfg.scan_hosts_threshold,
                w, [src], [], f"{src} probed {hosts} hosts on {ports} port(s)")))

    # --- General spike: rate vs. learned baseline -------------------------------
    if snap.baseline_ready:
        top = [ip for ip, _, _ in snap.top_src]
        tgt = [ip for ip, _, _ in snap.top_dst[:3]]
        limit = snap.baseline_pps * cfg.spike_multiplier
        if s.pps > limit and s.pps > cfg.spike_min_pps:
            out.append(("TRAFFIC_SPIKE:pps", _mk_alert(
                now, "TRAFFIC_SPIKE", "packets_per_sec", s.pps, round(limit, 2), w, top, tgt,
                f"{s.pps:.0f} pkt/s is {s.pps / max(snap.baseline_pps, 1e-9):.1f}x "
                f"baseline ({snap.baseline_pps:.0f})")))
        limit = snap.baseline_bytes_per_sec * cfg.spike_multiplier
        if s.bytes_per_sec > limit and s.bytes_per_sec > cfg.spike_min_bytes_per_sec:
            out.append(("TRAFFIC_SPIKE:bytes", _mk_alert(
                now, "TRAFFIC_SPIKE", "bytes_per_sec", s.bytes_per_sec, round(limit, 2),
                w, top, tgt,
                f"{fmt_bytes(s.bytes_per_sec)}/s is "
                f"{s.bytes_per_sec / max(snap.baseline_bytes_per_sec, 1e-9):.1f}x baseline")))
    return out


class AlertManager:
    """Applies the per-alert cooldown, keeps recent alerts for the UI and
    appends each alert to the JSON-lines log."""

    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.recent: Deque[Alert] = deque(maxlen=200)
        self.count = 0
        self.by_type: Counter = Counter()
        self._last_fired: Dict[str, float] = {}
        self._fh = None
        if cfg.alert_log:
            self._fh = open(cfg.alert_log, "a", encoding="utf-8")
            # Under sudo the file would be root-owned; hand it back to the user.
            uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
            if uid and gid and hasattr(os, "fchown"):
                try:
                    os.fchown(self._fh.fileno(), int(uid), int(gid))
                except OSError:
                    pass

    def submit(self, candidates: List[Tuple[str, Alert]]) -> List[Alert]:
        """Returns the alerts that actually fired (i.e. were not in cooldown)."""
        fired = []
        for key, alert in candidates:
            last = self._last_fired.get(key)
            if last is not None and alert.epoch - last < self.cfg.alert_cooldown:
                continue
            self._last_fired[key] = alert.epoch
            self.recent.append(alert)
            self.count += 1
            self.by_type[alert.type] += 1
            if self._fh:
                self._fh.write(json.dumps(asdict(alert)) + "\n")
                self._fh.flush()
            fired.append(alert)
        return fired

    def close(self) -> None:
        if self._fh:
            self._fh.close()
            self._fh = None


# =============================================================================
# 5. Capture (read-only)
# =============================================================================

def list_interfaces() -> List[Tuple[str, str, str, bool]]:
    """[(name, ipv4, mac, is_default), ...] using scapy's interface table."""
    from scapy.all import conf, get_if_addr, get_if_hwaddr, get_if_list
    default = str(conf.iface)
    rows = []
    for name in get_if_list():
        try:
            ip = get_if_addr(name)
        except Exception:
            ip = ""
        try:
            mac = get_if_hwaddr(name)
        except Exception:
            mac = ""
        rows.append((name, "" if ip == "0.0.0.0" else ip, mac, name == default))
    return rows


def default_interface() -> str:
    from scapy.all import conf
    return str(conf.iface)


class LiveCapture(threading.Thread):
    """Background thread: read frames from a listen-only socket and feed the
    metrics engine. Nothing in here can transmit."""

    def __init__(self, iface: str, engine: MetricsEngine, bpf: Optional[str],
                 promisc: bool) -> None:
        super().__init__(name="capture", daemon=True)
        self.iface, self.engine, self.bpf, self.promisc = iface, engine, bpf, promisc
        self.stop_event = threading.Event()
        self.error: Optional[BaseException] = None
        self.sock = None

    def open(self) -> None:
        """Open the capture socket (needs root). Called from the main thread so
        permission errors surface before the dashboard starts."""
        from scapy.all import conf
        kwargs = {"iface": self.iface, "promisc": self.promisc}
        if self.bpf:
            kwargs["filter"] = self.bpf
        # conf.L2listen is scapy's receive-only socket class for this platform
        # (BPF device on macOS, AF_PACKET on Linux).
        self.sock = conf.L2listen(**kwargs)

    def run(self) -> None:
        sock, engine = self.sock, self.engine
        try:
            while not self.stop_event.is_set():
                # select() handles BPF's internal frame buffering on macOS.
                for s in sock.select([sock], 0.25):
                    cls, raw, ts = s.recv_raw()
                    if raw is None:
                        continue
                    info = parse_frame(getattr(cls, "__name__", ""), raw,
                                       float(ts) if ts else time.time())
                    if info is not None:
                        # Bucket by arrival time on our own clock so windows
                        # line up with the main thread's time.time().
                        info.ts = time.time()
                        engine.process(info)
        except BaseException as exc:          # surface in the main thread
            if not self.stop_event.is_set():
                self.error = exc
        finally:
            try:
                sock.close()
            except Exception:
                pass

    def stop(self) -> None:
        self.stop_event.set()


def replay_pcap(path: str, engine: MetricsEngine, alerts: AlertManager,
                cfg: Config, on_alert) -> Snapshot:
    """Offline mode: feed a pcap through the same engine/detectors, using the
    packets' own timestamps as the clock. Handy for testing thresholds."""
    from scapy.all import PcapReader
    last_eval: Optional[int] = None
    snap = Snapshot()
    ts = 0.0
    with PcapReader(path) as reader:
        for pkt in reader:
            ts = float(pkt.time)
            sec = int(ts)
            if last_eval is None:
                last_eval = sec
            # Evaluate once for every second boundary we cross.
            while last_eval < sec:
                last_eval += 1
                snap = engine.snapshot(float(last_eval))
                for a in alerts.submit(detect(snap, cfg)):
                    on_alert(a)
                if sec - last_eval > cfg.window_long:     # long silence: jump
                    last_eval = sec - 1
            raw = getattr(pkt, "original", None) or bytes(pkt)
            info = parse_frame(type(pkt).__name__, raw, ts)
            if info is not None:
                engine.process(info)
    if last_eval is not None:
        snap = engine.snapshot(float(int(ts) + 1))
        for a in alerts.submit(detect(snap, cfg)):
            on_alert(a)
    return snap


# =============================================================================
# 6. UI
# =============================================================================

def fmt_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} GB"


def fmt_rate(n: float) -> str:
    if n >= 1_000_000:
        return f"{n / 1_000_000:.1f}M"
    if n >= 10_000:
        return f"{n / 1000:.1f}k"
    return f"{n:.1f}" if n < 100 else f"{n:.0f}"


def format_alert_line(a: Alert) -> str:
    local = datetime.fromtimestamp(a.epoch).strftime("%H:%M:%S")
    src = ", ".join(a.sources[:3]) or "-"
    return f"{local}  {a.type:<13} {a.detail}  src: {src}"


_SPARK = " ▁▂▃▄▅▆▇█"


def sparkline(values: List[float]) -> str:
    top = max(values) if values else 0
    if top <= 0:
        return " " * len(values)
    return "".join(_SPARK[min(8, int(v / top * 8 + 0.5))] for v in values)


class Dashboard:
    """rich-based live view. Only builds renderables; the main loop owns timing."""

    ALERT_STYLE = {"SYN_FLOOD": "bold red", "UDP_FLOOD": "bold red",
                   "ICMP_FLOOD": "bold red", "HTTP_FLOOD": "bold magenta",
                   "PORT_SCAN": "bold yellow", "TRAFFIC_SPIKE": "bold cyan"}

    def __init__(self, cfg: Config, iface: str, alerts: AlertManager) -> None:
        self.cfg, self.iface, self.alerts = cfg, iface, alerts
        self.started = time.time()

    def render(self, snap: Snapshot):
        from rich.console import Group
        from rich.layout import Layout
        from rich.panel import Panel
        from rich.table import Table
        from rich.text import Text
        cfg, s, l = self.cfg, snap.short, snap.long

        up = int(time.time() - self.started)
        header = Text.assemble(
            ("netwatch ", "bold"), (f"{self.iface}", "bold green"),
            f"   up {up // 3600:02d}:{up % 3600 // 60:02d}:{up % 60:02d}"
            f"   {snap.total_packets:,} pkts / {fmt_bytes(snap.total_bytes)}"
            f"   alerts: ", (str(self.alerts.count), "bold red" if self.alerts.count else ""),
            ("   passive / read-only   Ctrl-C to quit", "dim"))

        # -- rolling metrics --
        m = Table(expand=True, box=None, padding=(0, 1))
        m.add_column("metric")
        m.add_column(f"{cfg.window_short}s", justify="right")
        m.add_column(f"{cfg.window_long}s", justify="right")
        m.add_row("packets/s", fmt_rate(s.pps), fmt_rate(l.pps), style="bold")
        m.add_row("bytes/s", fmt_bytes(s.bytes_per_sec), fmt_bytes(l.bytes_per_sec),
                  style="bold")
        for proto in PROTOS:
            m.add_row(f"  {proto} pkt/s", fmt_rate(s.proto_pps[proto]),
                      fmt_rate(l.proto_pps[proto]))
            m.add_row(f"  {proto} bytes/s", fmt_bytes(s.proto_bytes_per_sec[proto]),
                      fmt_bytes(l.proto_bytes_per_sec[proto]), style="dim")
        m.add_row("new TCP conn/s", fmt_rate(s.new_conn_per_sec),
                  fmt_rate(l.new_conn_per_sec))
        m.add_row("handshakes done/s", fmt_rate(s.established_per_sec),
                  fmt_rate(l.established_per_sec))
        half_style = "bold red" if snap.half_open > cfg.half_open_threshold else ""
        m.add_row("half-open now", Text(str(snap.half_open), style=half_style), "")
        base = (f"{fmt_rate(snap.baseline_pps)} pkt/s" if snap.baseline_ready
                else "learning…")
        m.add_row("spike baseline", base, "", style="dim")
        spark = Text(sparkline(snap.pps_history[-40:]), style="green")
        metrics = Panel(Group(m, Text("pkt/s, last 40s:", style="dim"), spark),
                        title="Rolling metrics", border_style="blue")

        def talkers(title: str, rows) -> Panel:
            t = Table(expand=True, box=None, padding=(0, 1))
            t.add_column("IP", no_wrap=True)
            t.add_column("pkt/s", justify="right")
            t.add_column("bytes/s", justify="right")
            for ip, pps, bps in rows:
                t.add_row(ip, fmt_rate(pps), fmt_bytes(bps))
            return Panel(t, title=title, border_style="blue")

        # -- per-source fan-out (port-scan view) --
        sc = Table(expand=True, box=None, padding=(0, 1))
        sc.add_column("source", no_wrap=True)
        sc.add_column("ports", justify="right")
        sc.add_column("hosts", justify="right")
        for src, ports, hosts in snap.scanners[:cfg.top_n]:
            hot = ports > cfg.scan_ports_threshold or hosts > cfg.scan_hosts_threshold
            sc.add_row(src, str(ports), str(hosts), style="bold yellow" if hot else "")
        scan_panel = Panel(sc, title=f"Unique dst ports/hosts per source ({cfg.window_short}s)",
                           border_style="blue")

        # -- alerts (newest first) --
        lines = []
        for a in list(self.alerts.recent)[::-1][:50]:
            line = Text(format_alert_line(a), no_wrap=True, overflow="ellipsis")
            line.stylize(self.ALERT_STYLE.get(a.type, "bold"), 10, 24)
            lines.append(line)
        body = Group(*lines) if lines else Text("no alerts", style="dim")
        log = f"  → {cfg.alert_log}" if cfg.alert_log else ""
        alert_panel = Panel(body, title=f"Alerts (newest first){log}",
                            border_style="red" if lines else "blue")

        layout = Layout()
        layout.split_column(Layout(header, name="header", size=1),
                            Layout(name="body", ratio=3),
                            Layout(alert_panel, name="alerts", ratio=2))
        layout["body"].split_row(Layout(metrics, ratio=4), Layout(name="mid", ratio=4),
                                 Layout(scan_panel, ratio=3))
        layout["body"]["mid"].split_column(
            Layout(talkers(f"Top sources ({cfg.window_short}s)", snap.top_src)),
            Layout(talkers(f"Top destinations ({cfg.window_short}s)", snap.top_dst)))
        return layout


def plain_status_line(snap: Snapshot) -> str:
    s = snap.short
    top = snap.top_src[0][0] if snap.top_src else "-"
    return (f"{datetime.fromtimestamp(snap.now).strftime('%H:%M:%S')}  "
            f"pps={fmt_rate(s.pps)} bytes/s={fmt_bytes(s.bytes_per_sec)}  "
            f"tcp={fmt_rate(s.proto_pps[PROTO_TCP])} udp={fmt_rate(s.proto_pps[PROTO_UDP])} "
            f"icmp={fmt_rate(s.proto_pps[PROTO_ICMP])}  "
            f"syn/s={fmt_rate(s.new_conn_per_sec)} half-open={snap.half_open}  top-src={top}")


# =============================================================================
# 6b. Web UI (optional): local browser dashboard
# =============================================================================
# Serves dashboard.html and a small JSON API on 127.0.0.1 ONLY. This is
# loopback traffic between this process and your own browser; nothing is sent
# on the monitored network. Because the monitor usually runs as root, every
# API call must carry a secret token and a localhost Host header, so a random
# web page open in your browser cannot talk to it.

class WebMonitor:
    """Owns the capture + engine for web mode and lets the UI switch interface."""

    def __init__(self, cfg: Config, bpf: Optional[str], promisc: bool) -> None:
        self.cfg, self.bpf, self.promisc = cfg, bpf, promisc
        self.alerts = AlertManager(cfg)
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.started = time.time()
        self.iface = ""
        self.engine = MetricsEngine(cfg)
        self.capture: Optional[LiveCapture] = None
        self.snap = Snapshot()
        self.error = ""
        self.interfaces = [{"name": n, "ip": ip, "default": d}
                           for n, ip, _, d in list_interfaces()]

    def switch(self, iface: str) -> None:
        """Start watching `iface`. Raises if it cannot be opened, in which case
        the previous capture keeps running."""
        engine = MetricsEngine(self.cfg)
        capture = LiveCapture(iface, engine, self.bpf, self.promisc)
        capture.open()
        with self.lock:
            old = self.capture
            self.iface, self.engine, self.capture = iface, engine, capture
            self.snap, self.error = Snapshot(), ""
        capture.start()
        if old:
            old.stop()

    def tick(self) -> None:
        with self.lock:
            engine, capture = self.engine, self.capture
        snap = engine.snapshot(time.time())
        self.alerts.submit(detect(snap, self.cfg))
        with self.lock:
            if engine is self.engine:
                self.snap = snap
                if capture and capture.error:
                    self.error = f"capture stopped: {capture.error!r}"

    def state(self) -> dict:
        cfg = self.cfg
        with self.lock:
            d = asdict(self.snap)
            d.update(iface=self.iface, error=self.error)
        d.update(
            now=time.time(), uptime=time.time() - self.started,
            interfaces=self.interfaces,
            alerts=[asdict(a) for a in list(self.alerts.recent)[::-1][:50]],
            alert_count=self.alerts.count, alert_log=cfg.alert_log,
            config={"window_short": cfg.window_short, "window_long": cfg.window_long,
                    "half_open_threshold": cfg.half_open_threshold,
                    "scan_ports_threshold": cfg.scan_ports_threshold,
                    "scan_hosts_threshold": cfg.scan_hosts_threshold,
                    "alert_cooldown": cfg.alert_cooldown})
        return d

    def shutdown(self) -> None:
        if self.capture:
            self.capture.stop()
            self.capture.join(timeout=2.0)
        self.alerts.close()


def make_web_handler(monitor: WebMonitor, token: str, port: int, page: bytes):
    import hmac
    from http.server import BaseHTTPRequestHandler
    allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args) -> None:      # keep the console quiet
            pass

        def _send(self, code: int, body: bytes, ctype: str) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _json(self, code: int, obj) -> None:
            self._send(code, json.dumps(obj).encode(), "application/json")

        def _authorized(self) -> bool:
            if self.headers.get("Host", "") not in allowed_hosts:
                return False
            return hmac.compare_digest(self.headers.get("X-Netwatch-Token", ""), token)

        def do_GET(self) -> None:
            if self.headers.get("Host", "") not in allowed_hosts:
                return self._json(403, {"error": "forbidden"})
            if self.path in ("/", "/index.html"):
                return self._send(200, page, "text/html; charset=utf-8")
            if self.path == "/api/state":
                if not self._authorized():
                    return self._json(403, {"error": "forbidden"})
                return self._json(200, monitor.state())
            self._json(404, {"error": "not found"})

        def do_POST(self) -> None:
            if not self._authorized():
                return self._json(403, {"error": "forbidden"})
            length = min(int(self.headers.get("Content-Length") or 0), 4096)
            try:
                body = json.loads(self.rfile.read(length) or b"{}")
            except ValueError:
                return self._json(400, {"error": "bad json"})
            if self.path == "/api/quit":
                self._json(200, {"ok": True})
                monitor.stop.set()
            elif self.path == "/api/interface":
                name = str(body.get("name", ""))
                if name not in {i["name"] for i in monitor.interfaces}:
                    return self._json(400, {"error": "unknown interface"})
                try:
                    monitor.switch(name)
                except Exception as exc:
                    return self._json(500, {"error": str(exc)})
                self._json(200, {"ok": True})
            else:
                self._json(404, {"error": "not found"})

    return Handler


def run_web(args, cfg: Config) -> int:
    import secrets
    from http.server import ThreadingHTTPServer
    here = os.path.dirname(os.path.abspath(__file__))
    try:
        with open(os.path.join(here, "dashboard.html"), "rb") as fh:
            page = fh.read()
    except OSError:
        print("dashboard.html must sit next to netwatch.py for --web.", file=sys.stderr)
        return 1
    if args.web_token_file:
        with open(args.web_token_file, "r", encoding="utf-8") as fh:
            token = fh.read().strip()
        if len(token) < 16:
            print("web token file must hold at least 16 characters.", file=sys.stderr)
            return 1
    else:
        token = secrets.token_urlsafe(24)

    monitor = WebMonitor(cfg, args.bpf, promisc=not args.no_promisc)
    iface = args.interface or default_interface()
    try:
        monitor.switch(iface)
    except PermissionError:
        print(f"Permission denied opening {iface!r}. Raw capture needs root (sudo).",
              file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"Could not open interface {iface!r}: {exc}", file=sys.stderr)
        return 1

    try:
        server = ThreadingHTTPServer(("127.0.0.1", args.web_port),
                                     make_web_handler(monitor, token, args.web_port, page))
    except OSError as exc:
        print(f"Could not listen on 127.0.0.1:{args.web_port}: {exc}", file=sys.stderr)
        monitor.shutdown()
        return 1
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, name="web", daemon=True).start()

    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: monitor.stop.set())
    print(f"{AUTH_NOTICE}\nwatching {iface}\n"
          f"dashboard: http://127.0.0.1:{args.web_port}/#t={token}\n(Ctrl-C to stop)",
          flush=True)
    try:
        while not monitor.stop.is_set():
            monitor.tick()
            monitor.stop.wait(1.0)
    finally:
        server.shutdown()
        monitor.shutdown()
    print(f"netwatch stopped. {monitor.alerts.count} alert(s).")
    return 0


# =============================================================================
# 7. CLI / main
# =============================================================================

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="netwatch",
        description="Passive (read-only) network flood/anomaly monitor. " + AUTH_NOTICE,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    p.add_argument("-i", "--interface", help="interface to watch (default: primary)")
    p.add_argument("-l", "--list-interfaces", action="store_true",
                   help="list interfaces and exit")
    p.add_argument("-c", "--config", help="JSON config file with threshold overrides")
    p.add_argument("--dump-config", action="store_true",
                   help="print the effective config as JSON and exit")
    p.add_argument("--no-dashboard", action="store_true",
                   help="plain text output (one status line per second + alerts)")
    p.add_argument("--web", action="store_true",
                   help="serve a browser dashboard on 127.0.0.1 instead of the terminal UI")
    p.add_argument("--web-port", type=int, default=8787, help="port for --web")
    p.add_argument("--web-token-file", metavar="FILE",
                   help="read the dashboard access token from FILE (default: random)")
    p.add_argument("--pcap", metavar="FILE",
                   help="analyse a capture file instead of sniffing live (no sudo needed)")
    p.add_argument("--bpf", metavar="FILTER",
                   help="optional capture filter, e.g. 'not port 22'")
    p.add_argument("--no-promisc", action="store_true",
                   help="do not put the interface into promiscuous mode")
    p.add_argument("--version", action="version", version=__version__)

    # One flag per Config field, e.g. --syn-rate-threshold 500
    g = p.add_argument_group("thresholds (override config file)")
    for f in fields(Config):
        default = getattr(Config(), f.name)
        flag = "--" + f.name.replace("_", "-")
        if isinstance(default, bool):
            g.add_argument(flag, dest=f.name, default=None,
                           type=lambda v: v.lower() in ("1", "true", "yes", "on"),
                           metavar="BOOL", help=f"(default: {default})")
        else:
            g.add_argument(flag, dest=f.name, default=None, type=type(default),
                           metavar=type(default).__name__.upper(),
                           help=f"(default: {default!r})")
    return p


def cmd_list_interfaces() -> int:
    rows = list_interfaces()
    print(f"{'':2}{'NAME':<14}{'IPv4':<18}MAC")
    for name, ip, mac, is_default in rows:
        print(f"{'*' if is_default else ' ':2}{name:<14}{ip or '-':<18}{mac or '-'}")
    print("\n* = default (used when -i is not given)")
    if sys.platform == "darwin":
        print("Tip: `networksetup -listallhardwareports` maps en0/en1/... to Wi-Fi/Ethernet.")
    return 0


def run_replay(args, cfg: Config) -> int:
    engine, alerts = MetricsEngine(cfg), AlertManager(cfg)
    try:
        snap = replay_pcap(args.pcap, engine, alerts, cfg,
                           lambda a: print("ALERT  " + format_alert_line(a)))
    finally:
        alerts.close()
    print(f"\n{snap.total_packets:,} packets, {fmt_bytes(snap.total_bytes)}; "
          f"{alerts.count} alert(s) " + (dict(alerts.by_type).__repr__() if alerts.count else ""))
    if cfg.alert_log:
        print(f"alerts appended to {cfg.alert_log}")
    return 0


def run_live(args, cfg: Config) -> int:
    iface = args.interface or default_interface()
    engine, alerts = MetricsEngine(cfg), AlertManager(cfg)
    capture = LiveCapture(iface, engine, args.bpf, promisc=not args.no_promisc)
    try:
        capture.open()
    except PermissionError:
        print(f"Permission denied opening {iface!r}. Raw capture needs root:\n"
              f"    sudo {sys.executable} {' '.join(sys.argv)}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"Could not open interface {iface!r}: {exc}\n"
              f"Run with --list-interfaces to see valid names "
              f"(and use sudo for live capture).", file=sys.stderr)
        return 1

    # Ctrl-C / SIGTERM -> one clean shutdown path via this event.
    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())

    capture.start()
    use_dash = not args.no_dashboard and sys.stdout.isatty()
    snap = Snapshot()

    def tick() -> List[Alert]:
        """Recompute metrics and run detectors (once per second)."""
        nonlocal snap
        snap = engine.snapshot(time.time())
        return alerts.submit(detect(snap, cfg))

    try:
        if use_dash:
            from rich.live import Live
            dash = Dashboard(cfg, iface, alerts)
            next_tick = 0.0
            with Live(dash.render(snap), screen=True, auto_refresh=False) as live:
                while not stop.is_set() and capture.is_alive():
                    if time.time() >= next_tick:
                        tick()
                        next_tick = time.time() + 1.0
                    live.update(dash.render(snap), refresh=True)
                    stop.wait(cfg.refresh_interval)
        else:
            print(f"{AUTH_NOTICE}\nwatching {iface} (Ctrl-C to stop)")
            while not stop.is_set() and capture.is_alive():
                for a in tick():
                    print("ALERT  " + format_alert_line(a), flush=True)
                print(plain_status_line(snap), flush=True)
                stop.wait(1.0)
    finally:
        capture.stop()
        capture.join(timeout=2.0)
        alerts.close()

    if capture.error:
        print(f"capture stopped with error: {capture.error!r}", file=sys.stderr)
    print(f"\nnetwatch stopped. {snap.total_packets:,} packets seen, "
          f"{alerts.count} alert(s)"
          + (f", logged to {cfg.alert_log}" if cfg.alert_log else "") + ".")
    return 1 if capture.error else 0


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    overrides = {f.name: getattr(args, f.name) for f in fields(Config)}
    cfg = load_config(args.config, overrides)

    if args.dump_config:
        print(json.dumps(asdict(cfg), indent=2))
        return 0
    try:
        import scapy.all  # noqa: F401
    except ImportError:
        print("scapy is not installed. Run: pip install -r requirements.txt",
              file=sys.stderr)
        return 1
    if args.list_interfaces:
        return cmd_list_interfaces()
    if args.pcap:
        return run_replay(args, cfg)
    if args.web:
        return run_web(args, cfg)
    try:
        import rich  # noqa: F401
    except ImportError:
        if not args.no_dashboard:
            print("rich is not installed (pip install rich); using --no-dashboard.",
                  file=sys.stderr)
            args.no_dashboard = True
    return run_live(args, cfg)


if __name__ == "__main__":
    sys.exit(main())
