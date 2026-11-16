#!/usr/bin/env python3
"""
Generate synthetic capture files for testing netwatch's detectors offline.

This only WRITES .pcap files to disk. It never puts a packet on any network,
so you can exercise every heuristic without generating attack traffic:

    python3 make_test_pcaps.py            # writes test_pcaps/*.pcap
    python3 netwatch.py --pcap test_pcaps/syn_flood.pcap --alert-log ""

All addresses are from documentation/private ranges.
"""

import os
import random
import struct
import sys

T0 = 1_700_000_000.0
SERVER = "10.0.0.10"
random.seed(7)


def ip4(a: str) -> bytes:
    return bytes(int(x) for x in a.split("."))


def frame(src: str, dst: str, proto: int, l4: bytes) -> bytes:
    """Ethernet + IPv4 header around an L4 blob (checksums left as zero)."""
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(l4), 0, 0, 64, proto, 0,
                     ip4(src), ip4(dst))
    return b"\x02\x00\x00\x00\x00\x02" + b"\x02\x00\x00\x00\x00\x01" + b"\x08\x00" + ip + l4


def tcp(src, dst, sport, dport, flags, payload=b""):
    hdr = struct.pack("!HHIIBBHHH", sport, dport, 1, 1, 5 << 4, flags, 65535, 0, 0)
    return frame(src, dst, 6, hdr + payload)


def udp(src, dst, sport, dport, size=64):
    return frame(src, dst, 17, struct.pack("!HHHH", sport, dport, 8 + size, 0) + b"\0" * size)


def icmp(src, dst, size=56):
    return frame(src, dst, 1, struct.pack("!BBHHH", 8, 0, 0, 1, 1) + b"\0" * size)


SYN, ACK, PSH = 0x02, 0x10, 0x08


def background(seconds: int, start: float = T0):
    """~40 pkt/s of ordinary-looking traffic: full handshakes, a little DNS, pings."""
    out = []
    for s in range(seconds):
        for i in range(8):
            t = start + s + i / 8
            client, sport = f"10.0.0.{50 + i % 5}", 20000 + (s * 8 + i) % 30000
            out.append((t, tcp(client, SERVER, sport, 443, SYN)))
            out.append((t + 0.001, tcp(SERVER, client, 443, sport, SYN | ACK)))
            out.append((t + 0.002, tcp(client, SERVER, sport, 443, ACK)))
            out.append((t + 0.003, tcp(client, SERVER, sport, 443, ACK | PSH, b"x" * 200)))
        out.append((start + s + 0.5, udp("10.0.0.51", "10.0.0.1", 40000 + s % 100, 53)))
        out.append((start + s + 0.6, udp("10.0.0.1", "10.0.0.51", 53, 40000 + s % 100)))
        out.append((start + s + 0.7, icmp("10.0.0.52", SERVER)))
    return out


def syn_flood():
    pkts = background(50)
    for i in range(15 * 1500):                       # 1500 SYN/s for 15s, spoofed sources
        src = f"198.51.{random.randrange(256)}.{random.randrange(1, 255)}"
        pkts.append((T0 + 35 + i / 1500, tcp(src, SERVER, random.randrange(1024, 65535), 80, SYN)))
    return pkts


def udp_flood():
    pkts = background(50)
    for i in range(15 * 5000):                       # 5000 pkt/s from 3 hosts
        src = f"203.0.113.{5 + i % 3}"
        pkts.append((T0 + 35 + i / 5000, udp(src, SERVER, 4444, 9999, 400)))
    return pkts


def icmp_flood():
    pkts = background(50)
    for i in range(15 * 800):
        pkts.append((T0 + 35 + i / 800, icmp("203.0.113.9", SERVER, 1000)))
    return pkts


def http_flood():
    pkts = background(50)
    req = b"GET /index.html HTTP/1.1\r\nHost: test.local\r\n\r\n"
    for i in range(15 * 400):                        # 400 req/s from 2 hosts
        src = f"203.0.113.{20 + i % 2}"
        pkts.append((T0 + 35 + i / 400, tcp(src, SERVER, 30000 + i % 20000, 80, ACK | PSH, req)))
    return pkts


def port_scan():
    pkts = background(50)
    for i in range(1000):                            # 1000 ports in 5s
        pkts.append((T0 + 35 + i / 200, tcp("203.0.113.77", SERVER, 55555, 1 + i, SYN)))
    return pkts


def traffic_spike():
    """Mixed-protocol surge that stays under each per-protocol flood limit
    but is ~30x the learned baseline."""
    pkts = background(60)
    for i in range(15 * 1200):
        src = f"10.0.1.{i % 40 + 1}"
        t = T0 + 40 + i / 1200
        pkts.append((t, tcp(src, SERVER, 40000 + i % 100, 8080, ACK, b"x" * 300)))
    return pkts


def baseline_only():
    return background(60)


def write_pcap(path: str, pkts) -> None:
    pkts.sort(key=lambda p: p[0])
    with open(path, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))   # Ethernet
        for ts, data in pkts:
            fh.write(struct.pack("<IIII", int(ts), int((ts % 1) * 1_000_000),
                                 len(data), len(data)))
            fh.write(data)


def main() -> int:
    out = sys.argv[1] if len(sys.argv) > 1 else "test_pcaps"
    os.makedirs(out, exist_ok=True)
    for fn in (baseline_only, syn_flood, udp_flood, icmp_flood, http_flood,
               port_scan, traffic_spike):
        path = os.path.join(out, fn.__name__ + ".pcap")
        write_pcap(path, fn())
        print("wrote", path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
