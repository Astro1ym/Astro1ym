# netwatch

Passive network flood / anomaly monitor for macOS (also runs on Linux).

> **Authorized use only.** Run this only on networks you own or are explicitly
> authorized to monitor. Capturing other people's traffic without permission
> is illegal in most jurisdictions.

netwatch sniffs one interface, keeps rolling metrics over two sliding windows
(10 s and 60 s by default), and raises alerts for SYN floods, UDP/ICMP floods,
HTTP floods, port scans and general traffic spikes. Alerts appear in a live
terminal dashboard and are appended to a JSON-lines file.

**It is read-only.** It opens a listen-only capture socket and never sends,
injects or replies to a packet. No scapy send function is imported or called.

## The easy way: Netwatch.app

No Terminal needed.

1. Double-click **Netwatch** (in this folder; you can drag it to Applications).
2. The first time, it spends about a minute setting itself up (needs internet).
   A notification tells you it is working.
3. macOS asks for your password. That is required to watch network traffic.
4. The dashboard opens in your browser. Pick a different network interface
   from the **Watching** menu at the top right if you need to.
5. Click **Quit** in the dashboard to stop monitoring. Closing the browser
   tab alone leaves it running in the background; open the app again to get
   the dashboard back.

Alerts are saved to `Documents/Netwatch/alerts.jsonl`. To change thresholds,
put a `config.json` (copy `netwatch.example.json`) in `Documents/Netwatch`
and restart the app.

**"Netwatch can't be opened" / "unidentified developer":** the app is not
signed with an Apple developer certificate. Right-click the app, choose
**Open**, then **Open** again. On newer macOS versions, go to System Settings
> Privacy & Security, scroll down, and click **Open Anyway**. This is needed once.

**It asks to install "command line developer tools":** click Install. That is
how macOS provides Python. Open Netwatch again when it finishes.

**Nothing happens:** look at `~/Library/Application Support/Netwatch/netwatch.log`
and `setup.log` in the same folder.

The app is a thin launcher (`app_src/launcher.sh`) around `netwatch.py` and
`dashboard.html`. After editing either, run `./build_app.sh` to rebuild it.

### About the browser dashboard

The dashboard is served on `127.0.0.1` only, so it is reachable from your own
Mac and nowhere else. That is loopback traffic between the monitor and your
browser; nothing is sent on the network being watched. Each launch generates a
secret token that the page needs to read data or stop the monitor, so other
web pages and other users on the Mac cannot control it.

You can also start it by hand; it prints the dashboard link:

```bash
sudo .venv/bin/python3 netwatch.py --web -i en0
```

## Manual install

Needs Python 3.8+.

```bash
cd netwatch
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Test it step by step

Each step exercises one more piece. Steps 1–3 need no sudo and touch no network.

### 1. List interfaces

```bash
python3 netwatch.py --list-interfaces
```

`*` marks the default (the interface carrying your default route, usually
`en0`). On a Mac, this maps the names to Wi-Fi / Ethernet / Thunderbolt:

```bash
networksetup -listallhardwareports
```

### 2. Generate synthetic captures (files only — nothing is transmitted)

```bash
python3 make_test_pcaps.py
```

### 3. Replay them through the detectors

```bash
python3 netwatch.py --pcap test_pcaps/syn_flood.pcap
```

Try `udp_flood`, `icmp_flood`, `http_flood`, `port_scan`, `traffic_spike`
and `baseline_only` (which should raise nothing). Then look at the log:

```bash
cat alerts.jsonl
```

### 4. Live capture, plain text

Raw capture needs root on macOS, hence `sudo`. Use the venv's Python so sudo
finds scapy:

```bash
sudo .venv/bin/python3 netwatch.py -i en0 --no-dashboard
```

You should see one status line per second. Ctrl-C stops it cleanly.

### 5. Live capture, dashboard

```bash
sudo .venv/bin/python3 netwatch.py -i en0
```

Omit `-i` to use the default interface. A terminal at least ~130 columns wide
shows everything without truncation.

## Why sudo?

macOS exposes packet capture through `/dev/bpf*`, which only root can open by
default. If you would rather not run as root, installing Wireshark's
"ChmodBPF" helper gives your user access to those devices, after which
netwatch runs without sudo. When started under sudo, `alerts.jsonl` is handed
back to your own user so you can read and delete it normally.

## Tuning thresholds

Every threshold can be set in a JSON file or with a flag. Precedence is
flag > config file > built-in default.

```bash
cp netwatch.example.json my-lab.json
sudo .venv/bin/python3 netwatch.py -i en0 -c my-lab.json
```

```bash
sudo .venv/bin/python3 netwatch.py -i en0 --syn-rate-threshold 500 --udp-pps-threshold 10000
```

Print the effective settings (flags and file applied) without capturing:

```bash
python3 netwatch.py -c my-lab.json --dump-config
```

| Key | Default | Meaning |
| --- | --- | --- |
| `window_short` / `window_long` | 10 / 60 | Sliding windows in seconds. Detection uses the short one. |
| `syn_rate_threshold` | 200 | New SYNs per second (short-window average). |
| `half_open_threshold` | 500 | SYNs still waiting for the handshake's final ACK. |
| `half_open_timeout` | 30 | Seconds until an unanswered SYN is forgotten. |
| `udp_pps_threshold` | 2000 | UDP packets per second. |
| `icmp_pps_threshold` | 200 | ICMP + ICMPv6 packets per second. |
| `http_req_rate_threshold` | 100 | Requests per second to a single host:port. |
| `http_top_sources` / `http_top_share_min` | 5 / 0.5 | "Few sources": the top 5 requesters must send at least 50% of the requests. Set the share to 0 to also flag widely distributed floods. |
| `http_count_tls_hello` | true | Count TLS ClientHellos as requests (see limits below). |
| `scan_ports_threshold` | 100 | Distinct destination ports from one source in the short window. |
| `scan_hosts_threshold` | 50 | Distinct destination hosts from one source in the short window. |
| `spike_multiplier` | 5 | Alert when the rate exceeds baseline × this. |
| `spike_min_pps` / `spike_min_bytes_per_sec` | 500 / 1,000,000 | Floors, so a quiet network doesn't alert on small bumps. |
| `baseline_alpha` / `baseline_warmup` | 0.05 / 30 | Baseline smoothing, and seconds of learning before spike detection arms. |
| `alert_cooldown` | 30 | Seconds before the same alert may fire again. |
| `alert_log` | `alerts.jsonl` | Alert file; `""` disables it. |

The defaults suit a small lab. To tune: run for a while under normal load,
note the steady-state numbers in the dashboard, and set each threshold a
comfortable margin above them. The synthetic pcaps let you check a new config
still catches each attack type without generating any traffic.

## Alert log format

One JSON object per line:

```json
{"timestamp": "2023-11-14T22:13:56+00:00", "epoch": 1700000036.0, "type": "SYN_FLOOD",
 "metric": "half_open_connections", "value": 1500, "threshold": 500, "window_seconds": 30,
 "sources": ["198.51.100.7"], "targets": ["10.0.0.10"],
 "detail": "1500 half-open connections (limit 500), from 1488 source(s) to 10.0.0.10"}
```

`type` is one of `SYN_FLOOD`, `UDP_FLOOD`, `ICMP_FLOOD`, `HTTP_FLOOD`,
`PORT_SCAN`, `TRAFFIC_SPIKE`.

## How the heuristics work, and their limits

- **SYN flood** — SYN rate over the short window, or the number of handshakes
  that never got their final ACK. With spoofed sources no single IP stands
  out, so the alert also reports the number of distinct sources and the target.
- **UDP / ICMP flood** — packet rate for that protocol.
- **HTTP flood** — counts plaintext HTTP request lines per destination
  host:port. HTTPS payloads are encrypted, so there netwatch counts TLS
  ClientHellos instead: that is connections, not requests, and it misses
  floods sent over a few kept-alive connections.
- **Port scan** — distinct ports/hosts per source, counting TCP SYNs and UDP
  packets. UDP from a port below 1024 to a high port is treated as a server
  reply and ignored.
- **Traffic spike** — short-window rate against a moving-average baseline.
  The baseline learns ten times slower while a spike is in progress, so an
  attack doesn't quickly become "normal", but a sustained flood will
  eventually be absorbed and the spike alert will stop repeating.
- You only see what reaches your interface. On a switched network that means
  your own traffic plus broadcasts, unless you are on a mirror/SPAN port.
  On Wi-Fi, macOS promiscuous mode generally does not show other clients'
  traffic; try `--no-promisc` if capture misbehaves.
- Capture is in Python. Above very roughly tens of thousands of packets per
  second the kernel will drop packets before netwatch sees them, so reported
  rates during a heavy flood are a lower bound.

## Other options

- `--bpf "not port 22"` — capture filter, to exclude traffic you don't care about.
- `--pcap FILE` — analyse any pcap/pcapng offline (e.g. one saved by tcpdump).
- `--no-dashboard` — plain output; also used automatically when stdout isn't a terminal.

## Code layout

`netwatch.py` is one file in seven labelled sections (config, parsing,
metrics, detection, capture, terminal UI, web UI, CLI) that only depend on the
ones above them, so each can be lifted into its own module later.
`dashboard.html` is the browser dashboard used by `--web`.
