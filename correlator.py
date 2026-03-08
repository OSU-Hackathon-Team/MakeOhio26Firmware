#!/usr/bin/env python3
"""
correlator.py — WiFi multi-sensor RSSI correlator.

Reads PKT lines from the ESP12F hub over serial and correlates them by
sender MAC address, maintaining a rolling average of signal strength per
sensor over the last WINDOW samples.

Usage:
    python correlator.py [PORT] [--baud BAUD] [--interval SECS] [--window N]
                         [--target MAC] [--history-secs N]

    PORT defaults to /dev/ttyUSB1

PKT line format:
    PKT,<src>,<mac>,<rssi>,<channel>,<timestamp_ms>,<report_ms>
    timestamp_ms = board millis() when the packet was sniffed
    report_ms    = board millis() at transmit time (epoch correction anchor)
"""

import argparse
import serial
import sys
import time
from collections import deque

# ── constants ────────────────────────────────────────────────────────────────
SRC_LABELS  = {"L": "ESP12F", "1": "ESP32-1", "2": "ESP32-2"}
MAX_TRACKED = 5000   # cap dict size to avoid unbounded growth
SENSORS     = ("L", "1", "2")

# ── argument parsing ──────────────────────────────────────────────────────────
def parse_args():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("port",     nargs="?", default="/dev/ttyUSB1",
                   help="Serial port (default: /dev/ttyUSB1)")
    p.add_argument("--baud",   type=int,  default=115200)
    p.add_argument("--interval", type=float, default=10.0,
                   help="Seconds between summary prints (default: 10)")
    p.add_argument("--window", type=int, default=10,
                   help="Rolling average window size in samples (default: 10)")
    p.add_argument("--target", type=str, default=None, metavar="MAC",
                   help="MAC address to track in real-time (e.g. AA:BB:CC:DD:EE:FF or AABBCCDDEEFF)")
    p.add_argument("--history-secs", type=int, default=300, metavar="N",
                   help="Show recently-seen MACs from the last N seconds (default: 300)")
    return p.parse_args()

# ── data store ────────────────────────────────────────────────────────────────
# packets[mac] = {
#   "L":  deque([rssi, ...], maxlen=window),
#   "1":  deque([rssi, ...], maxlen=window),
#   "2":  deque([rssi, ...], maxlen=window),
#   "ch": last_seen_channel,
#   "ts": last_seen_timestamp_ms (board millis()),
#   "rx": python time.time() when the report containing this entry was received,
#         used to reconstruct: sniff_unix ≈ rx - (report_ms - ts) / 1000
# }
packets:  dict = {}
pkt_order: list = []
_window = 10

# ── history store ─────────────────────────────────────────────────────────────
# g_history[mac] = {
#   "L":      best RSSI seen from ESP12F  (or None)
#   "1":      best RSSI seen from ESP32-1 (or None)
#   "2":      best RSSI seen from ESP32-2 (or None)
#   "last":   Unix timestamp of most recent sighting
#   "hits":   total number of times this MAC has appeared in any PKT line
# }
g_history: dict = {}

def _history_update(mac: str, src: str, rssi: int, rx_time: float):
    if mac not in g_history:
        g_history[mac] = {"L": None, "1": None, "2": None, "last": rx_time, "hits": 0}
    h = g_history[mac]
    h["hits"] += 1
    h["last"] = rx_time
    if h[src] is None or rssi > h[src]:
        h[src] = rssi

def ingest(src: str, mac: str, rssi: int, ch: int, timestamp_ms: int, report_ms: int, rx_time: float):
    _history_update(mac, src, rssi, rx_time)

    if mac not in packets:
        if len(packets) >= MAX_TRACKED:
            old = pkt_order.pop(0)
            packets.pop(old, None)
        packets[mac] = {s: deque(maxlen=_window) for s in SENSORS}
        packets[mac]["ch"] = ch
        packets[mac]["ts"] = timestamp_ms
        packets[mac]["rx"] = rx_time
        packets[mac]["rm"] = report_ms
        pkt_order.append(mac)
    packets[mac][src].append(rssi)
    packets[mac]["ch"] = ch
    packets[mac]["ts"] = timestamp_ms
    packets[mac]["rx"] = rx_time
    packets[mac]["rm"] = report_ms

# ── display ───────────────────────────────────────────────────────────────────
def sensor_count(d):
    return sum(1 for s in SENSORS if d[s])

def avg_rssi(dq):
    return sum(dq) / len(dq) if dq else None

def fmt_rssi(dq):
    a = avg_rssi(dq)
    if a is None:
        return f"  {'───':^11} "
    n = len(dq)
    return f"{a:+5.1f} dBm({n:2d})"

def _fmt_mac(mac: str) -> str:
    """Convert 12-char hex string to colon-separated display form."""
    return ':'.join(mac[i:i+2] for i in range(0, 12, 2))

def _normalize_mac(mac: str) -> str:
    """Normalize MAC to 12-char uppercase hex (strip colons/dashes)."""
    return mac.upper().replace(":", "").replace("-", "")

def print_target_block(target_mac: str, history_secs: int):
    """Print the dedicated TARGET tracking block."""
    h = g_history.get(target_mac)
    now = time.time()
    fmt = _fmt_mac(target_mac)
    print(f"\n{'▶'*78}")
    if h is None:
        print(f"  TARGET {fmt}  ─  NOT YET SEEN")
    else:
        age = now - h["last"]
        ts_str = time.strftime("%H:%M:%S", time.localtime(h["last"]))
        best_L = f"{h['L']:+d}" if h["L"] is not None else "─"
        best_1 = f"{h['1']:+d}" if h["1"] is not None else "─"
        best_2 = f"{h['2']:+d}" if h["2"] is not None else "─"
        print(f"  TARGET {fmt}  hits={h['hits']}  last={ts_str} ({age:.0f}s ago)")
        print(f"         best RSSI: ESP12F={best_L}  ESP32-1={best_1}  ESP32-2={best_2}")

        # Show current rolling window if still active
        d = packets.get(target_mac)
        if d and sensor_count(d) > 0:
            print(f"         rolling:  {fmt_rssi(d['L'])}  {fmt_rssi(d['1'])}  {fmt_rssi(d['2'])}")
    print(f"{'◀'*78}")

def print_summary(target_mac: str = None, history_secs: int = 300):
    # Target block always printed first if requested
    if target_mac:
        print_target_block(target_mac, history_secs)

    if not packets:
        print("  (no packets received yet)")
        return

    seen_all  = sum(1 for d in packets.values() if sensor_count(d) == 3)
    seen_two  = sum(1 for d in packets.values() if sensor_count(d) == 2)
    seen_one  = sum(1 for d in packets.values() if sensor_count(d) == 1)

    # Only shared packets (2+ sensors), sorted by coverage then MAC
    shared = sorted(
        ((m, d) for m, d in packets.items() if sensor_count(d) >= 2),
        key=lambda kv: (-sensor_count(kv[1]), kv[0])
    )

    now_str = time.strftime("%H:%M:%S")
    print(f"\n{'━'*78}")
    print(f"  {now_str}  │  total={len(packets)}  "
          f"all-3={seen_all}  any-2={seen_two}  only-1={seen_one}  "
          f"(rolling avg window={_window})")
    print(f"{'─'*78}")
    print(f"  {'MAC':^14}  {'ESP12F':^14}  {'ESP32-1':^14}  {'ESP32-2':^14}  CH")
    print(f"{'─'*78}")

    if not shared:
        print("  (no shared packets yet)")
    for mac, d in shared:
        fmt_mac = _fmt_mac(mac)
        ch = d["ch"]
        rx = d.get("rx", 0.0)
        rm = d.get("rm", 0)
        ts = d.get("ts", 0)
        sniff_unix = rx - (rm - ts) / 1000.0
        sniff_str  = time.strftime("%H:%M:%S", time.localtime(sniff_unix)) + f".{int(sniff_unix * 1000) % 1000:03d}"
        print(f"  {fmt_mac}  {fmt_rssi(d['L'])}  {fmt_rssi(d['1'])}  {fmt_rssi(d['2'])}  {ch:>2}  sniff={sniff_str}")

    print(f"{'━'*78}")

    # ── recently-seen block ───────────────────────────────────────────────────
    now = time.time()
    cutoff = now - history_secs
    active = set(packets.keys())
    recent = [
        (mac, h) for mac, h in g_history.items()
        if h["last"] >= cutoff and mac not in active
    ]
    recent.sort(key=lambda kv: -kv[1]["last"])  # most-recently-seen first
    if recent:
        print(f"\n  RECENTLY SEEN (last {history_secs}s, not in current window):")
        print(f"  {'MAC':^14}  {'ESP12F':^8}  {'ESP32-1':^8}  {'ESP32-2':^8}  {'hits':>5}  last-seen")
        for mac, h in recent[:20]:  # cap at 20 rows
            fmt = _fmt_mac(mac)
            age = now - h["last"]
            ts_str = time.strftime("%H:%M:%S", time.localtime(h["last"]))
            bL = f"{h['L']:+d}" if h["L"] is not None else "─"
            b1 = f"{h['1']:+d}" if h["1"] is not None else "─"
            b2 = f"{h['2']:+d}" if h["2"] is not None else "─"
            print(f"  {fmt}  {bL:^8}  {b1:^8}  {b2:^8}  {h['hits']:>5}  {ts_str} ({age:.0f}s ago)")
        if len(recent) > 20:
            print(f"  … and {len(recent) - 20} more")

    print(f"{'━'*78}\n")

# ── main loop ─────────────────────────────────────────────────────────────────
def main():
    global _window
    args = parse_args()
    _window = args.window
    target_mac = _normalize_mac(args.target) if args.target else None

    if target_mac:
        print(f"  ★  Tracking target MAC: {_fmt_mac(target_mac)}")

    print(f"Opening {args.port} at {args.baud} baud …")
    try:
        ser = serial.Serial(args.port, args.baud, timeout=1)
        ser.reset_input_buffer()   # discard stale bytes buffered before we opened
        time.sleep(0.1)            # let any in-flight bytes arrive
        ser.reset_input_buffer()   # flush again to catch bytes that arrived during open
    except serial.SerialException as e:
        sys.exit(f"Cannot open serial port: {e}")

    print("Listening. Press Ctrl-C to stop.\n")

    last_print = time.time()

    try:
        while True:
            raw = ser.readline()
            if not raw:
                pass
            else:
                try:
                    line = raw.decode("ascii", errors="replace").strip()
                except Exception:
                    continue

                if line.startswith("PKT,"):
                    parts = line.split(",")
                    if len(parts) == 7:
                        _, src, mac, rssi_s, ch_s, ts_s, report_ms_s = parts
                        try:
                            mac_norm = mac.strip().upper()
                            ingest(src.strip(), mac_norm,
                                   int(rssi_s), int(ch_s),
                                   int(ts_s), int(report_ms_s), time.time())
                            # Real-time target alert
                            if target_mac and mac_norm == target_mac:
                                h = g_history[mac_norm]
                                ts_str = time.strftime("%H:%M:%S")
                                print(f"  ★ TARGET {_fmt_mac(mac_norm)} │ "
                                      f"src={src.strip():>1}({SRC_LABELS.get(src.strip(), src.strip())}) "
                                      f"rssi={int(rssi_s):+d} ch={ch_s.strip()} "
                                      f"hits={h['hits']} at {ts_str}")
                        except ValueError:
                            pass
                elif line.startswith("DBG,"):
                    print(f"  [HUB] {line[4:]}")
                elif line:
                    print(f"  [???] {line}")

            if time.time() - last_print >= args.interval:
                last_print = time.time()
                print_summary(target_mac=target_mac, history_secs=args.history_secs)

    except KeyboardInterrupt:
        print("\nStopped.")
        print_summary(target_mac=target_mac, history_secs=args.history_secs)
    finally:
        ser.close()

if __name__ == "__main__":
    main()
