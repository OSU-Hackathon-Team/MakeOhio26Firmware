#!/usr/bin/env python3
"""
correlator.py — WiFi multi-sensor RSSI correlator.

Reads PKT lines from the ESP12F hub over serial and correlates them by
sender MAC address, maintaining a rolling average of signal strength per
sensor over the last WINDOW samples.

Usage:
    python correlator.py [PORT] [--baud BAUD] [--interval SECS] [--window N]

    PORT defaults to /dev/ttyUSB1
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
    return p.parse_args()

# ── data store ────────────────────────────────────────────────────────────────
# packets[mac] = {
#   "L":  deque([rssi, ...], maxlen=window),
#   "1":  deque([rssi, ...], maxlen=window),
#   "2":  deque([rssi, ...], maxlen=window),
#   "ch": last_seen_channel,
# }
packets:  dict = {}
pkt_order: list = []
_window = 10

def ingest(src: str, mac: str, rssi: int, ch: int):
    if mac not in packets:
        if len(packets) >= MAX_TRACKED:
            old = pkt_order.pop(0)
            packets.pop(old, None)
        packets[mac] = {s: deque(maxlen=_window) for s in SENSORS}
        packets[mac]["ch"] = ch
        pkt_order.append(mac)
    packets[mac][src].append(rssi)
    packets[mac]["ch"] = ch

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

def print_summary():
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
        fmt_mac = ':'.join(mac[i:i+2] for i in range(0, 12, 2))
        ch = d["ch"]
        print(f"  {fmt_mac}  {fmt_rssi(d['L'])}  {fmt_rssi(d['1'])}  {fmt_rssi(d['2'])}  {ch:>2}")

    print(f"{'━'*78}\n")

# ── main loop ─────────────────────────────────────────────────────────────────
def main():
    global _window
    args = parse_args()
    _window = args.window

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
                    if len(parts) == 5:
                        _, src, mac, rssi_s, ch_s = parts
                        try:
                            ingest(src.strip(), mac.strip().upper(),
                                   int(rssi_s), int(ch_s))
                        except ValueError:
                            pass
                elif line.startswith("DBG,"):
                    print(f"  [HUB] {line[4:]}")
                elif line:
                    print(f"  [???] {line}")

            if time.time() - last_print >= args.interval:
                last_print = time.time()
                print_summary()

    except KeyboardInterrupt:
        print("\nStopped.")
        print_summary()
    finally:
        ser.close()

if __name__ == "__main__":
    main()
