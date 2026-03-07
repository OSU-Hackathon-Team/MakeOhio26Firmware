#!/usr/bin/env python3
"""
supabase_bridge.py — WiFi multi-sensor RSSI bridge to Supabase.

Reads PKT lines from the ESP12F hub over serial and uploads them to Supabase
to trigger real-time triangulation and occupancy tracking.

PKT line format (matches correlator.py):
    PKT,<src>,<mac>,<rssi>,<channel>
    src = 'L' (ESP12F local), '1' (ESP32 #1), '2' (ESP32 #2)
    mac = 12 hex chars, e.g. AABBCCDDEEFF

Usage:
    python supabase_bridge.py [PORT] [--baud BAUD] [--interval SECS]
"""

import argparse
import serial
import sys
import time
import os
from dotenv import load_dotenv
from supabase import create_client, Client

# Mapping of sensor codes from firmware to Supabase board IDs
BOARD_MAP = {
    "L": "board_east",   # ESP12F Hub (local)
    "1": "board_north",  # ESP32 #1
    "2": "board_south",  # ESP32 #2
}

def parse_args():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("port", nargs="?", default="/dev/ttyUSB1",
                   help="Serial port (default: /dev/ttyUSB1)")
    p.add_argument("--baud", type=int, default=115200)
    p.add_argument("--interval", type=float, default=1.0,
                   help="Minimum seconds between uploads per MAC (rate limiting)")
    return p.parse_args()

def main():
    args = parse_args()

    env_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "MakeOhio26", ".env"))
    load_dotenv(env_path)

    url = os.environ.get("VITE_SUPABASE_URL")
    key = os.environ.get("VITE_SUPABASE_ANON_KEY")

    if not url or not key:
        print(f"Error: Supabase credentials not found at {env_path}")
        sys.exit(1)

    print(f"Connecting to Supabase at {url}...")
    try:
        supabase: Client = create_client(url, key)
    except Exception as e:
        sys.exit(f"Failed to connect: {e}")

    print(f"Opening {args.port} at {args.baud} baud …")
    try:
        ser = serial.Serial(args.port, args.baud, timeout=1)
    except serial.SerialException as e:
        sys.exit(f"Cannot open serial port: {e}")

    print("Listening and bridging to Supabase. Press Ctrl-C to stop.\n")

    last_upload: dict = {}   # mac -> timestamp, for rate limiting

    try:
        while True:
            raw = ser.readline()
            if not raw:
                continue

            try:
                line = raw.decode("ascii", errors="replace").strip()
            except Exception:
                continue

            if line.startswith("PKT,"):
                parts = line.split(",")
                if len(parts) == 5:
                    _, src, mac, rssi_s, ch_s = parts
                    src = src.strip()
                    mac = mac.strip().upper()

                    board_id = BOARD_MAP.get(src)
                    if not board_id:
                        continue

                    # Rate-limit uploads per MAC to avoid slamming Supabase
                    now = time.time()
                    if mac in last_upload and now - last_upload[mac] < args.interval:
                        continue

                    try:
                        payload = {
                            "packet_id":      f"pkt_{mac}_{int(now)}",
                            "board_id":       board_id,
                            "mac_addr":       mac,
                            "rssi":           int(rssi_s),
                            "channel":        int(ch_s),
                            "arrival_time_us": int(now * 1_000_000),
                        }
                        supabase.table("packet_reports").insert(payload).execute()
                        print(f"  [SUPA] {mac} from {src} ({int(rssi_s):+d} dBm ch{ch_s})")
                        last_upload[mac] = now
                    except ValueError:
                        pass
                    except Exception as e:
                        print(f"  [ERR]  Supabase upload failed: {e}")

            elif line.startswith("DBG,"):
                print(f"  [HUB]  {line[4:]}")
            elif line:
                print(f"  [???]  {line}")

    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        ser.close()

if __name__ == "__main__":
    main()
