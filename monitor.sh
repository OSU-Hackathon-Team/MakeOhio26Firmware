#!/bin/sh
# Monitor ESP32 (/dev/ttyUSB0) and ESP12F hub (/dev/ttyUSB1) simultaneously.
# Hub output is filtered to DBG/PKT lines only; ESP32 shows everything.
# Usage: monitor.sh [esp32_port [hub_port]]
ESP32_PORT=${1:-/dev/ttyUSB0}
HUB_PORT=${2:-/dev/ttyUSB1}

python3 - "$ESP32_PORT" "$HUB_PORT" << 'EOF'
import serial, time, threading, sys

ESP32_PORT = sys.argv[1]
HUB_PORT   = sys.argv[2]

def monitor(port, label, hub_filter=False):
    try:
        s = serial.Serial(port, 115200, timeout=0.5)
    except Exception as e:
        print(f"[{label}] could not open {port}: {e}", flush=True)
        return
    try:
        while True:
            try:
                line = s.readline()
            except serial.SerialException:
                time.sleep(0.2)
                continue
            if not line:
                continue
            text = line.decode('utf-8', errors='replace').rstrip()
            if not text:
                continue
            if hub_filter and not any(k in text for k in ('DBG,', 'PKT,')):
                continue
            print(f"[{label}] {text}", flush=True)
    finally:
        s.close()

t1 = threading.Thread(target=monitor, args=(ESP32_PORT, 'ESP32', False), daemon=True)
t2 = threading.Thread(target=monitor, args=(HUB_PORT,   'HUB',   True),  daemon=True)
t1.start()
t2.start()
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("\n[monitor] stopped")
EOF
