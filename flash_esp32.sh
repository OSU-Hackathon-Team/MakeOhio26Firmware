#!/bin/sh
# Flash an ESP32 sniffer.
# Usage: flash_esp32.sh <device_id> [port]
#   device_id  1 or 2  (default: 1)
#   port       serial port (default: /dev/ttyUSB0)
DEVICE=${1:-1}
PORT=${2:-/dev/ttyUSB0}
cd "$(dirname "$0")/esp32_sniffer"
exec pio run -e "esp32_${DEVICE}" --target upload --upload-port "$PORT"
