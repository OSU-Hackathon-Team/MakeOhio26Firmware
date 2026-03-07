#!/bin/sh
# Flash the ESP12F hub to /dev/ttyUSB1
PORT=${1:-/dev/ttyUSB1}
cd "$(dirname "$0")/esp12f_hub"
exec pio run -e esp12e --target upload --upload-port "$PORT"
