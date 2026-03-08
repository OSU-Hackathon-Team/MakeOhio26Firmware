# makio2

WiFi-based multi-sensor RSSI triangulation and occupancy tracking system. Three ESP microcontrollers passively capture 802.11 frames from nearby devices, correlate signal strengths across sensors, and feed data to Supabase for real-time analysis and positioning.

## Hardware

| Component | Role | Qty |
|-----------|------|-----|
| ESP8266 (ESP12F) | Central hub — receives reports from ESP32s and relays everything to the host over serial | 1 |
| ESP32 | Dedicated channel-hopping sniffers (DEVICE_ID 1 and 2) | 2 |

**Architecture:**
1. ESP32 #1 and #2 hop channels 1–13, capturing RSSI per MAC
2. Every 30 seconds each ESP32 injects a report frame (magic bytes `DE AD BE EF`) to the hub on channel 6
3. The ESP12F hub forwards all data — its own captures plus both ESP32 reports — over serial to a host machine
4. Host Python scripts correlate signals or upload to Supabase

## Quick Start

### 1. Flash firmware

```bash
# Flash the ESP12F hub
./flash_hub.sh /dev/ttyUSB1

# Flash ESP32 #1 and #2 (pass DEVICE_ID and port)
./flash_esp32.sh 1 /dev/ttyUSB0
./flash_esp32.sh 2 /dev/ttyUSB2
```

Flashing uses [PlatformIO](https://platformio.org/) under the hood.

### 2. Install Python dependencies

```bash
pip install -r requirements.txt
```

### 3. Run

**Live serial monitor** (raw output from both boards):
```bash
./monitor.sh /dev/ttyUSB0 /dev/ttyUSB1
```

**Local RSSI correlator** (rolling average table across all three sensors):
```bash
python correlator.py /dev/ttyUSB1 --interval 10 --window 10
```

**Supabase bridge** (uploads packet reports in real-time):
```bash
python supabase_bridge.py /dev/ttyUSB1 --interval 0.5
```

## Configuration

### Supabase credentials (`.env`)

```
VITE_SUPABASE_URL=<your-supabase-url>
VITE_SUPABASE_ANON_KEY=<your-anon-key>
VITE_MAPTILER_API_KEY=<optional-maptiler-key>
```

See `supabase_instructions.md` for the required table schema and epoch correction details.

### Firmware flags (`platformio.ini`)

| Flag | Default | Description |
|------|---------|-------------|
| `DEVICE_ID` | 2 | Sniffer identity (1 or 2) |
| `HUB_CHANNEL` | 6 | Channel the hub listens on for ESP32 reports |
| `HOP_INTERVAL_MS` | 50 | Dwell time per channel (ms) |
| `REPORT_INTERVAL_MS` | 30000 | How often ESP32s send reports (ms) |
| `REPORT_RETRIES` | 8 | Retransmit count per report burst |
| `MAX_ENTRIES` | 100 / 200 | Max unique MACs tracked (ESP32 / hub) |

### Script arguments

**`correlator.py`**
```
PORT                 Serial port (default: /dev/ttyUSB1)
--baud BAUD          Baud rate (default: 115200)
--interval SECS      Print interval in seconds (default: 10)
--window N           Rolling average window size (default: 10)
```

**`supabase_bridge.py`**
```
PORT                 Serial port (default: /dev/ttyUSB1)
--baud BAUD          Baud rate (default: 115200)
--interval SECS      Min seconds between uploads per MAC (default: 0.5)
```

## How It Works

### Channel hopping

Both ESP32s use a weighted hop sequence that visits the three non-overlapping channels (1, 6, 11) more frequently:

```
1, 2, 6, 3, 4, 11, 5, 6, 7, 11, 8, 9, 6, 10, 11, 12, 13, 1
```

One full cycle is 18 steps × 50 ms = 900 ms.

### Timestamp correction

Boards record `millis()` (uptime), not wall-clock time. The Python host anchors each entry to real Unix time:

```
sniff_unix = python_rx_time - (report_ms - timestamp_ms) / 1000.0
```

Where `report_ms` is the board's clock at transmission and `timestamp_ms` is when each MAC was sniffed.

### Data format

Each sniffed entry is a 12-byte packed struct:

```c
struct __attribute__((packed)) PktEntry {
    uint8_t  mac[6];         // device MAC address
    int8_t   rssi;           // signal strength (dBm)
    uint8_t  channel;        // channel sniffed on
    uint32_t timestamp_ms;   // board uptime at capture
};
```

## Dependencies

- **Python:** `pyserial`, `supabase`, `python-dotenv`
- **Firmware:** Arduino framework, ESP-IDF WiFi (ESP32), NonOS SDK (ESP8266), via PlatformIO
