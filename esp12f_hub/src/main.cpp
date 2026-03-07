/*
 * ESP12F WiFi Hub
 *
 * Runs in 802.11 promiscuous mode on SNIFF_CHANNEL:
 *   • Detects ESP32 report frames (probe-requests with magic DE AD BE EF in body)
 *     and immediately prints their records to serial.
 *   • Records all other captured frames locally and flushes them to serial
 *     every REPORT_INTERVAL_MS.
 *
 * Serial output format (parsed by correlator.py):
 *   PKT,<src>,<mac>,<rssi>,<channel>
 *   src = 'L' (local), '1' (ESP32 #1), '2' (ESP32 #2)
 *   mac = 12 hex chars, e.g. AABBCCDDEEFF
 */

#include <Arduino.h>
#include <ESP8266WiFi.h>
extern "C" {
#include "user_interface.h"
}
#include <string.h>

// ─────────────────────── configuration ───────────────────────
#define HUB_CHANNEL         6          // channel ESP32 injects on
#define HOP_INTERVAL_MS     50UL       // dwell per channel while hopping
// Local flush interval — should match ESP32 REPORT_INTERVAL_MS so both
// sides emit data in the same cadence and the correlator sees overlap.
#ifndef REPORT_INTERVAL_MS
#define REPORT_INTERVAL_MS  30000UL    // 30 seconds (dev); 120000UL for production
#endif
// Weighted hop sequence matching esp32_sniffer — same pattern on both sensors
// ensures symmetric coverage.  18 steps × 50 ms = 900 ms full cycle.
static const uint8_t HOP_SEQ[]  = {1, 2, 6, 3, 4, 11, 5, 6, 7, 11, 8, 9, 6, 10, 11, 12, 13, 1};
#define HOP_SEQ_LEN (sizeof(HOP_SEQ) / sizeof(HOP_SEQ[0]))
#define MAX_ENTRIES         200

// ─────────────────────── shared data structure ───────────────
// Must be bit-for-bit identical to esp32_sniffer/src/main.cpp
struct __attribute__((packed)) PktEntry {
    uint8_t  mac[6];
    int8_t   rssi;
    uint8_t  channel;
};  // 8 bytes

// ─────────────────────── local capture buffer ────────────────
static PktEntry          g_local[MAX_ENTRIES];
static uint16_t          g_local_count = 0;
static volatile bool     g_snapping    = false;   // main loop is reading

// ─────────────────────── channel hopping state ───────────────
static uint8_t g_hop_idx = 0;
static uint8_t g_hop_ch  = HOP_SEQ[0];

// ─────────────────────── remote (ESP32) receive queue ────────
// Filled in the ISR; drained by loop() to avoid serial TX overflow.
// Allow up to 200 entries: ESP32 retries injection up to 15× per report,
// but we flush in loop() fast enough that this is just safety headroom.
#define MAX_REMOTE 200
struct RemoteEntry {
    uint8_t mac[6];
    int8_t  rssi;
    uint8_t channel;
    uint8_t devid;
};
static RemoteEntry       g_remote[MAX_REMOTE];
static volatile uint8_t  g_remote_count = 0;

// ─────────────────────── record a local capture ──────────────
static void record_local(const uint8_t *mac, int8_t rssi, uint8_t ch) {
    if (g_snapping) return;
    for (int i = 0; i < g_local_count; i++) {
        if (memcmp(g_local[i].mac, mac, 6) == 0) {
            if (rssi > g_local[i].rssi) {
                g_local[i].rssi    = rssi;
                g_local[i].channel = ch;
            }
            return;
        }
    }
    if (g_local_count < MAX_ENTRIES) {
        memcpy(g_local[g_local_count].mac, mac, 6);
        g_local[g_local_count].rssi    = rssi;
        g_local[g_local_count].channel = ch;
        g_local_count++;
    }
}

// ─────────────────────── ESP8266 promiscuous structs ─────────
/*
 * ESP8266 NonOS SDK sniffer callback buffer layout:
 *
 *  Management frames  (len == 128):
 *    [0..11]  RxCtrl  (rssi=buf[0], channel=buf[10]&0x0F)
 *    [12..123] first 112 bytes of 802.11 frame  ← sniffer_buf2.buf
 *    [124..127] cnt+len fields (ignored)
 *
 *  Data frames  (len != 128):
 *    [0..11]  RxCtrl
 *    [12..47] first 36 bytes of 802.11 frame    ← sniffer_buf.buf
 *    remainder: cnt / LenSeq fields (ignored)
 *
 * 802.11 MAC header offsets inside the frame bytes:
 *   [0-1]  FC, [2-3] Duration, [4-9] Addr1, [10-15] Addr2(src),
 *   [16-21] Addr3(BSSID), [22-23] SeqCtrl
 */
#define RXCTRL_SIZE  12   // sizeof(struct RxControl)

// ─────────────────────── promiscuous callback ─────────────────
void IRAM_ATTR sniffer_cb(uint8_t *buf, uint16_t len) {
    if (len < RXCTRL_SIZE + 24) return;    // need at least MAC header

    int8_t  rssi = static_cast<int8_t>(buf[0]);
    uint8_t ch   = buf[10] & 0x0F;

    const uint8_t *frame = buf + RXCTRL_SIZE;   // 802.11 frame start

    if (len == 128) {
        // ── Management frame (up to 112 bytes available) ──────────────────
        // Check for ESP32 report frame:
        //   FC[0]==0x40 (probe-request) and body bytes [24..27] == DE AD BE EF
        if (frame[0] == 0x40 && frame[1] == 0x00 &&
            frame[24] == 0xDE && frame[25] == 0xAD &&
            frame[26] == 0xBE && frame[27] == 0xEF) {

            uint8_t devid = frame[28];
            uint8_t count = frame[29];
            // Sanity: max 10 records fit within 82 bytes (8 bytes each)
            if (count > 10) count = 10;

            // Queue entries for loop() to print — avoids serial TX overflow
            // from printing 100 lines back-to-back in ISR context.
            PktEntry entry;
            for (uint8_t i = 0; i < count; i++) {
                if (g_remote_count >= MAX_REMOTE) break;
                memcpy(&entry, frame + 30 + i * sizeof(PktEntry), sizeof(PktEntry));
                RemoteEntry &r = g_remote[g_remote_count];
                memcpy(r.mac, entry.mac, 6);
                r.rssi    = entry.rssi;
                r.channel = entry.channel;
                r.devid   = devid;
                g_remote_count++;
            }
            return;
        }

        // Record locally by src MAC (Addr2) for cross-sensor correlation.
        record_local(frame + 10, rssi, ch);

    } else {
        // ── Data frame (first 36 bytes available) ─────────────────────────
        record_local(frame + 10, rssi, ch);
    }
}

// ─────────────────────── flush remote queue ──────────────────
static void flush_remote() {
    uint8_t count = g_remote_count;
    if (count == 0) return;
    for (uint8_t i = 0; i < count; i++) {
        RemoteEntry &r = g_remote[i];
        Serial.printf("PKT,%u,%02X%02X%02X%02X%02X%02X,%d,%u\n",
                      r.devid,
                      r.mac[0], r.mac[1], r.mac[2],
                      r.mac[3], r.mac[4], r.mac[5],
                      (int)r.rssi, (unsigned)r.channel);
        Serial.flush();   // block until TX buffer drains before next line
        yield();          // feed the watchdog on long flushes
    }
    g_remote_count = 0;
}


static void flush_local() {
    g_snapping = true;
    uint16_t count = g_local_count;
    PktEntry snap[MAX_ENTRIES];
    if (count > 0) memcpy(snap, g_local, count * sizeof(PktEntry));
    g_local_count = 0;
    g_snapping    = false;

    if (count == 0) {
        Serial.println("DBG,no local packets this interval");
        return;
    }
    Serial.printf("DBG,flushing %u local entries\n", count);
    for (uint16_t i = 0; i < count; i++) {
        Serial.printf("PKT,L,%02X%02X%02X%02X%02X%02X,%d,%u\n",
                      snap[i].mac[0], snap[i].mac[1], snap[i].mac[2],
                      snap[i].mac[3], snap[i].mac[4], snap[i].mac[5],
                      (int)snap[i].rssi, (unsigned)snap[i].channel);
    }
}

// ─────────────────────── setup / loop ─────────────────────────
void setup() {
    Serial.begin(115200);
    delay(500);
    Serial.printf("\nDBG,ESP12F hub starting hop=1..13 interval=%lus\n",
                  REPORT_INTERVAL_MS / 1000);

    WiFi.mode(WIFI_STA);
    WiFi.disconnect();

    g_hop_idx = 0;
    g_hop_ch  = HOP_SEQ[0];
    wifi_set_channel(g_hop_ch);
    wifi_set_promiscuous_rx_cb(sniffer_cb);  // set callback BEFORE enabling
    wifi_promiscuous_enable(1);

    Serial.printf("DBG,ESP12F sniffing ch=%d..%d hop=%lums interval=%lus\n",
                  1, 13, HOP_INTERVAL_MS, REPORT_INTERVAL_MS / 1000);
}

void loop() {
    static uint32_t last_flush = 0;
    static uint32_t last_hop   = 0;
    uint32_t now = millis();

    flush_remote();   // drain any queued ESP32 entries first

    // Channel hop through weighted sequence — disable promiscuous around
    // wifi_set_channel() to avoid ESP8266 exceptions during channel changes.
    if (now - last_hop >= HOP_INTERVAL_MS) {
        last_hop = now;
        g_hop_idx = (g_hop_idx + 1) % HOP_SEQ_LEN;
        g_hop_ch  = HOP_SEQ[g_hop_idx];
        wifi_promiscuous_enable(0);
        wifi_set_channel(g_hop_ch);
        wifi_promiscuous_enable(1);
    }

    if (now - last_flush >= REPORT_INTERVAL_MS) {
        last_flush = now;
        flush_local();
    }
    delay(10);
}
