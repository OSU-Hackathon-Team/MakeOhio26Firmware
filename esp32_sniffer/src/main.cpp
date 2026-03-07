/*
 * ESP32 WiFi Sniffer + Reporter
 *
 * Promiscuously captures 802.11 frames across all 2.4 GHz channels (1–13),
 * recording a compact {mac, rssi, channel} entry per unique src-MAC.
 * Every REPORT_INTERVAL ms it switches to HUB_CHANNEL, injects raw
 * probe-request frames whose body carries the collected entries, then resumes
 * hopping.  The ESP12F hub picks these up and forwards them to the laptop.
 *
 * Build with DEVICE_ID=1 for the first ESP32, DEVICE_ID=2 for the second.
 */

#include <Arduino.h>
#include <WiFi.h>
#include "esp_wifi.h"
#include <string.h>

// ─────────────────────── configuration ───────────────────────
#ifndef DEVICE_ID
#define DEVICE_ID 1
#endif

#define HUB_CHANNEL        6          // channel ESP12F hub listens on
#ifndef HOP_INTERVAL_MS
#define HOP_INTERVAL_MS    50UL       // dwell time per channel while hopping
#endif
#ifndef REPORT_INTERVAL_MS
#define REPORT_INTERVAL_MS 30000UL    // 30 seconds
#endif
// Weighted hop sequence: ch 1, 6, 11 appear multiple times so the most-used
// non-overlapping 2.4 GHz channels get proportionally more coverage.
// 18 steps × 50 ms = 900 ms full cycle.
// ch1 ×2, ch6 ×3, ch11 ×4 — all others ×1.
static const uint8_t HOP_SEQ[]  = {1, 2, 6, 3, 4, 11, 5, 6, 7, 11, 8, 9, 6, 10, 11, 12, 13, 1};
#define HOP_SEQ_LEN (sizeof(HOP_SEQ) / sizeof(HOP_SEQ[0]))
// How many times to repeat the full injection burst so the hub lands on
// HUB_CHANNEL at least once.  Hub cycle = 900 ms; ch6 appears 3/18 of steps.
// 8 retries × ~250 ms each ≈ 2 s = ~2.2 hub cycles → very high hit probability.
#ifndef REPORT_RETRIES
#define REPORT_RETRIES     8
#endif
#define MAX_ENTRIES        100
#define RECS_PER_FRAME     10         // 82 bytes payload / 8 bytes per entry

// ─────────────────────── shared data structures ──────────────
// Must be identical to the struct used in esp12f_hub/src/main.cpp
struct __attribute__((packed)) PktEntry {
    uint8_t  mac[6];
    int8_t   rssi;
    uint8_t  channel;
};  // 8 bytes

static PktEntry          g_buf[MAX_ENTRIES];
static volatile uint16_t g_count = 0;
static uint8_t           g_my_mac[6];
static portMUX_TYPE      g_mux = portMUX_INITIALIZER_UNLOCKED;
static uint8_t           g_hop_idx = 0;                  // index into HOP_SEQ
static uint8_t           g_hop_ch  = HOP_SEQ[0];         // current channel

// ─────────────────────── buffer helpers ──────────────────────
static void IRAM_ATTR record(const uint8_t *mac, int8_t rssi, uint8_t ch) {
    portENTER_CRITICAL_ISR(&g_mux);
    for (int i = 0; i < g_count; i++) {
        if (memcmp(g_buf[i].mac, mac, 6) == 0) {
            if (rssi > g_buf[i].rssi) {
                g_buf[i].rssi    = rssi;
                g_buf[i].channel = ch;
            }
            portEXIT_CRITICAL_ISR(&g_mux);
            return;
        }
    }
    if (g_count < MAX_ENTRIES) {
        memcpy(g_buf[g_count].mac, mac, 6);
        g_buf[g_count].rssi    = rssi;
        g_buf[g_count].channel = ch;
        g_count++;
    }
    portEXIT_CRITICAL_ISR(&g_mux);
}

// ─────────────────────── promiscuous callback ─────────────────
/*
 * 802.11 MAC header layout (data / management frames):
 *   [0-1]  Frame Control
 *   [2-3]  Duration
 *   [4-9]  Addr1 (dst)
 *   [10-15] Addr2 (src)
 *   [16-21] Addr3 (BSSID)
 *   [22-23] Sequence Control
 */
static void IRAM_ATTR sniffer_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (type == WIFI_PKT_MISC) return;

    const wifi_promiscuous_pkt_t *pkt =
        reinterpret_cast<const wifi_promiscuous_pkt_t *>(buf);
    const uint8_t *frame = pkt->payload;
    int len = pkt->rx_ctrl.sig_len;

    if (len < 24) return;

    // Skip our own injected probe-request frames (FC=0x40 + magic in body)
    if (frame[0] == 0x40 && len >= 30 &&
        frame[24] == 0xDE && frame[25] == 0xAD &&
        frame[26] == 0xBE && frame[27] == 0xEF) return;

    // Skip frames originating from our own MAC (Addr2)
    if (memcmp(frame + 10, g_my_mac, 6) == 0) return;

    record(frame + 10, pkt->rx_ctrl.rssi, pkt->rx_ctrl.channel);
}

// ─────────────────────── raw frame injection ──────────────────
/*
 * Probe-request frame template (24-byte 802.11 MAC header):
 *   FC  = 0x40 0x00  (management, subtype=probe-request)
 *   Dur = 0x00 0x00
 *   A1  = FF:FF:FF:FF:FF:FF  (broadcast)
 *   A2  = <filled at runtime from g_my_mac>
 *   A3  = FF:FF:FF:FF:FF:FF  (broadcast BSSID)
 *   Seq = 0x00 0x00
 *
 * Followed by payload:
 *   [0-3]  magic   = DE AD BE EF
 *   [4]    device_id
 *   [5]    count   (number of PktEntry records following)
 *   [6..]  PktEntry[]
 */
static const uint8_t PROBE_HDR[24] = {
    0x40, 0x00,                                     // Frame Control
    0x00, 0x00,                                     // Duration
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,             // Addr1: broadcast
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,             // Addr2: filled at runtime
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,             // Addr3: broadcast
    0x00, 0x00                                      // Sequence Control
};

// Maximum frame size: 24 header + 6 payload header + 10 * 8 records = 110
static uint8_t s_frame_buf[24 + 6 + RECS_PER_FRAME * sizeof(PktEntry)];

static void send_report() {
    // Atomically snapshot and clear the buffer
    portENTER_CRITICAL(&g_mux);
    uint16_t count = g_count;
    PktEntry snap[MAX_ENTRIES];
    if (count > 0) memcpy(snap, g_buf, count * sizeof(PktEntry));
    g_count = 0;
    portEXIT_CRITICAL(&g_mux);

    if (count == 0) {
        Serial.printf("[ESP32-%d] nothing to report\n", DEVICE_ID);
        return;
    }
    Serial.printf("[ESP32-%d] sending %u entries\n", DEVICE_ID, count);

    // Disable promiscuous + switch to hub channel for clean TX
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_channel(HUB_CHANNEL, WIFI_SECOND_CHAN_NONE);
    delay(10);  // let WiFi stack settle before TX

    memcpy(s_frame_buf, PROBE_HDR, 24);
    memcpy(s_frame_buf + 10, g_my_mac, 6);   // fill Addr2

    // Retry the full burst REPORT_RETRIES times so the hub (which is also
    // hopping channels) is on HUB_CHANNEL for at least one transmission.
    for (int retry = 0; retry < REPORT_RETRIES; retry++) {
        for (int off = 0; off < count; off += RECS_PER_FRAME) {
            int batch = count - off;
            if (batch > RECS_PER_FRAME) batch = RECS_PER_FRAME;

            uint8_t *p     = s_frame_buf + 24;
            p[0] = 0xDE; p[1] = 0xAD; p[2] = 0xBE; p[3] = 0xEF;
            p[4] = (uint8_t)DEVICE_ID;
            p[5] = (uint8_t)batch;
            memcpy(p + 6, &snap[off], batch * sizeof(PktEntry));

            int frame_len = 24 + 6 + batch * (int)sizeof(PktEntry);
            esp_err_t err = esp_wifi_80211_tx(WIFI_IF_AP, s_frame_buf, frame_len, true);
            if (err != ESP_OK)
                Serial.printf("[ESP32-%d] tx err %d\n", DEVICE_ID, err);

            delay(25);  // small gap between back-to-back frames
        }
        delay(25);  // brief gap between retries (no need to pad to 200ms with 50ms dwell)
    }

    // Resume hopping from the channel we were on before the report
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(sniffer_cb);
    esp_wifi_set_channel(g_hop_ch, WIFI_SECOND_CHAN_NONE);
}

// ─────────────────────── setup / loop ─────────────────────────
void setup() {
    Serial.begin(115200);
    delay(500);
    Serial.printf("\n[ESP32-%d] starting, hub_ch=%d, hop_interval=%lums, report_interval=%lus\n",
                  DEVICE_ID, HUB_CHANNEL, HOP_INTERVAL_MS, REPORT_INTERVAL_MS / 1000);

    // Start as a hidden AP with 0 max connections — gives us a TX interface
    // without actually accepting clients.
    WiFi.mode(WIFI_AP);
    WiFi.softAP("_sniff", "", HUB_CHANNEL, /*hidden=*/1, /*maxconn=*/0);

    esp_wifi_get_mac(WIFI_IF_AP, g_my_mac);
    Serial.printf("[ESP32-%d] MAC %02X:%02X:%02X:%02X:%02X:%02X\n",
                  DEVICE_ID,
                  g_my_mac[0], g_my_mac[1], g_my_mac[2],
                  g_my_mac[3], g_my_mac[4], g_my_mac[5]);

    // Capture everything — length check in callback handles short frames
    wifi_promiscuous_filter_t filt = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_ALL
    };
    esp_wifi_set_promiscuous_filter(&filt);
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(sniffer_cb);

    // Start hopping from channel 1
    g_hop_ch = 1;
    esp_wifi_set_channel(g_hop_ch, WIFI_SECOND_CHAN_NONE);
    Serial.printf("[ESP32-%d] sniffing all channels\n", DEVICE_ID);
}

void loop() {
    static uint32_t last_report = 0;
    static uint32_t last_hop    = 0;
    uint32_t now = millis();

    // Channel hop through weighted sequence
    if (now - last_hop >= HOP_INTERVAL_MS) {
        last_hop = now;
        g_hop_idx = (g_hop_idx + 1) % HOP_SEQ_LEN;
        g_hop_ch  = HOP_SEQ[g_hop_idx];
        esp_wifi_set_channel(g_hop_ch, WIFI_SECOND_CHAN_NONE);
    }

    // Periodic report (switches to HUB_CHANNEL internally, then restores g_hop_ch)
    if (now - last_report >= REPORT_INTERVAL_MS) {
        last_report = now;
        send_report();
    }
    delay(100);
}
