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
 *
 * Debug option: define TARGET_MAC as a byte-array literal to lock onto the
 * channel where that MAC is first seen instead of continuing to hop.
 *   build_flags = -DTARGET_MAC="{0xAA,0xBB,0xCC,0xDD,0xEE,0xFF}"
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
#define REPORT_INTERVAL_MS  10000UL    // 10 seconds (dev); 120000UL for production
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
    uint32_t timestamp_ms;   // millis() on the originating ESP32 when sniffed
};  // 12 bytes

// ─────────────────────── local capture buffer ────────────────
static PktEntry          g_local[MAX_ENTRIES];
static uint16_t          g_local_count    = 0;
static uint16_t          g_local_overflow = 0;    // entries evicted because buffer was full
static volatile bool     g_snapping       = false;   // main loop is reading

// ─────────────────────── channel hopping state ───────────────
// Hub starts at offset 12 in the hop sequence (= 2/3 of 18 steps) so that
// ESP32 #1 (offset 0), ESP32 #2 (offset 6), and the hub (offset 12) all
// cover different channels simultaneously, tripling effective coverage.
#define HUB_HOP_OFFSET 12
static uint8_t g_hop_idx = HUB_HOP_OFFSET;
static uint8_t g_hop_ch  = HOP_SEQ[HUB_HOP_OFFSET];

#ifdef TARGET_MAC
static const uint8_t    TARGET_MAC_BYTES[] = {TARGET_MAC_0, TARGET_MAC_1, TARGET_MAC_2,
                                              TARGET_MAC_3, TARGET_MAC_4, TARGET_MAC_5};
static volatile bool    g_target_locked    = false;
static volatile uint8_t g_locked_ch        = 0;
static bool             g_target_logged    = false;
#endif

// ─────────────────────── remote (ESP32) receive queue ────────
// Filled in the ISR; drained by loop() to avoid serial TX overflow.
// Allow up to 200 entries: ESP32 retries injection up to 15× per report,
// but we flush in loop() fast enough that this is just safety headroom.
#define MAX_REMOTE 200
struct RemoteEntry {
    uint8_t  mac[6];
    int8_t   rssi;
    uint8_t  channel;
    uint8_t  devid;
    uint32_t timestamp_ms;   // millis() on ESP32 when sniffed
    uint32_t report_ms;      // millis() on ESP32 at start of send_report()
};
static RemoteEntry       g_remote[MAX_REMOTE];
static volatile uint8_t  g_remote_count = 0;

// ─────────────────────── persistent dedup store ──────────────
// Tracks every entry printed by flush_remote() so that retries arriving after
// the queue has already been flushed are still recognised as duplicates.
// Keyed on all output fields (devid + mac + rssi + channel + timestamp_ms +
// report_ms); evicted per-devid whenever a new report_ms is detected, which
// happens at most once every REPORT_INTERVAL_MS.
struct SeenKey {
    uint8_t  mac[6];
    uint8_t  devid;
    int8_t   rssi;
    uint8_t  channel;
    uint32_t timestamp_ms;
    uint32_t report_ms;
};  // 18 bytes
#define MAX_SEEN (MAX_ENTRIES * 2)   // headroom for up to 2 ESP32s
static SeenKey   g_seen[MAX_SEEN];
static uint16_t  g_seen_count = 0;
static uint32_t  g_devid_report_ms[3] = {0, 0, 0};  // last report_ms seen per devid

// ─────────────────────── record a local capture ──────────────
static void record_local(const uint8_t *mac, int8_t rssi, uint8_t ch) {
    if (g_snapping) return;
    uint32_t now_ms = millis();
    for (int i = 0; i < g_local_count; i++) {
        if (memcmp(g_local[i].mac, mac, 6) == 0) {
            if (rssi > g_local[i].rssi) {
                g_local[i].rssi         = rssi;
                g_local[i].channel      = ch;
                g_local[i].timestamp_ms = now_ms;
            }
            return;
        }
    }
    if (g_local_count < MAX_ENTRIES) {
        memcpy(g_local[g_local_count].mac, mac, 6);
        g_local[g_local_count].rssi         = rssi;
        g_local[g_local_count].channel      = ch;
        g_local[g_local_count].timestamp_ms = now_ms;
        g_local_count++;
    } else {
        // Buffer full: evict the oldest entry so recent observations are preserved.
        int oldest = 0;
        for (int i = 1; i < MAX_ENTRIES; i++) {
            if ((int32_t)(g_local[i].timestamp_ms - g_local[oldest].timestamp_ms) < 0)
                oldest = i;
        }
        memcpy(g_local[oldest].mac, mac, 6);
        g_local[oldest].rssi         = rssi;
        g_local[oldest].channel      = ch;
        g_local[oldest].timestamp_ms = now_ms;
        g_local_overflow++;
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
    if (len < RXCTRL_SIZE + 10) return;    // need at least Addr1 for control frames

    int8_t  rssi = static_cast<int8_t>(buf[0]);
    uint8_t ch   = buf[10] & 0x0F;

    const uint8_t *frame = buf + RXCTRL_SIZE;   // 802.11 frame start

    if (len == 128) {
        // ── Management frame (up to 112 bytes available) ──────────────────
        if (len < RXCTRL_SIZE + 24) return;
        // Check for ESP32 report frame:
        //   FC[0]==0x40 (probe-request) and body bytes [24..27] == DE AD BE EF
        if (frame[0] == 0x40 && frame[1] == 0x00 &&
            frame[24] == 0xDE && frame[25] == 0xAD &&
            frame[26] == 0xBE && frame[27] == 0xEF) {

            uint8_t devid = frame[28];
            uint8_t count = frame[29];
            uint32_t report_ms;
            memcpy(&report_ms, frame + 30, 4);   // millis() on ESP32 at send_report()
            // Sanity: max 6 records fit within the 82-byte body window
            if (count > 6) count = 6;

            // Queue entries for loop() to print — avoids serial TX overflow
            // from printing 100 lines back-to-back in ISR context.
            // Dedup: skip entries where all fields (devid, mac, rssi, channel,
            // timestamp_ms) are identical to an already-queued entry.  This
            // prevents the same 200-entry report from being queued 4× when the
            // ESP32 sends REPORT_RETRIES identical retries.
            PktEntry entry;
            for (uint8_t i = 0; i < count; i++) {
                if (g_remote_count >= MAX_REMOTE) break;
                memcpy(&entry, frame + 34 + i * sizeof(PktEntry), sizeof(PktEntry));
                bool dup = false;
                for (uint8_t k = 0; k < g_remote_count; k++) {
                    if (g_remote[k].devid        == devid             &&
                        g_remote[k].rssi         == entry.rssi        &&
                        g_remote[k].channel      == entry.channel     &&
                        g_remote[k].timestamp_ms == entry.timestamp_ms &&
                        memcmp(g_remote[k].mac, entry.mac, 6) == 0) {
                        dup = true;
                        break;
                    }
                }
                if (dup) continue;
                RemoteEntry &r = g_remote[g_remote_count];
                memcpy(r.mac, entry.mac, 6);
                r.rssi         = entry.rssi;
                r.channel      = entry.channel;
                r.devid        = devid;
                r.timestamp_ms = entry.timestamp_ms;
                r.report_ms    = report_ms;
                g_remote_count++;
            }
            return;
        }

        // Management frame: Addr2 is always the sender — record it.
#ifdef TARGET_MAC
        if (!g_target_locked && memcmp(frame + 10, TARGET_MAC_BYTES, 6) == 0) {
            g_target_locked = true;
            g_locked_ch     = ch;
        }
        if (g_target_locked && memcmp(frame + 10, TARGET_MAC_BYTES, 6) != 0) return;
#endif
        record_local(frame + 10, rssi, ch);

    } else {
        // ── Data or Control frame (first 36 bytes available) ──────────────
        // Only process 802.11 data frames (type bits [2:3] of FC[0] == 0b10).
        // Ignore control frames (0b01) to avoid recording AP/broadcast MACs
        // from short ACK/CTS frames whose Addr2 may be absent or garbage.
        uint8_t fc_type = (frame[0] >> 2) & 0x03;
        if (fc_type != 0x02) return;   // skip non-data frames (control = 0x01)

        if (len < RXCTRL_SIZE + 24) return;

        // Determine client MAC using DS bits in FC[1]:
        //   bit 0 = To DS   (STA→AP): Addr2 = client
        //   bit 1 = From DS (AP→STA): Addr1 = client (phone MAC in downlink)
        bool to_ds   = frame[1] & 0x01;
        bool from_ds = frame[1] & 0x02;

        const uint8_t *client_mac;
        if (from_ds && !to_ds) {
            // Downlink (AP→phone): phone MAC is in Addr1
            client_mac = frame + 4;
        } else {
            // Uplink (phone→AP), IBSS, or WDS: sender in Addr2
            client_mac = frame + 10;
        }

        // Skip broadcast/multicast
        if (client_mac[0] & 0x01) return;
#ifdef TARGET_MAC
        if (!g_target_locked && memcmp(client_mac, TARGET_MAC_BYTES, 6) == 0) {
            g_target_locked = true;
            g_locked_ch     = ch;
        }
        if (g_target_locked && memcmp(client_mac, TARGET_MAC_BYTES, 6) != 0) return;
#endif
        record_local(client_mac, rssi, ch);
    }
}

// ─────────────────────── flush remote queue ──────────────────
static void flush_remote() {
    uint8_t count = g_remote_count;
    if (count == 0) return;
    for (uint8_t i = 0; i < count; i++) {
        RemoteEntry &r = g_remote[i];
        uint8_t didx = (r.devid <= 2) ? r.devid : 0;

        // When a new report_ms is seen for this devid, the prior report cycle is
        // over — evict its stale seen entries so the new report prints cleanly.
        if (g_devid_report_ms[didx] != r.report_ms) {
            g_devid_report_ms[didx] = r.report_ms;
            uint16_t w = 0;
            for (uint16_t k = 0; k < g_seen_count; k++)
                if (g_seen[k].devid != r.devid)
                    g_seen[w++] = g_seen[k];
            g_seen_count = w;
        }

        // Skip if all fields were already printed in a previous flush cycle.
        // This deduplcates retries that arrive after the queue has been cleared.
        bool dup = false;
        for (uint16_t k = 0; k < g_seen_count; k++) {
            if (g_seen[k].devid        == r.devid        &&
                g_seen[k].rssi         == r.rssi          &&
                g_seen[k].channel      == r.channel       &&
                g_seen[k].timestamp_ms == r.timestamp_ms  &&
                g_seen[k].report_ms    == r.report_ms     &&
                memcmp(g_seen[k].mac, r.mac, 6) == 0) {
                dup = true;
                break;
            }
        }
        if (dup) continue;

        Serial.printf("PKT,%u,%02X%02X%02X%02X%02X%02X,%d,%u,%lu,%lu\n",
                      r.devid,
                      r.mac[0], r.mac[1], r.mac[2],
                      r.mac[3], r.mac[4], r.mac[5],
                      (int)r.rssi, (unsigned)r.channel,
                      (unsigned long)r.timestamp_ms,
                      (unsigned long)r.report_ms);
        Serial.flush();
        yield();

        // Record as printed so subsequent retries are recognised as duplicates.
        if (g_seen_count < MAX_SEEN) {
            SeenKey &sk = g_seen[g_seen_count++];
            memcpy(sk.mac, r.mac, 6);
            sk.devid        = r.devid;
            sk.rssi         = r.rssi;
            sk.channel      = r.channel;
            sk.timestamp_ms = r.timestamp_ms;
            sk.report_ms    = r.report_ms;
        }
    }
    // Compact any entries that arrived via ISR during the flush above.
    // Briefly disable promiscuous mode so the callback cannot write to the
    // queue while we move and reset it.
    wifi_promiscuous_enable(0);
    uint8_t leftover = g_remote_count - count;
    if (leftover > 0)
        memmove(g_remote, g_remote + count, leftover * sizeof(RemoteEntry));
    g_remote_count = leftover;
    wifi_promiscuous_enable(1);
}


static void flush_local() {
    g_snapping = true;
    uint16_t count    = g_local_count;
    uint16_t overflow = g_local_overflow;
    PktEntry snap[MAX_ENTRIES];
    if (count > 0) memcpy(snap, g_local, count * sizeof(PktEntry));
    uint32_t report_ms = millis();   // anchor for epoch correction, same as ESP32 pattern
    g_local_count    = 0;
    g_local_overflow = 0;
    g_snapping       = false;

    if (count == 0) {
        Serial.println("DBG,no local packets this interval");
        return;
    }
    if (overflow > 0)
        Serial.printf("DBG,WARNING: %u local evictions (buffer full)\n", overflow);
    Serial.printf("DBG,flushing %u local entries\n", count);
    for (uint16_t i = 0; i < count; i++) {
        Serial.printf("PKT,L,%02X%02X%02X%02X%02X%02X,%d,%u,%lu,%lu\n",
                      snap[i].mac[0], snap[i].mac[1], snap[i].mac[2],
                      snap[i].mac[3], snap[i].mac[4], snap[i].mac[5],
                      (int)snap[i].rssi, (unsigned)snap[i].channel,
                      (unsigned long)snap[i].timestamp_ms,
                      (unsigned long)report_ms);
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

    // g_hop_idx and g_hop_ch already initialized to HUB_HOP_OFFSET above
    wifi_set_channel(g_hop_ch);
    wifi_set_promiscuous_rx_cb(sniffer_cb);  // set callback BEFORE enabling
    wifi_promiscuous_enable(1);

    Serial.printf("DBG,ESP12F sniffing ch=%d..%d hop=%lums interval=%lus\n",
                  1, 13, HOP_INTERVAL_MS, REPORT_INTERVAL_MS / 1000);
#ifdef TARGET_MAC
    Serial.println("DBG,TARGET_MAC mode — will lock channel on first sighting");
#endif
}

void loop() {
    static uint32_t last_flush = 0;
    static uint32_t last_hop   = 0;
    uint32_t now = millis();

    flush_remote();   // drain any queued ESP32 entries first

    // Channel hop through weighted sequence — disable promiscuous around
    // wifi_set_channel() to avoid ESP8266 exceptions during channel changes.
#ifdef TARGET_MAC
    if (g_target_locked && !g_target_logged) {
        g_target_logged = true;
        g_hop_ch = g_locked_ch;
        wifi_promiscuous_enable(0);
        wifi_set_channel(g_hop_ch);
        wifi_promiscuous_enable(1);
        Serial.printf("DBG,TARGET FOUND — alternating ch%d/ch%d (hub_ch)\n", g_hop_ch, HUB_CHANNEL);
    }
#endif
    if (now - last_hop >= HOP_INTERVAL_MS) {
        last_hop = now;
#ifdef TARGET_MAC
        if (g_target_locked) {
            // Alternate every hop tick between the locked channel and HUB_CHANNEL
            // so ESP32 reports are never missed.  50 ms on each gives more
            // HUB_CHANNEL coverage than normal hopping (50 % vs ~17 %).
            g_hop_ch = (g_hop_ch == g_locked_ch && g_locked_ch != HUB_CHANNEL)
                       ? HUB_CHANNEL : g_locked_ch;
        } else {
#endif
        g_hop_idx = (g_hop_idx + 1) % HOP_SEQ_LEN;
        g_hop_ch  = HOP_SEQ[g_hop_idx];
#ifdef TARGET_MAC
        }
#endif
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
