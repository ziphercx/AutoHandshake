#ifndef CONFIG_H
#define CONFIG_H

#include <Arduino.h>

// ==================== CONFIGURATION ====================
#define MAX_APS 50
#define MAX_CHANNELS 11
#define MAX_HANDSHAKES 20
#define DEAUTH_DURATION 2000    // 2 วินาที (ลดจาก 3)
#define CAPTURE_DURATION 5000   // 5 วินาที (ลดจาก 10)
#define DEAUTH_INTERVAL 50      // ส่ง deauth ทุก 50ms
#define LED_PIN 17              // LED สำหรับแสดงสถานะ handshake
#define BUTTON_PIN 0            // ปุ่มสำหรับเปิด Web File Manager

// ==================== STRUCTURES ====================
struct APInfo {
    char ssid[33];
    uint8_t bssid[6];
    uint8_t channel;
    int rssi;
};

struct HandshakeInfo {
    uint8_t bssid[6];
    uint8_t channel;
    uint8_t messageFlags;  // bit 0=M1, bit 1=M2, bit 2=M3, bit 3=M4
    bool complete;
    uint32_t timestamp;
};

// ==================== PCAP HEADERS ====================
typedef struct {
    uint32_t magic_number;   // 0xa1b2c3d4
    uint16_t version_major;  // 2
    uint16_t version_minor;  // 4
    int32_t  thiszone;       // 0
    uint32_t sigfigs;        // 0
    uint32_t snaplen;        // 65535
    uint32_t network;        // 105 (IEEE 802.11)
} pcap_hdr_t;

typedef struct {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
} pcaprec_hdr_t;

#endif