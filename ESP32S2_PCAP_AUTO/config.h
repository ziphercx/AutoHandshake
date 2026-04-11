#ifndef CONFIG_H
#define CONFIG_H

#include <Arduino.h>

// ==================== CONFIGURATION ====================
#define MAX_APS 50
#define MAX_BEACON_TRACKERS 100  // สำหรับ deduplicate beacon
#define MAX_HANDSHAKES 20
#define BEACON_DEDUPE_INTERVAL 100  // 100ms
#define PCAP_BUFFER_SIZE 2048  // Buffer สำหรับเขียนไฟล์
#define DEAUTH_DURATION 2000    // 2 วินาที (ลดจาก 3)
#define CAPTURE_DURATION 5000   // 5 วินาที (ลดจาก 10)
#define DEAUTH_INTERVAL 50      // ส่ง deauth ทุก 50ms

// ==================== WIFI BAND CONFIGURATION ====================
// ESP32-C5 รองรับ WiFi 6 (2.4GHz + 5GHz)
#if defined(CONFIG_IDF_TARGET_ESP32C5)
  #define WIFI_5GHZ_SUPPORTED 1
  #define MAX_CHANNELS_24GHZ 14    // 2.4GHz: CH 1-14
  #define MAX_CHANNELS_5GHZ 25     // 5GHz: CH 36,40,44,48,52,56,60,64,100,104,108,112,116,120,124,128,132,136,140,144,149,153,157,161,165
  #define MAX_CHANNELS (MAX_CHANNELS_24GHZ + MAX_CHANNELS_5GHZ)
#else
  // ESP32 / S2 / S3 / C3 รองรับเฉพาะ 2.4GHz
  #define WIFI_5GHZ_SUPPORTED 0
  #define MAX_CHANNELS_24GHZ 14
  #define MAX_CHANNELS MAX_CHANNELS_24GHZ
#endif

// ==================== LED PIN CONFIGURATION ====================
#if defined(CONFIG_IDF_TARGET_ESP32S2)
  #define LED_PIN 17
#elif defined(CONFIG_IDF_TARGET_ESP32S3)
  #define LED_PIN 48
#elif defined(CONFIG_IDF_TARGET_ESP32C3)
  #define LED_PIN 8
#elif defined(CONFIG_IDF_TARGET_ESP32C5)
  #define LED_PIN 8
#elif defined(CONFIG_IDF_TARGET_ESP32)
  #define LED_PIN 2
#else
  #define LED_PIN -1
#endif

#define BUTTON_PIN 0            // ปุ่มสำหรับเปิด Web File Manager

// ==================== STRUCTURES ====================
struct APInfo {
    char ssid[33];
    uint8_t bssid[6];
    uint8_t channel;
    int rssi;
};

// สำหรับ deduplicate beacon
struct BeaconTracker {
    uint8_t bssid[6];
    uint32_t lastSeen;
    bool operator==(const uint8_t* other_bssid) const {
        return memcmp(bssid, other_bssid, 6) == 0;
    }
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