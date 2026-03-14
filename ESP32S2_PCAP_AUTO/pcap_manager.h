#ifndef PCAP_MANAGER_H
#define PCAP_MANAGER_H

#include "config.h"
#include <Arduino.h>
#include "esp_wifi_types.h"

// ==================== PCAP FUNCTIONS ====================
void initSPIFFS();
void initWiFi();
String getUniqueFilename(const char* baseFilename);
void createPcapFile();
void closePcapFile();

// ==================== AP SCANNING FUNCTIONS ====================
void deepScanAllAPs();
String getSSIDFromBSSID(uint8_t* bssid);

// ==================== PACKET HANDLER ====================
void packetHandler(void* buf, wifi_promiscuous_pkt_type_t type);
void processEAPOLPacket(uint8_t* payload, uint16_t len, int eapolOffset);

// ==================== DEAUTH FUNCTIONS ====================
void sendDeauthToChannel(uint8_t channel);

// ==================== MAIN CAPTURE FUNCTIONS ====================
void startCapture();
void updateCapture();
void stopCapture();

#endif