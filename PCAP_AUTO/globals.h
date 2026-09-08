#ifndef GLOBALS_H
#define GLOBALS_H

#include "config.h"
#include <FS.h>

// ==================== GLOBAL VARIABLES ====================
extern APInfo apList[MAX_APS];
extern HandshakeInfo handshakes[MAX_HANDSHAKES];
extern BeaconTracker beaconTrackers[MAX_BEACON_TRACKERS];
extern int apCount;
extern int handshakeCount;
extern int beaconTrackerCount;
extern uint32_t packetCount;
extern uint32_t deauthCount;
extern uint32_t filteredPacketCount;  // Count filtered packets

extern uint8_t currentChannel;
extern uint32_t channelStartTime;
extern bool isDeauthPhase;
extern bool isCapturing;
extern uint8_t cycleCount;

// Active channels (channels with APs)
extern uint8_t activeChannels[MAX_CHANNELS];
extern int activeChannelCount;
extern int activeChannelIndex;

extern File pcapFile;
extern bool fileOpen;
extern char currentFilename[32];

// PCAP write buffer
extern uint8_t pcapWriteBuffer[PCAP_BUFFER_SIZE];
extern uint16_t pcapBufferPos;

// Web Server Variables
extern bool webServerMode;
extern bool usbMscMode;
extern uint32_t buttonPressStart;
extern bool buttonPressed;

#endif