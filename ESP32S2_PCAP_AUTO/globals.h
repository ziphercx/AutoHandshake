#ifndef GLOBALS_H
#define GLOBALS_H

#include "config.h"
#include <FS.h>

// ==================== GLOBAL VARIABLES ====================
extern APInfo apList[MAX_APS];
extern HandshakeInfo handshakes[MAX_HANDSHAKES];
extern int apCount;
extern int handshakeCount;
extern uint32_t packetCount;
extern uint32_t deauthCount;

extern uint8_t currentChannel;
extern uint32_t channelStartTime;
extern bool isDeauthPhase;
extern bool isCapturing;
extern uint8_t cycleCount;

// Active channels (ช่องที่มี AP)
extern uint8_t activeChannels[MAX_CHANNELS];
extern int activeChannelCount;
extern int activeChannelIndex;

extern File pcapFile;
extern bool fileOpen;
extern char currentFilename[32];

// Web Server Variables
extern bool webServerMode;
extern bool usbMscMode;
extern uint32_t buttonPressStart;
extern bool buttonPressed;

#endif