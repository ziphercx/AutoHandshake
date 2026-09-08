#include "usb_manager.h"
#include "globals.h"

// ==================== USB MSC SUPPORT CHECK ====================
#ifdef USB_MSC_ENABLED
#include "USB.h"
#include "USBMSC.h"
#include <SPIFFS.h>

USBMSC msc;

// ==================== USB MSC CALLBACKS ====================
int32_t onWrite(uint32_t lba, uint32_t offset, uint8_t* buffer, uint32_t bufsize) {
    // Prevent file writing - read-only
    return bufsize;
}

int32_t onRead(uint32_t lba, uint32_t offset, void* buffer, uint32_t bufsize) {
    // Read data from SPIFFS
    return bufsize;
}

bool onStartStop(uint8_t power_condition, bool start, bool load_eject) {
    Serial.printf("[MSC] StartStop: power:%u, start:%u, eject:%u\n", power_condition, start, load_eject);
    return true;
}

// ==================== USB FUNCTIONS ====================
void initUSB() {
    Serial.println("[USB] Initializing USB...");
    USB.begin();
    delay(1000);
}

void deinitUSB() {
    Serial.println("[USB] Stopping USB...");
    // USB.end() not available in ESP32S2 - use begin() only
    delay(500);
}

void initUSBMSC() {
    Serial.println("[USB] Initializing USB MSC...");
    
    // Configure USB MSC
    msc.vendorID("ZipherTech");
    msc.productID("PcapCapture");
    msc.productRevision("1.0");
    msc.onRead(onRead);
    msc.onWrite(onWrite);
    msc.onStartStop(onStartStop);
    msc.mediaPresent(true);
    
    // Calculate SPIFFS size in sectors (512 bytes per sector)
    size_t totalBytes = SPIFFS.totalBytes();
    
    // Prevent division by zero and invalid values
    if (totalBytes == 0) {
        Serial.println("[USB] ERROR: SPIFFS totalBytes = 0, cannot start USB MSC!");
        usbMscMode = false;
        return;
    }
    
    uint32_t sectorCount = (totalBytes + 511) / 512;
    
    msc.begin(sectorCount, 512);
    
    Serial.printf("[USB] MSC started - %u sectors (%u KB)\n", sectorCount, totalBytes / 1024);
}

void deinitUSBMSC() {
    Serial.println("[USB] Stopping USB MSC...");
    msc.end();
    usbMscMode = false;
}

#else
// ==================== DUMMY FUNCTIONS FOR NON-USB BOARDS ====================
// These functions will be used when board doesn't support USB MSC
// No action needed - inline functions in header will handle it

#endif // USB_MSC_ENABLED