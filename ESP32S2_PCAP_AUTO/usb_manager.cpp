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
    // ป้องกันการเขียนไฟล์ - อ่านอย่างเดียว
    return bufsize;
}

int32_t onRead(uint32_t lba, uint32_t offset, void* buffer, uint32_t bufsize) {
    // อ่านข้อมูลจาก SPIFFS
    return bufsize;
}

bool onStartStop(uint8_t power_condition, bool start, bool load_eject) {
    Serial.printf("[MSC] StartStop: power:%u, start:%u, eject:%u\n", power_condition, start, load_eject);
    return true;
}

// ==================== USB FUNCTIONS ====================
void initUSB() {
    Serial.println("[USB] เริ่มต้น USB...");
    USB.begin();
    delay(1000);
}

void deinitUSB() {
    Serial.println("[USB] ปิด USB...");
    // USB.end() ไม่มีใน ESP32S2 - ใช้ begin() เท่านั้น
    delay(500);
}

void initUSBMSC() {
    Serial.println("[USB] เริ่มต้น USB MSC...");
    
    // ตั้งค่า USB MSC
    msc.vendorID("ZipherTech");
    msc.productID("PcapCapture");
    msc.productRevision("1.0");
    msc.onRead(onRead);
    msc.onWrite(onWrite);
    msc.onStartStop(onStartStop);
    msc.mediaPresent(true);
    
    // คำนวณขนาด SPIFFS เป็น sectors (512 bytes per sector)
    size_t totalBytes = SPIFFS.totalBytes();
    uint32_t sectorCount = (totalBytes + 511) / 512;
    
    msc.begin(sectorCount, 512);
    
    Serial.printf("[USB] MSC เริ่มแล้ว - %u sectors (%u KB)\n", sectorCount, totalBytes / 1024);
}

void deinitUSBMSC() {
    Serial.println("[USB] ปิด USB MSC...");
    msc.end();
    usbMscMode = false;
}

#else
// ==================== DUMMY FUNCTIONS FOR NON-USB BOARDS ====================
// ฟังก์ชันเหล่านี้จะถูกใช้เมื่อ board ไม่รองรับ USB MSC
// ไม่ต้องทำอะไร - inline functions ใน header จะจัดการให้

#endif // USB_MSC_ENABLED