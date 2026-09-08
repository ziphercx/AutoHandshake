#ifndef USB_MANAGER_H
#define USB_MANAGER_H

#include <stdint.h>

// ==================== USB MSC SUPPORT CHECK ====================
#if defined(ARDUINO_USB_MODE) && defined(ARDUINO_USB_MSC_ON_BOOT)
    #define USB_MSC_ENABLED
#endif

// ==================== USB MSC FUNCTIONS ====================
#ifdef USB_MSC_ENABLED
void initUSB();
void deinitUSB();
void initUSBMSC();
void deinitUSBMSC();

// ==================== USB MSC CALLBACKS ====================
int32_t onWrite(uint32_t lba, uint32_t offset, uint8_t* buffer, uint32_t bufsize);
int32_t onRead(uint32_t lba, uint32_t offset, void* buffer, uint32_t bufsize);
bool onStartStop(uint8_t power_condition, bool start, bool load_eject);
#else
// Dummy functions for boards without USB MSC support
inline void initUSB() {}
inline void deinitUSB() {}
inline void initUSBMSC() {}
inline void deinitUSBMSC() {}
#endif

#endif