#ifndef HARDWARE_H
#define HARDWARE_H

#include "config.h"

// ==================== HARDWARE FUNCTIONS ====================
void initLED();
void initButton();
void blinkLED(int duration = 100);
void checkButton();

// ==================== OPTIMIZATION FUNCTIONS ====================
void optimizeMemory();

#endif