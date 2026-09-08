#include "hardware.h"
#include "globals.h"
#include <WiFi.h>

// Forward declarations
void startWebServer();
void stopWebServer();

// ==================== LED FUNCTIONS ====================
void initLED() {
    pinMode(LED_PIN, OUTPUT);
    digitalWrite(LED_PIN, LOW);
    Serial.printf("[INIT] LED ready at IO%d\n", LED_PIN);
}

void initButton() {
    pinMode(BUTTON_PIN, INPUT_PULLUP);
    Serial.printf("[INIT] Button ready at IO%d\n", BUTTON_PIN);
}

void blinkLED(int duration) {
    digitalWrite(LED_PIN, HIGH);
    delay(duration);
    digitalWrite(LED_PIN, LOW);
}

// ==================== BUTTON FUNCTIONS ====================
void checkButton() {
    bool currentButtonState = digitalRead(BUTTON_PIN) == LOW;
    
    if (currentButtonState && !buttonPressed) {
        // Button just pressed
        buttonPressed = true;
        buttonPressStart = millis();
        if (webServerMode) {
            Serial.println("[BUTTON] Button pressed - hold 2s to return to capture mode");
        } else {
            Serial.println("[BUTTON] Button pressed - hold 2s to open Web Manager");
        }
    } else if (!currentButtonState && buttonPressed) {
        // Button just released
        buttonPressed = false;
        uint32_t pressDuration = millis() - buttonPressStart;
        
        if (pressDuration < 2000) {
            Serial.printf("[BUTTON] Short press %lu ms - need to hold 2s\n", pressDuration);
        }
    } else if (currentButtonState && buttonPressed) {
        // Button being held
        uint32_t pressDuration = millis() - buttonPressStart;
        
        // Blink LED to show status
        if (pressDuration >= 1000 && pressDuration < 5000) {
            static uint32_t lastBlink = 0;
            if (millis() - lastBlink >= 500) {
                lastBlink = millis();
                blinkLED(100);
            }
        }
        
        // Change mode immediately when 2 seconds reached (no need to wait for release)
        if (pressDuration >= 2000) {
            buttonPressed = false; // Reset state to prevent re-trigger
            
            if (webServerMode) {
                Serial.println("[BUTTON] Held 2s - returning to capture mode!");
                stopWebServer();
            } else {
                Serial.println("[BUTTON] Held 2s - opening Web File Manager!");
                startWebServer();
            }
        }
    }
}

// ==================== OPTIMIZATION FUNCTIONS ====================
void optimizeMemory() {
    // Clear WiFi scan cache
    WiFi.scanDelete();
    
    // Force garbage collection
    if (ESP.getFreeHeap() < 15000) {
        Serial.println("[OPTIMIZE] Low memory - cleaning up...");
        
        // Close file temporarily to flush buffer
        if (fileOpen && pcapFile) {
            pcapFile.flush();
        }
        
        delay(100);
    }
}