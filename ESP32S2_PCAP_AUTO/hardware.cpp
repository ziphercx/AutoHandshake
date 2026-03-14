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
    Serial.printf("[INIT] LED พร้อมที่ IO%d\n", LED_PIN);
}

void initButton() {
    pinMode(BUTTON_PIN, INPUT_PULLUP);
    Serial.printf("[INIT] Button พร้อมที่ IO%d\n", BUTTON_PIN);
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
        // ปุ่มเพิ่งถูกกด
        buttonPressed = true;
        buttonPressStart = millis();
        if (webServerMode) {
            Serial.println("[BUTTON] กดปุ่ม - กดค้าง 3 วิเพื่อกลับสู่โหมดดักจับ");
        } else {
            Serial.println("[BUTTON] กดปุ่ม - กดค้าง 3 วิเพื่อเปิด Web Manager");
        }
    } else if (!currentButtonState && buttonPressed) {
        // ปุ่มเพิ่งถูกปล่อย
        buttonPressed = false;
        uint32_t pressDuration = millis() - buttonPressStart;
        
        if (pressDuration >= 3000) {
            if (webServerMode) {
                Serial.println("[BUTTON] กดค้าง 3 วิ - กลับสู่โหมดดักจับ!");
                stopWebServer();
            } else {
                Serial.println("[BUTTON] กดค้าง 3 วิ - เปิด Web File Manager!");
                startWebServer();
            }
        } else {
            Serial.printf("[BUTTON] กดสั้น %lu ms - ต้องกดค้าง 3 วิ\n", pressDuration);
        }
    } else if (currentButtonState && buttonPressed) {
        // ปุ่มกำลังถูกกดค้าง - กระพิบ LED เพื่อแสดงสถานะ
        uint32_t pressDuration = millis() - buttonPressStart;
        
        if (pressDuration >= 1000 && pressDuration < 3000) {
            static uint32_t lastBlink = 0;
            if (millis() - lastBlink >= 500) {
                lastBlink = millis();
                blinkLED(100);
            }
        }
    }
}

// ==================== OPTIMIZATION FUNCTIONS ====================
void optimizeMemory() {
    // ล้าง WiFi scan cache
    WiFi.scanDelete();
    
    // Force garbage collection
    if (ESP.getFreeHeap() < 15000) {
        Serial.println("[OPTIMIZE] Low memory - cleaning up...");
        
        // ปิดไฟล์ชั่วคราวเพื่อ flush buffer
        if (fileOpen && pcapFile) {
            pcapFile.flush();
        }
        
        delay(100);
    }
}