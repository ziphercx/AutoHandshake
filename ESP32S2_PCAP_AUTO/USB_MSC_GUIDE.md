# คู่มือการใช้งาน USB Mass Storage (MSC)

## ภาพรวม
โปรเจคนี้รองรับ USB Mass Storage Class (MSC) ซึ่งทำให้คอมพิวเตอร์เห็น ESP32 เป็น USB Drive

## Board ที่รองรับ

### ✅ รองรับ USB MSC
- **ESP32S2** - รองรับเต็มรูปแบบ
- **ESP32S3** - รองรับเต็มรูปแบบ
- **ESP32-C3** - รองรับเต็มรูปแบบ

### ❌ ไม่รองรับ USB MSC
- **ESP32** (ปกติ) - ใช้ Web File Manager เท่านั้น

## การตั้งค่า Arduino IDE

### สำคัญมาก! ⚠️
**ต้องเปิด "USB Firmware MSC On Boot" ใน Arduino IDE**

### ESP32S2 Settings:
```
Tools > Board > ESP32S2 Dev Module
Tools > USB CDC On Boot > Enabled
Tools > USB Firmware MSC On Boot > Enabled  ⚠️ ต้องเปิด!
Tools > USB DFU On Boot > Disabled
Tools > Upload Mode > Internal USB
Tools > Partition Scheme > Default 4MB with spiffs
```

### ESP32S3 Settings:
```
Tools > Board > ESP32S3 Dev Module
Tools > USB CDC On Boot > Enabled
Tools > USB Firmware MSC On Boot > Enabled  ⚠️ ต้องเปิด!
Tools > USB DFU On Boot > Disabled
Tools > Upload Mode > UART0 / Hardware CDC
Tools > Partition Scheme > Default 4MB with spiffs
```

### ESP32-C3 Settings:
```
Tools > Board > ESP32C3 Dev Module
Tools > USB CDC On Boot > Enabled
Tools > USB Firmware MSC On Boot > Enabled  ⚠️ ต้องเปิด!
Tools > Partition Scheme > Default 4MB with spiffs
```

## การทำงานของ USB MSC

### Automatic Detection
โค้ดจะตรวจสอบอัตโนมัติว่า board รองรับ USB MSC หรือไม่:

```cpp
#if defined(ARDUINO_USB_MODE) && defined(ARDUINO_USB_MSC_ON_BOOT)
    #define USB_MSC_ENABLED
    // USB MSC code here
#endif
```

### การเปิดใช้งาน
1. กดปุ่ม IO0 ค้าง 3 วินาที
2. ระบบจะเปิด Web File Manager
3. **ถ้า board รองรับ**: USB MSC จะเปิดอัตโนมัติ
4. **ถ้า board ไม่รองรับ**: จะแสดงข้อความ "Not supported"

### Serial Monitor Output

#### Board รองรับ USB MSC:
```
[WEB] USB MSC: Enabled
[USB] เริ่มต้น USB...
[USB] เริ่มต้น USB MSC...
[USB] MSC เริ่มแล้ว - 2816 sectors (1408 KB)
[WEB] 📱 USB Drive เริ่มแล้ว!
[WEB] USB: คอมจะเห็น ESP32 เป็น USB Drive
```

#### Board ไม่รองรับ USB MSC:
```
[WEB] USB MSC: Not supported on this board
[WEB] 📱 USB Drive: Not available (board limitation)
```

## การใช้งาน USB Drive

### Windows:
1. เปิด File Explorer
2. จะเห็น "ZipherTech PcapCapture" ใน Devices
3. เปิดดูไฟล์ .pcap ได้เลย
4. ลาก-วางไฟล์ออกมาได้

### macOS:
1. เปิด Finder
2. จะเห็น "ZipherTech PcapCapture" ใน Devices
3. เข้าถึงไฟล์ได้ปกติ

### Linux:
1. USB Drive จะ mount อัตโนมัติ
2. หรือใช้คำสั่ง: `lsblk` เพื่อดู device
3. Mount manual: `sudo mount /dev/sdX /mnt/pcap`

## ข้อจำกัด

### Read-Only Mode
USB MSC ถูกตั้งค่าเป็น **Read-Only** เพื่อป้องกัน:
- การลบไฟล์โดยไม่ตั้งใจ
- การเขียนทับไฟล์
- File system corruption

### การลบไฟล์
ใช้ Web Interface แทน:
- เปิด http://192.168.4.1
- กดปุ่ม Delete ที่ไฟล์ที่ต้องการ

## Troubleshooting

### USB Drive ไม่ปรากฏ

#### 1. ตรวจสอบ Board Settings
```
Arduino IDE > Tools > USB Firmware MSC On Boot > Enabled
```

#### 2. ตรวจสอบ Serial Monitor
ดูว่ามีข้อความ:
```
[USB] MSC เริ่มแล้ว
```

#### 3. ตรวจสอบ USB Cable
- ใช้ cable ที่รองรับ data (ไม่ใช่ charging only)
- ลองเปลี่ยน USB port

#### 4. ตรวจสอบ Driver (Windows)
- Device Manager > Ports
- ควรเห็น "USB Serial Device"

### USB Drive แสดง Error

#### Windows: "Please insert a disk"
- Reboot ESP32
- ตรวจสอบ SPIFFS ว่า format ถูกต้อง

#### macOS: "The disk you inserted was not readable"
- ปกติ - SPIFFS ไม่ใช่ FAT32
- ใช้ Web Interface แทน

#### Linux: "Unknown filesystem"
- ปกติ - SPIFFS เป็น proprietary format
- ใช้ Web Interface แทน

## การ Compile สำหรับ Board ต่างๆ

### Compile สำหรับ ESP32S2 (มี USB MSC):
```bash
# USB_MSC_ENABLED จะถูก defined อัตโนมัติ
# Code จะ compile พร้อม USB MSC support
```

### Compile สำหรับ ESP32 (ไม่มี USB MSC):
```bash
# USB_MSC_ENABLED จะไม่ถูก defined
# Code จะ compile โดยไม่มี USB MSC
# ใช้ Web File Manager เท่านั้น
```

## Code Structure

### usb_manager.h
```cpp
#ifdef USB_MSC_ENABLED
    // Real USB functions
    void initUSB();
    void initUSBMSC();
#else
    // Dummy inline functions
    inline void initUSB() {}
    inline void initUSBMSC() {}
#endif
```

### usb_manager.cpp
```cpp
#ifdef USB_MSC_ENABLED
    // Full USB MSC implementation
    USBMSC msc;
    // ... callbacks and functions
#else
    // Empty file - dummy functions in header
#endif
```

### web_interface.cpp
```cpp
#ifdef USB_MSC_ENABLED
    initUSB();
    initUSBMSC();
    Serial.println("USB Drive: Active");
#else
    Serial.println("USB Drive: Not supported");
#endif
```

## Performance

### USB 2.0 Full Speed
- Speed: 12 Mbps
- Transfer rate: ~1 MB/s
- Latency: Low

### SPIFFS Access
- Read: Fast (direct access)
- Write: Disabled (read-only)
- File list: Instant

## Security

### Read-Only Protection
```cpp
int32_t onWrite(...) {
    // ป้องกันการเขียน - return success แต่ไม่ทำอะไร
    return bufsize;
}
```

### Benefits:
- ป้องกันการลบไฟล์
- ป้องกัน malware
- ป้องกัน file corruption

## Best Practices

### 1. ใช้ Web Interface สำหรับการจัดการ
- Download: ใช้ USB หรือ Web
- Delete: ใช้ Web เท่านั้น
- View: ใช้ Web

### 2. Safely Remove
- Windows: "Safely Remove Hardware"
- macOS: Eject ก่อน unplug
- Linux: `umount` ก่อน unplug

### 3. Monitor Serial Output
- ดู USB status
- ตรวจสอบ errors
- Debug problems

## Summary

| Feature | ESP32S2/S3/C3 | ESP32 |
|---------|---------------|-------|
| WiFi Capture | ✅ | ✅ |
| Web File Manager | ✅ | ✅ |
| USB Mass Storage | ✅ | ❌ |
| File Download | USB + Web | Web only |
| File Delete | Web | Web |
| Auto Detection | ✅ | ✅ |

**สรุป**: ESP32S2/S3/C3 ได้ทุกฟีเจอร์, ESP32 ปกติใช้ Web เท่านั้น