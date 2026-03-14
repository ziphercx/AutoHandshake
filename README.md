# 🔐 ESP32 WiFi Handshake Capture Tool

เครื่องมือดักจับ WiFi Handshake อัตโนมัติ พร้อม Web File Manager และ USB Drive

---

## 📋 สารบัญ
- [คืออะไร?](#คืออะไร)
- [ฟีเจอร์](#ฟีเจอร์)
- [บอร์ดที่รองรับ](#บอร์ดที่รองรับ)
- [LED Indicator](#led-indicator)
- [การติดตั้ง](#การติดตั้ง)
- [การใช้งาน](#การใช้งาน)
- [การแก้ปัญหา](#การแก้ปัญหา)

---

## คืออะไร?

เครื่องมือนี้ใช้ ESP32 ในการดักจับ **WPA/WPA2 Handshake** จาก WiFi โดยอัตโนมัติ เก็บเป็นไฟล์ .pcap ที่สามารถนำไปใช้กับ Wireshark หรือ hashcat ได้

### การทำงาน (แบบง่าย)
1. **สแกนหา WiFi** ทั้งหมดในบริเวณ (รวม Hidden SSID)
2. **ส่ง Deauth** เพื่อบังคับให้อุปกรณ์ตัดการเชื่อมต่อ
3. **ดักจับ Handshake** ตอนที่อุปกรณ์เชื่อมต่อใหม่
4. **บันทึกเป็นไฟล์** .pcap ใน SPIFFS
5. **วนซ้ำ** ไปเรื่อยๆ อัตโนมัติ

---

## ฟีเจอร์

### 🎯 ฟีเจอร์หลัก
- ✅ ดักจับ WPA/WPA2 Handshake อัตโนมัติ
- ✅ สแกน AP ทั้งหมดแบบ Deep Scan (800ms/ช่อง = ~9 วินาที)
- ✅ รองรับ Hidden SSID
- ✅ ส่ง Deauth packets อัตโนมัติ
- ✅ Hop เฉพาะช่องที่มี AP (ไม่เสียเวลา hop ช่องว่าง)
- ✅ เก็บไฟล์ .pcap ใน SPIFFS (รองรับ Wireshark/hashcat)
- ✅ LED indicator แสดงสถานะ Handshake
- ✅ Memory optimization อัตโนมัติ

### 🌐 Web File Manager
- ✅ Web interface แบบ Dark Terminal Theme
- ✅ Captive Portal (เปิดเบราว์เซอร์อะไรก็ได้)
- ✅ ดาวน์โหลด/ดู/ลบไฟล์ผ่านเว็บ
- ✅ แสดงสถานะ SPIFFS

### 💾 USB Mass Storage (เฉพาะบอร์ดที่รองรับ)
- ✅ คอมเห็น ESP32 เป็น USB Drive
- ✅ Copy ไฟล์ได้เหมือน Flash Drive ธรรมดา
- ✅ ไม่ต้องใช้เว็บก็ได้

### ⚡ การทำงานที่ปรับปรุงแล้ว
- **Deauth Phase**: 2 วินาที (ส่ง deauth รัวๆ ต่อเนื่อง)
- **Capture Phase**: 5 วินาที (รอฟัง handshake)
- **Smart Channel Hop**: Hop เฉพาะช่องที่มี AP
- **Auto Rescan**: สแกน AP ใหม่หลังครบ 1 รอบ

---

## บอร์ดที่รองรับ

| บอร์ด | WiFi Capture | Web Manager | USB Drive | แนะนำ |
|-------|:------------:|:-----------:|:---------:|:-----:|
| **ESP32-S2** | ✅ | ✅ | ✅ | ⭐⭐⭐ แนะนำมาก |
| **ESP32-S3** | ✅ | ✅ | ✅ | ⭐⭐⭐ แนะนำมาก |
| **ESP32-C3** | ✅ | ✅ | ✅ | ⭐⭐ รองรับ |
| **ESP32** (ปกติ) | ✅ | ✅ | ❌ | ⭐ จำกัด |

### คำอธิบาย
- **ESP32-S2/S3**: รองรับครบทุกฟีเจอร์ รวม USB Drive (แนะนำที่สุด)
- **ESP32-C3**: รองรับครบ แต่ RAM น้อยกว่า
- **ESP32 ปกติ**: ไม่มี USB Native → ไม่รองรับ USB Drive (ใช้ Web เท่านั้น)

---

## LED Indicator

LED ที่ขา **IO17** จะแสดงสถานะการดักจับ Handshake

### 💡 สัญญาณ LED

| สัญญาณ | ความหมาย |
|--------|----------|
| 🟢 กระพิบสั้น 100ms | ได้ **M1, M2, หรือ M3** (Handshake Message 1-3) |
| 🟢 ติดยาว 500ms | ได้ **M4** (Handshake Message 4 - ข้อความสุดท้าย) |
| 🟢 กระพิบ 3 ครั้ง | ✅ **Handshake สมบูรณ์!** (ได้ครบ M1-M4) |
| 🟢 กระพิบ 5 ครั้ง | เข้าสู่ **Web Mode** |
| 🟢 กระพิบ 3 ครั้ง | ออกจาก Web Mode กลับสู่ **Capture Mode** |
| 🔴 กระพิบเร็ว 10 ครั้ง | ❌ **Error** (SPIFFS ไม่สามารถเริ่มต้นได้) |

### การต่อ LED (ถ้าต้องการ)
```
LED ขายาว (+) → ต่อ IO17
LED ขาสั้น (-) → ต่อ Resistor 220Ω → ต่อ GND
```

**หมายเหตุ**: LED เป็น optional ถ้าไม่ต่อก็ใช้งานได้ปกติ (ดูสถานะผ่าน Serial Monitor แทน)

---

## การติดตั้ง

### 1️⃣ ติดตั้ง Arduino IDE

1. ดาวน์โหลด [Arduino IDE 2.0+](https://www.arduino.cc/en/software)
2. เปิด Arduino IDE
3. ไปที่ **File → Preferences**
4. ใน **Additional Board Manager URLs** ใส่:
   ```
   https://raw.githubusercontent.com/espressif/arduino-esp32/gh-pages/package_esp32_index.json
   ```
5. ไปที่ **Tools → Board → Boards Manager**
6. ค้นหา **"esp32"** และติดตั้ง **"esp32 by Espressif Systems"** (v2.0.0 ขึ้นไป)

---

### 2️⃣ ตั้งค่า Board

เลือกตามบอร์ดที่คุณมี:

#### 🔷 ESP32-S2 (แนะนำ)
```
Tools → Board: "ESP32S2 Dev Module"
Tools → USB CDC On Boot: "Enabled"
Tools → USB Firmware MSC On Boot: "Enabled"  ⚠️ สำคัญมาก!
Tools → Upload Mode: "Internal USB"
Tools → Partition Scheme: "Default 4MB with spiffs (1.2MB APP/1.5MB SPIFFS)"
```

#### 🔷 ESP32-S3 (แนะนำ)
```
Tools → Board: "ESP32S3 Dev Module"
Tools → USB CDC On Boot: "Enabled"
Tools → USB Firmware MSC On Boot: "Enabled"  ⚠️ สำคัญมาก!
Tools → Upload Mode: "UART0 / Hardware CDC"
Tools → Partition Scheme: "Default 4MB with spiffs"
```

#### 🔷 ESP32-C3
```
Tools → Board: "ESP32C3 Dev Module"
Tools → USB CDC On Boot: "Enabled"
Tools → USB Firmware MSC On Boot: "Enabled"  ⚠️ สำคัญมาก!
Tools → Partition Scheme: "Default 4MB with spiffs"
```

#### 🔷 ESP32 ปกติ (ไม่มี USB Drive)
```
Tools → Board: "ESP32 Dev Module"
Tools → Partition Scheme: "Default 4MB with spiffs"
หมายเหตุ: ไม่มี USB MSC option (ปกติ)
```

---

### 3️⃣ Upload โปรแกรม

1. เปิดไฟล์ `ESP32S2_PCAP_AUTO.ino`
2. เลือก **Port** ที่ถูกต้อง (Tools → Port)
3. กด **Upload** (ปุ่มลูกศรขวา)
4. รอจนขึ้น **"Done uploading"**

---

## การใช้งาน

### 🎯 โหมดดักจับ (Capture Mode) - โหมดปกติ

เมื่อเปิดเครื่อง ESP32 จะเริ่มดักจับอัตโนมัติทันที:

1. **สแกน AP** ทั้งหมด (~9 วินาที)
2. **เริ่มดักจับ** ในช่องแรกที่มี AP
3. **ส่ง Deauth** 2 วินาที (LED กระพิบถ้าได้ M1-M3)
4. **รอฟัง Handshake** 5 วินาที (LED ติดยาว 500ms ถ้าได้ M4)
5. **Hop ไปช่องถัดไป** (เฉพาะช่องที่มี AP)
6. **วนซ้ำ** จนครบทุกช่อง แล้วสแกนใหม่

#### ดูสถานะผ่าน Serial Monitor
```
[SCAN] พบ 15 AP
[SCAN] Active Channels: 1 6 11
[HANDSHAKE] M1 #1: MyWiFi | AA:BB:CC:DD:EE:FF | CH6
[HANDSHAKE] M2 #1: MyWiFi | AA:BB:CC:DD:EE:FF | CH6
[HANDSHAKE] M3 #1: MyWiFi | AA:BB:CC:DD:EE:FF | CH6
[HANDSHAKE] M4 #1: MyWiFi | AA:BB:CC:DD:EE:FF | CH6
========================================
[SUCCESS] ✓ HANDSHAKE สมบูรณ์! #1 (รวม 1 ตัว)
[SUCCESS] SSID: MyWiFi
[SUCCESS] BSSID: AA:BB:CC:DD:EE:FF
[SUCCESS] Channel: 6
[SUCCESS] ไฟล์: /.auto_12345.pcap
========================================
```

---

### 🌐 โหมด File Manager (Web + USB)

#### เปิด File Manager
1. **กดปุ่ม IO0 ค้าง 3 วินาที** (ปุ่ม Boot บนบอร์ด)
2. LED จะกระพิบ 5 ครั้ง → เข้าสู่ Web Mode
3. Serial Monitor จะแสดง:
   ```
   [WEB] AP เริ่มแล้ว: ZipherPcap
   [WEB] Password: zipher123
   [WEB] IP: 192.168.4.1
   [WEB] USB Drive เริ่มแล้ว!
   ```

#### เข้าถึงไฟล์ผ่าน Web
1. เชื่อมต่อ WiFi:
   - **SSID**: `ZipherPcap`
   - **Password**: `zipher123`
2. เปิดเบราว์เซอร์ไปที่: **http://192.168.4.1**
3. จะเห็น Web Interface แบบ Terminal Theme
4. สามารถ:
   - 📥 **Download** ไฟล์ .pcap
   - 👁️ **View** ข้อมูลไฟล์
   - 🗑️ **Delete** ไฟล์ที่ไม่ต้องการ

#### เข้าถึงไฟล์ผ่าน USB Drive (ESP32-S2/S3/C3 เท่านั้น)
1. เสียบสาย USB เข้าคอมพิวเตอร์
2. คอมจะเห็น ESP32 เป็น **USB Drive** ชื่อ "ESP32-S2"
3. เปิด Drive → เห็นไฟล์ .pcap ทั้งหมด
4. Copy ไฟล์ออกมาได้เลย (เหมือน Flash Drive)

#### ปิด File Manager (กลับสู่ Capture Mode)
1. **กดปุ่ม IO0 ค้าง 3 วินาที** อีกครั้ง
2. LED จะกระพิบ 3 ครั้ง → กลับสู่ Capture Mode
3. เริ่มดักจับใหม่อัตโนมัติ

---

### 📁 รูปแบบไฟล์

- **ชื่อไฟล์**: `/.auto_<timestamp>.pcap`
  - ตัวอย่าง: `/.auto_12345678.pcap`
- **ไฟล์ซ้ำ**: ถ้าชื่อซ้ำจะเพิ่ม (2), (3), etc.
  - ตัวอย่าง: `/.auto_12345678(2).pcap`
- **รองรับ**: Wireshark, hashcat, tcpdump

---

### 🔓 การใช้งานกับ Hashcat

#### 1. แปลงไฟล์ .pcap เป็น .hc22000
```bash
hcxpcapngtool -o hash.hc22000 capture.pcap
```

#### 2. Crack ด้วย Hashcat
```bash
# ใช้ wordlist
hashcat -m 22000 hash.hc22000 wordlist.txt

# ใช้ mask attack (8 ตัวเลข)
hashcat -m 22000 hash.hc22000 -a 3 ?d?d?d?d?d?d?d?d

# ใช้ combinator attack
hashcat -m 22000 hash.hc22000 -a 1 wordlist1.txt wordlist2.txt
```

---

## การแก้ปัญหา

### ❌ ปัญหาที่พบบ่อย

#### 1. **SPIFFS ไม่สามารถเริ่มต้นได้**
```
[ERROR] ไม่สามารถเริ่มต้น SPIFFS ได้!
```
**วิธีแก้**:
- โปรแกรมจะ **format SPIFFS อัตโนมัติ** และลองใหม่
- ถ้ายังไม่ได้ → ตรวจสอบ **Partition Scheme**:
  - ต้องเลือก **"Default 4MB with spiffs"**
  - ถ้าเลือก "No OTA" หรือ "Minimal SPIFFS" จะมีพื้นที่น้อยเกินไป

#### 2. **USB Drive ไม่ทำงาน**
```
[WEB] USB Drive: Not supported
```
**วิธีแก้**:
- ตรวจสอบว่าเปิด **"USB Firmware MSC On Boot: Enabled"** แล้ว
- ตรวจสอบว่าบอร์ดรองรับ USB MSC (S2/S3/C3 เท่านั้น)
- ESP32 ปกติไม่รองรับ USB MSC (ใช้ Web เท่านั้น)
- ลองเปลี่ยนสาย USB (บางสายเป็น charging only)

#### 3. **ไม่พบ AP เลย**
```
[SCAN] ไม่พบ AP
```
**วิธีแก้**:
- ตรวจสอบ antenna (ถ้ามี external antenna)
- ย้ายไปใกล้ WiFi Router มากขึ้น
- ตรวจสอบว่า WiFi เปิดอยู่

#### 4. **Memory หมด**
```
[DEAUTH] Low memory - stopping early
```
**วิธีแก้**:
- ลดค่า `MAX_APS` ใน `config.h` (จาก 50 → 30)
- ลดค่า `MAX_HANDSHAKES` ใน `config.h` (จาก 20 → 10)
- ลบไฟล์เก่าใน SPIFFS ผ่าน Web Interface

#### 5. **Web ไม่เปิด**
**วิธีแก้**:
- ตรวจสอบว่าเชื่อมต่อ WiFi "ZipherPcap" แล้ว
- ลองเปิด http://192.168.4.1 ใหม่
- ลองปิด Mobile Data (ถ้าใช้มือถือ)
- ลองเปิดเบราว์เซอร์ใหม่ (Captive Portal จะเปิดอัตโนมัติ)

#### 6. **ไม่ได้ Handshake เลย**
**สาเหตุที่เป็นไปได้**:
- ไม่มีอุปกรณ์เชื่อมต่อกับ WiFi นั้น
- WiFi ใช้ WPA3 (ไม่รองรับ - รองรับแค่ WPA/WPA2)
- ระยะห่างไกลเกินไป
- Deauth ไม่ส่งถึง (บาง Router มี protection)

**วิธีแก้**:
- รอนานขึ้น (บางครั้งต้องรอหลายรอบ)
- ลองใช้ WiFi ของตัวเอง (ทดสอบก่อน)
- ตรวจสอบ Serial Monitor ว่าเห็น M1-M4 หรือไม่

---

### 🔍 การ Debug

#### เปิด Serial Monitor
1. **Tools → Serial Monitor**
2. ตั้ง Baud Rate: **115200**
3. ดูข้อความที่แสดง

#### ข้อความสำคัญ
- `[SCAN]` - การสแกน AP
- `[HANDSHAKE]` - ได้ Handshake Message
- `[SUCCESS]` - ได้ Handshake สมบูรณ์
- `[ERROR]` - เกิด Error
- `[STATS]` - สถิติการทำงาน (ทุก 5 วินาที)

#### ตัวอย่าง Stats
```
[STATS] CH6 | Phase:CAPTURE | Cycle:1 | HS:1/1 | PKT:1234 | DEAUTH:56 | Heap:45678
```
- **CH6**: ช่องปัจจุบัน
- **Phase**: DEAUTH หรือ CAPTURE
- **Cycle**: รอบที่
- **HS:1/1**: Handshake สมบูรณ์ 1 จาก 1
- **PKT**: จำนวน packets ที่ดักจับ
- **DEAUTH**: จำนวน deauth ที่ส่ง
- **Heap**: RAM ว่าง (ถ้าต่ำกว่า 15000 จะทำความสะอาดอัตโนมัติ)

---

## ⚠️ ข้อควรระวัง

### กฎหมาย
- ⚠️ **ใช้เฉพาะกับ WiFi ที่คุณเป็นเจ้าของหรือได้รับอนุญาต**
- ⚠️ **ห้ามใช้เพื่อการผิดกฎหมาย**
- ⚠️ **เครื่องมือนี้สำหรับการศึกษาและ Penetration Testing เท่านั้น**

### ความปลอดภัย
- ใช้ความรับผิดชอบของตนเอง
- ผู้พัฒนาไม่รับผิดชอบต่อการใช้งานที่ผิดกฎหมาย

---

## 📚 เอกสารเพิ่มเติม

- [USB MSC Setup Guide](USB_MSC_GUIDE.md) - คู่มือตั้งค่า USB Mass Storage
- [Example PCAP](Example/) - ตัวอย่างไฟล์ PCAP

---

## 📝 License

MIT License - ใช้งานได้อย่างอิสระ แต่ใช้ความรับผิดชอบของตนเอง

---

## 🙏 Credits

Developed for educational and security research purposes.

**Version**: 2.0 (Modular + Optimized)  
**Last Updated**: 2024
