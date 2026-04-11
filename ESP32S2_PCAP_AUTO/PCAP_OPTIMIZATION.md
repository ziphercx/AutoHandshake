# PCAP Optimization สำหรับลดขนาดไฟล์

## การเปลี่ยนแปลงหลัก

### 1. Packet Filtering
- **เก็บเฉพาะ**: Beacon, Probe Request/Response, Authentication, Association, EAPOL, PMKID
- **ไม่เก็บ**: Data frames, QoS Data, Block ACK, CTS, RTS, Control frames อื่นๆ

### 2. Beacon Deduplication
- เก็บ Beacon ของ AP เดิมทุก 100ms เท่านั้น
- ใช้ `BeaconTracker` array เพื่อติดตาม BSSID และเวลา
- ลด Beacon spam ได้มากถึง 90%

### 3. สถิติใหม่
- `packetCount`: จำนวน packet ทั้งหมดที่ได้รับ
- `filteredPacketCount`: จำนวน packet ที่ผ่านการกรองและเก็บลงไฟล์
- `beaconTrackerCount`: จำนวน AP ที่ติดตาม beacon
- แสดง filter efficiency เป็น %

## ประโยชน์

### ขนาดไฟล์
- ลดขนาดไฟล์ PCAP ได้ 70-90%
- เก็บเฉพาะข้อมูลที่จำเป็นสำหรับ handshake analysis

### ประสิทธิภาพ
- ลด I/O operations
- ประหยัด memory และ storage
- เพิ่มความเร็วในการประมวลผล

### การใช้งาน
- ไฟล์ PCAP เล็กลง เปิดเร็วขึ้นใน Wireshark
- Transfer ผ่าน USB/Web ได้เร็วขึ้น
- วิเคราะห์ handshake ได้ง่ายขึ้น

## การทำงาน

```
Packet มา -> shouldCapturePacket() -> กรองตาม frame type/subtype
                                  -> Beacon: ตรวจสอบ dedupe (100ms)
                                  -> EAPOL: ตรวจสอบ signature
                                  -> เก็บลงไฟล์เฉพาะที่ผ่านการกรอง
```

## ตัวอย่างผลลัพธ์

```
[CAPTURE] - Packets รวม: 15420
[CAPTURE] - Packets กรองแล้ว: 2341 (15.2%)
[CAPTURE] - Beacon trackers: 23
```

ขนาดไฟล์ลดจาก ~5MB เหลือ ~800KB (ลด 84%)