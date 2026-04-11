#include "web_interface.h"
#include "globals.h"
#include "pcap_manager.h"
#include "usb_manager.h"
#include <WiFi.h>
#include <SPIFFS.h>

// Forward declarations
void blinkLED(int duration);
void stopCapture();
void initWiFi();
void deepScanAllAPs();
void startCapture();

WebServer server(80);
DNSServer dnsServer;

// ==================== WEB HANDLERS ====================
// URL encode helper function
String urlEncode(const String& str) {
    String encoded = "";
    char c;
    for (size_t i = 0; i < str.length(); i++) {
        c = str.charAt(i);
        if (c == ' ') {
            encoded += "%20";
        } else if (c == '/') {
            encoded += "%2F";
        } else if (c == '.') {
            encoded += c;
        } else if (isalnum(c) || c == '-' || c == '_' || c == '~') {
            encoded += c;
        } else {
            encoded += '%';
            char hex[3];
            sprintf(hex, "%02X", c);
            encoded += hex;
        }
    }
    return encoded;
}

void handleRoot() {
    String html = R"(
<!DOCTYPE html>
<html>
<head>
    <meta charset='UTF-8'>
    <title>ZipherPcap Terminal</title>
    <meta name='viewport' content='width=device-width, initial-scale=1'>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Courier New', monospace; 
            background: #0a1f0a; 
            color: #00ff41;
            padding: 20px;
            line-height: 1.6;
        }
        .terminal { 
            max-width: 900px; 
            margin: 0 auto; 
            background: #0d2b0d; 
            border: 2px solid #00ff41;
            border-radius: 8px;
            box-shadow: 0 0 30px rgba(0, 255, 65, 0.5);
        }
        .terminal-header {
            background: #051805;
            padding: 10px 20px;
            border-bottom: 1px solid #00ff41;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .terminal-dot { 
            width: 12px; 
            height: 12px; 
            border-radius: 50%; 
            display: inline-block;
        }
        .dot-red { background: #ff5f56; }
        .dot-yellow { background: #ffbd2e; }
        .dot-green { background: #27c93f; }
        .terminal-title {
            margin-left: 10px;
            color: #00ff41;
            font-weight: bold;
        }
        .terminal-body { padding: 20px; }
        h1 { 
            color: #00ff41; 
            text-align: center; 
            margin-bottom: 20px;
            text-shadow: 0 0 15px rgba(0, 255, 65, 0.8);
            font-size: 24px;
        }
        .prompt { color: #00cc33; }
        .stats { 
            background: #051805; 
            padding: 15px; 
            border: 1px solid #00ff41;
            border-radius: 5px; 
            margin: 20px 0;
            font-size: 14px;
        }
        .stats-line { margin: 5px 0; }
        .label { color: #66ff66; }
        .value { color: #ffff00; }
        .success { color: #00ff41; }
        .warning { color: #ffaa00; }
        .file-list { margin: 20px 0; }
        .file-header {
            color: #66ff66;
            font-size: 16px;
            margin-bottom: 10px;
            border-bottom: 1px dashed #00ff41;
            padding-bottom: 5px;
        }
        .file-item { 
            display: flex; 
            justify-content: space-between; 
            align-items: center;
            padding: 12px; 
            margin: 8px 0; 
            background: #051805;
            border-left: 3px solid #00ff41;
            border-radius: 3px;
            transition: all 0.3s;
        }
        .file-item:hover {
            background: #0a2b0a;
            border-left-color: #66ff66;
            transform: translateX(5px);
            box-shadow: 0 0 10px rgba(0, 255, 65, 0.3);
        }
        .file-name { 
            color: #00ff41; 
            font-weight: bold;
            font-size: 14px;
        }
        .file-size { 
            color: #66ff66; 
            font-size: 12px;
            margin-top: 3px;
        }
        .btn { 
            padding: 6px 12px; 
            margin: 0 3px; 
            border: 1px solid;
            border-radius: 3px; 
            cursor: pointer; 
            text-decoration: none; 
            display: inline-block;
            font-family: 'Courier New', monospace;
            font-size: 12px;
            transition: all 0.3s;
        }
        .btn-download { 
            background: #051805; 
            color: #00ff41; 
            border-color: #00ff41;
        }
        .btn-download:hover { 
            background: #00ff41; 
            color: #051805;
            box-shadow: 0 0 10px rgba(0, 255, 65, 0.5);
        }
        .btn-delete { 
            background: #051805; 
            color: #ff5f56; 
            border-color: #ff5f56;
        }
        .btn-delete:hover { 
            background: #ff5f56; 
            color: #051805;
        }
        .btn-view { 
            background: #051805; 
            color: #66ff66; 
            border-color: #66ff66;
        }
        .btn-view:hover { 
            background: #66ff66; 
            color: #051805;
        }
        .btn-format {
            background: #051805;
            color: #ff3333;
            border: 2px solid #ff3333;
            padding: 12px 24px;
            border-radius: 5px;
            font-size: 14px;
            font-weight: bold;
            margin: 10px 5px;
        }
        .btn-format:hover {
            background: #ff3333;
            color: #051805;
            box-shadow: 0 0 15px rgba(255, 51, 51, 0.5);
        }
        .back-btn { 
            background: #051805; 
            color: #00ff41; 
            border: 2px solid #00ff41;
            padding: 12px 24px; 
            border-radius: 5px;
            font-size: 14px;
            font-weight: bold;
            margin: 10px 5px;
        }
        .back-btn:hover {
            background: #00ff41;
            color: #051805;
            box-shadow: 0 0 15px rgba(0, 255, 65, 0.5);
        }
        .center { text-align: center; margin-top: 30px; }
        .no-files {
            text-align: center;
            color: #66ff66;
            padding: 20px;
            font-style: italic;
        }
    </style>
</head>
<body>
    <div class='terminal'>
        <div class='terminal-header'>
            <span class='terminal-dot dot-red'></span>
            <span class='terminal-dot dot-yellow'></span>
            <span class='terminal-dot dot-green'></span>
            <span class='terminal-title'>root@zipher:~#</span>
        </div>
        <div class='terminal-body'>
            <h1>🔐 ZIPHER PCAP TERMINAL</h1>
            <div class='stats'>
                <div class='stats-line'><span class='prompt'>$</span> <span class='label'>df -h /spiffs</span></div>
)";
    
    size_t totalBytes = SPIFFS.totalBytes();
    size_t usedBytes = SPIFFS.usedBytes();
    size_t freeBytes = totalBytes - usedBytes;
    
    html += "<div class='stats-line'><span class='label'>Total:</span> <span class='value'>" + String(totalBytes / 1024) + " KB</span></div>";
    html += "<div class='stats-line'><span class='label'>Used:</span> <span class='value'>" + String(usedBytes / 1024) + " KB</span></div>";
    html += "<div class='stats-line'><span class='label'>Free:</span> <span class='value'>" + String(freeBytes / 1024) + " KB</span></div>";
    
    // ป้องกัน division by zero
    int usagePercent = (totalBytes > 0) ? ((usedBytes * 100) / totalBytes) : 0;
    html += "<div class='stats-line'><span class='label'>Usage:</span> <span class='value'>" + String(usagePercent) + "%</span></div>";
#ifdef USB_MSC_ENABLED
    html += "<div class='stats-line'><span class='label'>USB Drive:</span> <span class='success'>● ACTIVE</span></div>";
#else
    html += "<div class='stats-line'><span class='label'>USB Drive:</span> <span class='warning'>○ NOT SUPPORTED</span></div>";
#endif
    
    html += R"(
            </div>
            <div class='file-list'>
                <div class='file-header'><span class='prompt'>$</span> ls -lah *.pcap</div>
)";
    
    File root = SPIFFS.open("/");
    File file = root.openNextFile();
    int fileCount = 0;
    
    while (file) {
        if (!file.isDirectory()) {
            fileCount++;
            String fileName = file.name();
            size_t fileSize = file.size();
            
            // URL encode the filename for links
            String encodedFileName = urlEncode(fileName);
            
            html += "<div class='file-item'>";
            html += "<div>";
            html += "<div class='file-name'>" + fileName + "</div>";
            html += "<div class='file-size'>" + String(fileSize) + " bytes (" + String(fileSize / 1024.0, 2) + " KB)</div>";
            html += "</div>";
            html += "<div>";
            html += "<a href='/download?file=" + encodedFileName + "' class='btn btn-download'>↓ DOWNLOAD</a>";
            html += "<a href='/view?file=" + encodedFileName + "' class='btn btn-view'>👁 VIEW</a>";
            html += "<a href='/delete?file=" + encodedFileName + "' class='btn btn-delete' onclick='return confirm(\"rm -f " + fileName + "?\")'>✕ DELETE</a>";
            html += "</div>";
            html += "</div>";
        }
        file = root.openNextFile();
    }
    
    if (fileCount == 0) {
        html += "<div class='no-files'>No files found. Start capturing to create PCAP files.</div>";
    }
    
    html += R"(
            </div>
            <div class='center'>
                <a href='/format' class='btn btn-format' onclick='return confirm("⚠️ WARNING: This will DELETE ALL FILES!\n\nAre you sure you want to format SPIFFS?")'>🗑️ FORMAT SPIFFS (DELETE ALL)</a>
                <br>
                <a href='/restart' class='btn back-btn' onclick='return confirm("Exit web mode and return to capture?")'>⟲ BACK TO CAPTURE MODE</a>
            </div>
        </div>
    </div>
</body>
</html>
)";
    
    server.send(200, "text/html", html);
}

void handleDownload() {
    if (!server.hasArg("file")) {
        server.send(400, "text/plain", "Missing file parameter");
        return;
    }
    
    String fileName = server.arg("file");
    
    // ถ้าไม่มี / ข้างหน้า ให้เพิ่มให้
    if (!fileName.startsWith("/")) {
        fileName = "/" + fileName;
    }
    
    if (!SPIFFS.exists(fileName)) {
        server.send(404, "text/plain", "File not found: " + fileName);
        return;
    }
    
    File file = SPIFFS.open(fileName, "r");
    if (!file) {
        server.send(500, "text/plain", "Cannot open file");
        return;
    }
    
    String contentType = "application/octet-stream";
    if (fileName.endsWith(".pcap")) {
        contentType = "application/vnd.tcpdump.pcap";
    }
    
    // ใช้ชื่อไฟล์โดยไม่มี / สำหรับ download
    String downloadName = fileName;
    if (downloadName.startsWith("/")) {
        downloadName = downloadName.substring(1);
    }
    
    server.sendHeader("Content-Disposition", "attachment; filename=\"" + downloadName + "\"");
    server.streamFile(file, contentType);
    file.close();
}

void handleView() {
    if (!server.hasArg("file")) {
        server.send(400, "text/plain", "Missing file parameter");
        return;
    }
    
    String fileName = server.arg("file");
    
    // ถ้าไม่มี / ข้างหน้า ให้เพิ่มให้
    if (!fileName.startsWith("/")) {
        fileName = "/" + fileName;
    }
    
    if (!SPIFFS.exists(fileName)) {
        server.send(404, "text/plain", "File not found: " + fileName);
        return;
    }
    
    File file = SPIFFS.open(fileName, "r");
    if (!file) {
        server.send(500, "text/plain", "Cannot open file");
        return;
    }
    
    String content = "File: " + fileName + "\n";
    content += "Size: " + String(file.size()) + " bytes\n\n";
    
    if (fileName.endsWith(".pcap")) {
        content += "This is a PCAP file. Use Wireshark or hashcat to analyze.\n";
        content += "For hashcat: hashcat -m 22000 " + fileName + " wordlist.txt\n";
    } else {
        // Show first 1KB for text files
        content += "Content preview (first 1KB):\n";
        content += "----------------------------------------\n";
        
        size_t bytesToRead = min((size_t)1024, file.size());
        char buffer[1025];
        size_t bytesRead = file.readBytes(buffer, bytesToRead);
        buffer[bytesRead] = '\0';
        content += String(buffer);
    }
    
    file.close();
    server.send(200, "text/plain", content);
}

void handleDelete() {
    if (!server.hasArg("file")) {
        server.send(400, "text/plain", "Missing file parameter");
        return;
    }
    
    String fileName = server.arg("file");
    
    // ถ้าไม่มี / ข้างหน้า ให้เพิ่มให้
    if (!fileName.startsWith("/")) {
        fileName = "/" + fileName;
    }
    
    if (!SPIFFS.exists(fileName)) {
        server.send(404, "text/plain", "File not found: " + fileName);
        return;
    }
    
    if (SPIFFS.remove(fileName)) {
        server.sendHeader("Location", "/");
        server.send(302, "text/plain", "File deleted");
    } else {
        server.send(500, "text/plain", "Cannot delete file");
    }
}

void handleRestart() {
    server.send(200, "text/html", 
        "<html><body><h2>Back to capture mode...</h2>"
        "<script>setTimeout(function(){window.close();}, 2000);</script></body></html>");
    delay(1000);
    
    // ปิด Web Server และกลับสู่โหมดดักจับ
    stopWebServer();
}

void handleFormat() {
    Serial.println("[WEB] ========================================");
    Serial.println("[WEB] ⚠️  FORMAT SPIFFS - DELETING ALL FILES!");
    Serial.println("[WEB] ========================================");
    
    // ลบไฟล์ทั้งหมดก่อน
    File root = SPIFFS.open("/");
    File file = root.openNextFile();
    int deletedCount = 0;
    
    while (file) {
        if (!file.isDirectory()) {
            String fileName = file.name();
            file.close();
            
            if (SPIFFS.remove(fileName)) {
                Serial.printf("[WEB] Deleted: %s\n", fileName.c_str());
                deletedCount++;
            }
        }
        file = root.openNextFile();
    }
    
    Serial.printf("[WEB] Deleted %d files\n", deletedCount);
    
    // Format SPIFFS
    Serial.println("[WEB] Formatting SPIFFS...");
    bool formatSuccess = SPIFFS.format();
    
    if (formatSuccess) {
        Serial.println("[WEB] ✓ Format สำเร็จ!");
        
        // แสดงพื้นที่ว่างหลัง format
        size_t totalBytes = SPIFFS.totalBytes();
        size_t usedBytes = SPIFFS.usedBytes();
        Serial.printf("[WEB] SPIFFS: %d KB total, %d KB used, %d KB free\n", 
                     totalBytes / 1024, usedBytes / 1024, (totalBytes - usedBytes) / 1024);
        
        server.send(200, "text/html", 
            "<html><head><meta charset='UTF-8'></head><body style='background:#0a1f0a;color:#00ff41;font-family:monospace;padding:20px;'>"
            "<h2>✓ Format สำเร็จ!</h2>"
            "<p>ลบไฟล์ทั้งหมด " + String(deletedCount) + " ไฟล์</p>"
            "<p>SPIFFS ถูก format เรียบร้อยแล้ว</p>"
            "<p>กำลังกลับหน้าหลัก...</p>"
            "<script>setTimeout(function(){window.location='/';}, 3000);</script>"
            "</body></html>");
    } else {
        Serial.println("[WEB] ✗ Format ล้มเหลว!");
        
        server.send(500, "text/html", 
            "<html><head><meta charset='UTF-8'></head><body style='background:#0a1f0a;color:#ff5f56;font-family:monospace;padding:20px;'>"
            "<h2>✗ Format ล้มเหลว!</h2>"
            "<p>ไม่สามารถ format SPIFFS ได้</p>"
            "<p><a href='/' style='color:#00ff41;'>กลับหน้าหลัก</a></p>"
            "</body></html>");
    }
    
    Serial.println("[WEB] ========================================");
}

void handleNotFound() {
    // Captive Portal - redirect all requests to root
    server.sendHeader("Location", "/");
    server.send(302, "text/plain", "");
}

// ==================== WEB SERVER FUNCTIONS ====================
void startWebServer() {
    Serial.println("[WEB] หยุดการดักจับและเริ่ม Web File Manager...");
    
    // หยุดการดักจับ
    if (isCapturing) {
        stopCapture();
    }
    
#ifdef USB_MSC_ENABLED
    // เริ่ม USB และ MSC พร้อมกัน (เฉพาะ boards ที่รองรับ)
    initUSB();
    initUSBMSC();
    usbMscMode = true;
    Serial.println("[WEB] USB MSC: Enabled");
#else
    Serial.println("[WEB] USB MSC: Not supported on this board");
#endif
    
    // เริ่ม AP mode
    WiFi.mode(WIFI_AP);
    WiFi.softAP("ZipherPcap", "zipher123");
    
    IPAddress IP = WiFi.softAPIP();
    Serial.printf("[WEB] AP เริ่มแล้ว: ZipherPcap\n");
    Serial.printf("[WEB] Password: zipher123\n");
    Serial.printf("[WEB] IP: %s\n", IP.toString().c_str());
    
    // เริ่ม DNS Server สำหรับ Captive Portal
    dnsServer.start(53, "*", IP);
    
    // ตั้งค่า Web Server routes
    server.on("/", handleRoot);
    server.on("/download", handleDownload);
    server.on("/view", handleView);
    server.on("/delete", handleDelete);
    server.on("/format", handleFormat);
    server.on("/restart", handleRestart);
    server.onNotFound(handleNotFound);
    
    server.begin();
    webServerMode = true;
    
    Serial.println("[WEB] ========================================");
    Serial.println("[WEB] 🌐 Web File Manager เริ่มแล้ว!");
#ifdef USB_MSC_ENABLED
    Serial.println("[WEB] 📱 USB Drive เริ่มแล้ว!");
#else
    Serial.println("[WEB] 📱 USB Drive: Not available (board limitation)");
#endif
    Serial.println("[WEB] ========================================");
    Serial.println("[WEB] WiFi: ZipherPcap / zipher123");
    Serial.println("[WEB] Web: http://192.168.4.1");
#ifdef USB_MSC_ENABLED
    Serial.println("[WEB] USB: คอมจะเห็น ESP32 เป็น USB Drive");
#endif
    Serial.println("[WEB] กดปุ่ม IO0 ค้าง 3 วิเพื่อกลับสู่โหมดดักจับ");
    Serial.println("[WEB] ========================================");
    
    // กระพิบ LED เพื่อแสดงว่าเข้า Web mode
    for (int i = 0; i < 5; i++) {
        blinkLED(200);
        delay(200);
    }
}

void stopWebServer() {
    Serial.println("[WEB] ========================================");
    Serial.println("[WEB] ปิด Web Server และกลับสู่โหมดดักจับ...");
    Serial.println("[WEB] ========================================");
    
#ifdef USB_MSC_ENABLED
    // ปิด USB MSC และ USB (เฉพาะ boards ที่รองรับ)
    if (usbMscMode) {
        deinitUSBMSC();
    }
    deinitUSB();
#endif
    
    webServerMode = false;
    server.stop();
    dnsServer.stop();
    WiFi.softAPdisconnect(true);
    WiFi.mode(WIFI_OFF);
    delay(500);
    
    // กระพิบ LED เพื่อแสดงว่าออกจาก Web mode
    for (int i = 0; i < 3; i++) {
        blinkLED(100);
        delay(100);
    }
    
    Serial.println("[WEB] กลับสู่โหมดดักจับ...");
    
    // เริ่มต้นระบบใหม่
    initWiFi();
    deepScanAllAPs();
    startCapture();
}