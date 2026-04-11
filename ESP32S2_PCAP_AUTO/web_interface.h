#ifndef WEB_INTERFACE_H
#define WEB_INTERFACE_H

#include <WebServer.h>
#include <DNSServer.h>

// ==================== WEB SERVER FUNCTIONS ====================
void startWebServer();
void stopWebServer();

// ==================== WEB HANDLERS ====================
void handleRoot();
void handleDownload();
void handleView();
void handleDelete();
void handleFormat();
void handleRestart();
void handleNotFound();

// ==================== EXTERNAL OBJECTS ====================
extern WebServer server;
extern DNSServer dnsServer;

#endif