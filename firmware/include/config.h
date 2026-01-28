#ifndef MARAUDER_CONFIG_H
#define MARAUDER_CONFIG_H

// System Configuration
#define DEVICE_NAME "ESP32-S3 Marauder"
#define FIRMWARE_VERSION "0.1.0"

// Display Configuration
#define TFT_WIDTH 240
#define TFT_HEIGHT 320
#define TFT_MOSI 11
#define TFT_MISO 13
#define TFT_SCLK 12
#define TFT_CS 10
#define TFT_DC 8
#define TFT_RST 9

// Touch Configuration
#define TOUCH_CS 14
#define TOUCH_IRQ 15

// NFC/RFID Configuration
#define NFC_SDA 21
#define NFC_SCL 22
#define NFC_IRQ 23
#define NFC_RESET 18

// System Settings
#define MAX_SCAN_RESULTS 50
#define SCAN_TIMEOUT 30000
#define UI_UPDATE_INTERVAL 100

// WiFi Settings
#define MAX_SSID_LENGTH 32
#define MAX_PASSWORD_LENGTH 64

// Debug Settings
#define DEBUG_SERIAL true
#define DEBUG_LEVEL 3

#endif