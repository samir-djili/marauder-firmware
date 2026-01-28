#ifndef WIFI_PERSISTENCE_H
#define WIFI_PERSISTENCE_H

#include <Arduino.h>
#include <FS.h>
#include <SPIFFS.h>
#include <SD.h>
#include <WiFi.h>
#include <vector>
#include <map>

// Forward declarations
struct AccessPoint;
struct Station;
struct DetectedThreat;

enum StorageLocation {
    STORAGE_SPIFFS,
    STORAGE_SD,
    STORAGE_AUTO
};

enum CaptureFormat {
    CAPTURE_PCAP,
    CAPTURE_PCAPNG,
    CAPTURE_JSON,
    CAPTURE_CSV
};

enum ExportFormat {
    EXPORT_PCAP,
    EXPORT_JSON,
    EXPORT_CSV,
    EXPORT_TXT
};

struct CaptureSession {
    uint32_t id;
    String filename;
    CaptureFormat format;
    StorageLocation storageLocation;
    uint32_t startTime;
    uint32_t endTime;
    uint32_t packetCount;
    uint32_t totalBytes;
    bool isActive;
    bool isPaused;
    String description;
};

struct CaptureStats {
    uint32_t totalCapturedPackets;
    uint32_t totalCaptureBytes;
    uint32_t totalCaptureFiles;
    uint32_t captureUptime;
    bool isCapturing;
    uint32_t currentCaptureSize;
    String currentFilename;
};

class WiFiPersistence {
public:
    WiFiPersistence();
    ~WiFiPersistence();
    
    // Core functionality
    bool begin();
    void update();
    void stop();
    
    // Capture management
    bool startCapture(const String& filename = "", CaptureFormat format = CAPTURE_PCAP);
    bool stopCapture();
    bool pauseCapture();
    bool resumeCapture();
    bool capturePacket(const uint8_t* packet, uint16_t length, int32_t rssi, 
                      uint32_t timestamp, uint32_t channel);
    
    // Export functionality
    bool exportCapture(const String& sourceFile, const String& targetFile, ExportFormat format);
    std::vector<String> listCaptureFiles();
    bool deleteCapture(const String& filename);
    
    // Status and information
    CaptureStats getCaptureStats();
    String getCaptureInfo();
    String getStatusString();
    
    // Configuration
    void setStorageLocation(StorageLocation location);
    StorageLocation getStorageLocation();
    void setMaxCaptureSize(uint32_t maxSize);
    void enableAutoRotate(bool enabled);
    void enableCompression(bool enabled);
    void enableEncryption(bool enabled, const String& password = "");
    
    // Configuration persistence
    bool loadConfig();
    bool saveConfig();
    String getStorageInfo();
    
    // Session management
    std::vector<CaptureSession> getActiveSessions();
    std::vector<CaptureSession> getCompletedSessions();
    
private:
    static const uint32_t DEFAULT_MAX_CAPTURE_SIZE = 10 * 1024 * 1024; // 10MB
    static const uint8_t PCAP_GLOBAL_HEADER[24];
    
    bool initialized;
    bool captureActive;
    bool sdCardAvailable;
    
    // Capture settings
    CaptureFormat currentCaptureFormat;
    StorageLocation currentStorageLocation;
    uint32_t maxCaptureSize;
    uint32_t currentCaptureSize;
    uint32_t totalCapturedPackets;
    uint32_t totalPacketBytes;
    uint32_t captureStartTime;
    uint32_t sessionCounter;
    bool autoRotateEnabled;
    bool compressionEnabled;
    bool encryptionEnabled;
    String encryptionKey;
    
    // Current capture session
    uint32_t currentCaptureId;
    CaptureSession currentSession;
    File currentCaptureFile;
    std::map<uint32_t, CaptureSession> activeSessions;
    std::vector<CaptureSession> completedSessions;
    
    // Internal methods
    bool rotateCapture();
    void cleanup();
    void initializeStorageManagers();
    String generateCaptureFilename(CaptureFormat format);
    bool isCaptureFile(const String& filename);
    uint32_t getLastSessionNumber();
    String getCaptureFormatString(CaptureFormat format);
    String getStorageLocationString(StorageLocation location);
    
    // File format implementations
    bool writePcapHeader();
    bool writePcapPacket(const uint8_t* packet, uint16_t length, uint32_t timestamp);
    bool writePcapNgHeader();
    bool writePcapNgPacket(const uint8_t* packet, uint16_t length, int32_t rssi, 
                          uint32_t timestamp, uint32_t channel);
    bool writeJsonHeader();
    bool writeJsonPacket(const uint8_t* packet, uint16_t length, int32_t rssi, 
                        uint32_t timestamp, uint32_t channel);
    bool writeJsonFooter();
    bool writeCsvHeader();
    bool writeCsvPacket(const uint8_t* packet, uint16_t length, int32_t rssi, 
                       uint32_t timestamp, uint32_t channel);
};

#endif // WIFI_PERSISTENCE_H