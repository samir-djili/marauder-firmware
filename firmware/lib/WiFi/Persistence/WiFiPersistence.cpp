#include "WiFiPersistence.h"
#include <ArduinoJson.h>
#include <time.h>

// Static PCAP file header
const uint8_t WiFiPersistence::PCAP_GLOBAL_HEADER[24] = {
    0xD4, 0xC3, 0xB2, 0xA1,  // Magic number
    0x02, 0x00,              // Version major
    0x04, 0x00,              // Version minor  
    0x00, 0x00, 0x00, 0x00,  // Timezone offset
    0x00, 0x00, 0x00, 0x00,  // Timestamp accuracy
    0xFF, 0xFF, 0x00, 0x00,  // Max packet length
    0x01, 0x00, 0x00, 0x00   // Data link type (Ethernet)
};

WiFiPersistence::WiFiPersistence() :
    initialized(false),
    captureActive(false),
    currentCaptureFormat(CAPTURE_PCAP),
    maxCaptureSize(DEFAULT_MAX_CAPTURE_SIZE),
    currentCaptureSize(0),
    totalCapturedPackets(0),
    totalPacketBytes(0),
    captureStartTime(0),
    sessionCounter(0),
    autoRotateEnabled(false),
    compressionEnabled(true),
    encryptionEnabled(false),
    currentCaptureId(0) {
    
    // Initialize storage managers
    initializeStorageManagers();
}

WiFiPersistence::~WiFiPersistence() {
    stop();
    cleanup();
}

bool WiFiPersistence::begin() {
    if (initialized) {
        return true;
    }
    
    Serial.println("[Persistence] Initializing WiFi persistence module...");
    
    // Initialize SPIFFS
    if (!SPIFFS.begin()) {
        Serial.println("[Persistence] Failed to initialize SPIFFS");
        return false;
    }
    
    // Initialize SD card if available
    sdCardAvailable = SD.begin();
    if (sdCardAvailable) {
        Serial.println("[Persistence] SD card initialized");
    } else {
        Serial.println("[Persistence] SD card not available, using SPIFFS only");
    }
    
    // Load configuration
    loadConfig();
    
    // Initialize session counter
    sessionCounter = getLastSessionNumber() + 1;
    
    initialized = true;
    Serial.println("[Persistence] Persistence module initialized successfully");
    return true;
}

void WiFiPersistence::update() {
    if (!initialized) return;
    
    // Periodic maintenance tasks
    if (captureActive && currentCaptureFile) {
        currentCaptureFile.flush(); // Ensure data is written
    }
    
    // Auto-rotate if needed
    if (captureActive && autoRotateEnabled && 
        currentCaptureSize >= maxCaptureSize) {
        rotateCapture();
    }
}

void WiFiPersistence::stop() {
    if (captureActive) {
        stopCapture();
    }
    
    initialized = false;
    Serial.println("[Persistence] Persistence module stopped");
}

bool WiFiPersistence::startCapture(const String& filename, CaptureFormat format) {
    if (!initialized || captureActive) {
        return false;
    }
    
    currentCaptureFormat = format;
    
    // Generate filename if not provided
    String captureFile = filename;
    if (captureFile.isEmpty()) {
        captureFile = generateCaptureFilename(format);
    }
    
    // Create capture session
    CaptureSession session;
    session.id = ++currentCaptureId;
    session.filename = captureFile;
    session.format = format;
    session.startTime = millis();
    session.packetCount = 0;
    session.totalBytes = 0;
    session.isActive = true;
    
    // Open file for writing
    bool useSD = sdCardAvailable && (currentStorageLocation == STORAGE_SD || 
                                    currentStorageLocation == STORAGE_AUTO);
    
    File file;
    if (useSD) {
        file = SD.open(captureFile, FILE_WRITE);
        session.storageLocation = STORAGE_SD;
        Serial.printf("[Persistence] Using SD card storage: %s\n", captureFile.c_str());
    } else {
        file = SPIFFS.open(captureFile, "w");
        session.storageLocation = STORAGE_SPIFFS;
        Serial.printf("[Persistence] Using SPIFFS storage: %s\n", captureFile.c_str());
    }
    
    if (!file) {
        Serial.printf("[Persistence] Failed to create capture file: %s\n", captureFile.c_str());
        return false;
    }
    
    currentCaptureFile = file;
    currentSession = session;
    
    // Write file header based on format
    switch (format) {
        case CAPTURE_PCAP:
            if (!writePcapHeader()) {
                file.close();
                return false;
            }
            break;
        case CAPTURE_PCAPNG:
            if (!writePcapNgHeader()) {
                file.close();
                return false;
            }
            break;
        case CAPTURE_JSON:
            if (!writeJsonHeader()) {
                file.close();
                return false;
            }
            break;
        case CAPTURE_CSV:
            if (!writeCsvHeader()) {
                file.close();
                return false;
            }
            break;
    }
    
    captureActive = true;
    captureStartTime = millis();
    currentCaptureSize = 0;
    totalCapturedPackets = 0;
    
    // Add session to active sessions
    activeSessions[session.id] = session;
    
    Serial.printf("[Persistence] Started capture: %s (Format: %s)\n", 
                  captureFile.c_str(), getCaptureFormatString(format).c_str());
    
    return true;
}

bool WiFiPersistence::stopCapture() {
    if (!captureActive || !currentCaptureFile) {
        return false;
    }
    
    // Write file footer if needed
    switch (currentCaptureFormat) {
        case CAPTURE_JSON:
            writeJsonFooter();
            break;
        default:
            break;
    }
    
    currentCaptureFile.close();
    
    // Update session
    currentSession.endTime = millis();
    currentSession.isActive = false;
    activeSessions[currentSession.id] = currentSession;
    
    // Add to completed sessions
    completedSessions.push_back(currentSession);
    
    Serial.printf("[Persistence] Stopped capture: %s (%d packets, %d bytes)\n",
                  currentSession.filename.c_str(), totalCapturedPackets, currentCaptureSize);
    
    captureActive = false;
    return true;
}

bool WiFiPersistence::pauseCapture() {
    if (!captureActive) return false;
    
    // Implementation depends on format
    // For now, just mark as paused
    currentSession.isPaused = true;
    
    Serial.println("[Persistence] Capture paused");
    return true;
}

bool WiFiPersistence::resumeCapture() {
    if (!captureActive || !currentSession.isPaused) return false;
    
    currentSession.isPaused = false;
    
    Serial.println("[Persistence] Capture resumed");
    return true;
}

bool WiFiPersistence::capturePacket(const uint8_t* packet, uint16_t length, int32_t rssi, 
                                  uint32_t timestamp, uint32_t channel) {
    if (!captureActive || !currentCaptureFile || currentSession.isPaused) {
        return false;
    }
    
    // Check file size limit
    if (currentCaptureSize + length + 100 > maxCaptureSize) { // 100 bytes overhead
        if (autoRotateEnabled) {
            rotateCapture();
        } else {
            Serial.println("[Persistence] Capture file size limit reached");
            stopCapture();
            return false;
        }
    }
    
    bool success = false;
    
    switch (currentCaptureFormat) {
        case CAPTURE_PCAP:
            success = writePcapPacket(packet, length, timestamp);
            break;
        case CAPTURE_PCAPNG:
            success = writePcapNgPacket(packet, length, rssi, timestamp, channel);
            break;
        case CAPTURE_JSON:
            success = writeJsonPacket(packet, length, rssi, timestamp, channel);
            break;
        case CAPTURE_CSV:
            success = writeCsvPacket(packet, length, rssi, timestamp, channel);
            break;
    }
    
    if (success) {
        totalCapturedPackets++;
        currentCaptureSize += length;
        totalPacketBytes += length;
        
        currentSession.packetCount = totalCapturedPackets;
        currentSession.totalBytes = currentCaptureSize;
        activeSessions[currentSession.id] = currentSession;
    }
    
    return success;
}

bool WiFiPersistence::exportCapture(const String& sourceFile, const String& targetFile, 
                                  ExportFormat format) {
    Serial.printf("[Persistence] Exporting %s to %s (format: %d)\n", 
                  sourceFile.c_str(), targetFile.c_str(), format);
    
    // Implementation would depend on source and target formats
    // This is a simplified version
    
    File source, target;
    
    // Open source file
    if (SPIFFS.exists(sourceFile)) {
        source = SPIFFS.open(sourceFile, "r");
    } else if (sdCardAvailable && SD.exists(sourceFile)) {
        source = SD.open(sourceFile);
    } else {
        Serial.println("[Persistence] Source file not found");
        return false;
    }
    
    // Create target file
    target = SPIFFS.open(targetFile, "w");
    if (!target) {
        source.close();
        Serial.println("[Persistence] Failed to create target file");
        return false;
    }
    
    // Simple copy for now (format conversion not implemented)
    while (source.available()) {
        target.write(source.read());
    }
    
    source.close();
    target.close();
    
    Serial.printf("[Persistence] Export completed: %s\n", targetFile.c_str());
    return true;
}

std::vector<String> WiFiPersistence::listCaptureFiles() {
    std::vector<String> files;
    
    // List SPIFFS files
    File root = SPIFFS.open("/");
    File file = root.openNextFile();
    while (file) {
        String filename = file.name();
        if (isCaptureFile(filename)) {
            files.push_back("SPIFFS:" + filename);
        }
        file = root.openNextFile();
    }
    
    // List SD card files if available
    if (sdCardAvailable) {
        File sdRoot = SD.open("/");
        File sdFile = sdRoot.openNextFile();
        while (sdFile) {
            String filename = sdFile.name();
            if (isCaptureFile(filename)) {
                files.push_back("SD:" + filename);
            }
            sdFile = sdRoot.openNextFile();
        }
    }
    
    return files;
}

bool WiFiPersistence::deleteCapture(const String& filename) {
    bool deleted = false;
    
    if (SPIFFS.exists(filename)) {
        deleted = SPIFFS.remove(filename);
        Serial.printf("[Persistence] Deleted SPIFFS file: %s (%s)\n", 
                      filename.c_str(), deleted ? "success" : "failed");
    }
    
    if (sdCardAvailable && SD.exists(filename)) {
        deleted = SD.remove(filename) || deleted;
        Serial.printf("[Persistence] Deleted SD file: %s (%s)\n", 
                      filename.c_str(), deleted ? "success" : "failed");
    }
    
    return deleted;
}

CaptureStats WiFiPersistence::getCaptureStats() {
    CaptureStats stats;
    stats.totalCapturedPackets = totalCapturedPackets;
    stats.totalCaptureBytes = totalPacketBytes;
    stats.totalCaptureFiles = completedSessions.size();
    stats.captureUptime = captureActive ? (millis() - captureStartTime) : 0;
    stats.isCapturing = captureActive;
    stats.currentCaptureSize = currentCaptureSize;
    stats.currentFilename = captureActive ? currentSession.filename : "";
    
    return stats;
}

String WiFiPersistence::getCaptureInfo() {
    String info = "=== CAPTURE INFO ===\n";
    info += "Status: " + String(captureActive ? "Active" : "Stopped") + "\n";
    
    if (captureActive) {
        info += "File: " + currentSession.filename + "\n";
        info += "Format: " + getCaptureFormatString(currentCaptureFormat) + "\n";
        info += "Packets: " + String(totalCapturedPackets) + "\n";
        info += "Size: " + String(currentCaptureSize) + " bytes\n";
        info += "Duration: " + String((millis() - captureStartTime) / 1000) + "s\n";
    }
    
    info += "Total sessions: " + String(completedSessions.size()) + "\n";
    info += "Storage: " + getStorageInfo() + "\n";
    
    return info;
}

String WiFiPersistence::getStatusString() {
    if (!initialized) return "Not initialized";
    
    String status = "";
    if (captureActive) {
        status += "Capturing to " + currentSession.filename;
        status += " (" + String(totalCapturedPackets) + " packets)";
    } else {
        status += "Ready";
    }
    
    return status;
}

void WiFiPersistence::setStorageLocation(StorageLocation location) {
    currentStorageLocation = location;
    Serial.printf("[Persistence] Storage location set to: %s\n", 
                  getStorageLocationString(location).c_str());
}

StorageLocation WiFiPersistence::getStorageLocation() {
    return currentStorageLocation;
}

void WiFiPersistence::setMaxCaptureSize(uint32_t maxSize) {
    maxCaptureSize = maxSize;
    Serial.printf("[Persistence] Max capture size set to: %d bytes\n", maxSize);
}

void WiFiPersistence::enableAutoRotate(bool enabled) {
    autoRotateEnabled = enabled;
    Serial.printf("[Persistence] Auto-rotate %s\n", enabled ? "enabled" : "disabled");
}

void WiFiPersistence::enableCompression(bool enabled) {
    compressionEnabled = enabled;
    Serial.printf("[Persistence] Compression %s\n", enabled ? "enabled" : "disabled");
    // Note: Actual compression implementation would require additional libraries
}

void WiFiPersistence::enableEncryption(bool enabled, const String& password) {
    encryptionEnabled = enabled;
    encryptionKey = password;
    Serial.printf("[Persistence] Encryption %s\n", enabled ? "enabled" : "disabled");
    // Note: Actual encryption implementation would require additional libraries
}

bool WiFiPersistence::loadConfig() {
    File configFile = SPIFFS.open("/wifi_persistence_config.json", "r");
    if (!configFile) {
        Serial.println("[Persistence] Config file not found, using defaults");
        return false;
    }
    
    DynamicJsonDocument doc(1024);
    DeserializationError error = deserializeJson(doc, configFile);
    configFile.close();
    
    if (error) {
        Serial.printf("[Persistence] Config parse error: %s\n", error.c_str());
        return false;
    }
    
    // Load settings
    maxCaptureSize = doc["maxCaptureSize"] | DEFAULT_MAX_CAPTURE_SIZE;
    autoRotateEnabled = doc["autoRotate"] | false;
    compressionEnabled = doc["compression"] | true;
    encryptionEnabled = doc["encryption"] | false;
    currentStorageLocation = (StorageLocation)(doc["storageLocation"] | STORAGE_AUTO);
    
    Serial.println("[Persistence] Configuration loaded");
    return true;
}

bool WiFiPersistence::saveConfig() {
    DynamicJsonDocument doc(1024);
    
    doc["maxCaptureSize"] = maxCaptureSize;
    doc["autoRotate"] = autoRotateEnabled;
    doc["compression"] = compressionEnabled;
    doc["encryption"] = encryptionEnabled;
    doc["storageLocation"] = currentStorageLocation;
    
    File configFile = SPIFFS.open("/wifi_persistence_config.json", "w");
    if (!configFile) {
        Serial.println("[Persistence] Failed to create config file");
        return false;
    }
    
    serializeJson(doc, configFile);
    configFile.close();
    
    Serial.println("[Persistence] Configuration saved");
    return true;
}

String WiFiPersistence::getStorageInfo() {
    String info = "";
    
    // SPIFFS info
    info += "SPIFFS: ";
    info += String(SPIFFS.usedBytes()) + "/" + String(SPIFFS.totalBytes()) + " bytes";
    
    // SD card info if available
    if (sdCardAvailable) {
        info += ", SD: Available";
        // Note: Getting SD card size requires additional implementation
    } else {
        info += ", SD: Not available";
    }
    
    return info;
}

std::vector<CaptureSession> WiFiPersistence::getActiveSessions() {
    std::vector<CaptureSession> sessions;
    for (const auto& pair : activeSessions) {
        if (pair.second.isActive) {
            sessions.push_back(pair.second);
        }
    }
    return sessions;
}

std::vector<CaptureSession> WiFiPersistence::getCompletedSessions() {
    return completedSessions;
}

bool WiFiPersistence::rotateCapture() {
    if (!captureActive) return false;
    
    // Stop current capture
    String oldFilename = currentSession.filename;
    stopCapture();
    
    // Start new capture with rotated filename
    String newFilename = generateCaptureFilename(currentCaptureFormat);
    bool result = startCapture(newFilename, currentCaptureFormat);
    
    if (result) {
        Serial.printf("[Persistence] Rotated capture: %s -> %s\n", 
                      oldFilename.c_str(), newFilename.c_str());
    }
    
    return result;
}

void WiFiPersistence::cleanup() {
    // Close any open files
    if (currentCaptureFile) {
        currentCaptureFile.close();
    }
    
    // Clear session data
    activeSessions.clear();
    completedSessions.clear();
    
    Serial.println("[Persistence] Cleanup completed");
}

void WiFiPersistence::initializeStorageManagers() {
    // Initialize default settings
    currentStorageLocation = STORAGE_AUTO;
    maxCaptureSize = DEFAULT_MAX_CAPTURE_SIZE;
    autoRotateEnabled = false;
    compressionEnabled = true;
    encryptionEnabled = false;
}

String WiFiPersistence::generateCaptureFilename(CaptureFormat format) {
    String extension = "";
    switch (format) {
        case CAPTURE_PCAP: extension = ".pcap"; break;
        case CAPTURE_PCAPNG: extension = ".pcapng"; break;
        case CAPTURE_JSON: extension = ".json"; break;
        case CAPTURE_CSV: extension = ".csv"; break;
    }
    
    // Generate timestamp-based filename
    time_t now = time(nullptr);
    struct tm* timeinfo = localtime(&now);
    
    char filename[50];
    snprintf(filename, sizeof(filename), "/capture_%04d%02d%02d_%02d%02d%02d_%d%s",
             timeinfo->tm_year + 1900, timeinfo->tm_mon + 1, timeinfo->tm_mday,
             timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec,
             sessionCounter, extension.c_str());
    
    sessionCounter++;
    return String(filename);
}

bool WiFiPersistence::isCaptureFile(const String& filename) {
    return filename.endsWith(".pcap") || filename.endsWith(".pcapng") || 
           filename.endsWith(".json") || filename.endsWith(".csv");
}

uint32_t WiFiPersistence::getLastSessionNumber() {
    // Simple implementation - could be improved
    return sessionCounter;
}

String WiFiPersistence::getCaptureFormatString(CaptureFormat format) {
    switch (format) {
        case CAPTURE_PCAP: return "PCAP";
        case CAPTURE_PCAPNG: return "PCAPNG";
        case CAPTURE_JSON: return "JSON";
        case CAPTURE_CSV: return "CSV";
        default: return "Unknown";
    }
}

String WiFiPersistence::getStorageLocationString(StorageLocation location) {
    switch (location) {
        case STORAGE_SPIFFS: return "SPIFFS";
        case STORAGE_SD: return "SD Card";
        case STORAGE_AUTO: return "Auto";
        default: return "Unknown";
    }
}

// File format implementations
bool WiFiPersistence::writePcapHeader() {
    return currentCaptureFile.write(PCAP_GLOBAL_HEADER, 24) == 24;
}

bool WiFiPersistence::writePcapPacket(const uint8_t* packet, uint16_t length, uint32_t timestamp) {
    // PCAP packet header (16 bytes)
    uint8_t packetHeader[16];
    
    // Timestamp seconds
    uint32_t ts_sec = timestamp / 1000;
    memcpy(&packetHeader[0], &ts_sec, 4);
    
    // Timestamp microseconds
    uint32_t ts_usec = (timestamp % 1000) * 1000;
    memcpy(&packetHeader[4], &ts_usec, 4);
    
    // Captured length
    memcpy(&packetHeader[8], &length, 4);
    
    // Original length
    memcpy(&packetHeader[12], &length, 4);
    
    // Write header
    if (currentCaptureFile.write(packetHeader, 16) != 16) {
        return false;
    }
    
    // Write packet data
    return currentCaptureFile.write(packet, length) == length;
}

bool WiFiPersistence::writePcapNgHeader() {
    // Simplified PCAPNG header - full implementation would be more complex
    return writePcapHeader(); // Use PCAP format for now
}

bool WiFiPersistence::writePcapNgPacket(const uint8_t* packet, uint16_t length, int32_t rssi, 
                                      uint32_t timestamp, uint32_t channel) {
    // Simplified - use PCAP format for now
    return writePcapPacket(packet, length, timestamp);
}

bool WiFiPersistence::writeJsonHeader() {
    String header = "{\n  \"capture_info\": {\n";
    header += "    \"format\": \"JSON\",\n";
    header += "    \"start_time\": " + String(millis()) + ",\n";
    header += "    \"version\": \"1.0\"\n";
    header += "  },\n  \"packets\": [\n";
    
    return currentCaptureFile.print(header) > 0;
}

bool WiFiPersistence::writeJsonPacket(const uint8_t* packet, uint16_t length, int32_t rssi, 
                                    uint32_t timestamp, uint32_t channel) {
    String packetJson = "";
    if (totalCapturedPackets > 0) {
        packetJson += ",\n";
    }
    
    packetJson += "    {\n";
    packetJson += "      \"timestamp\": " + String(timestamp) + ",\n";
    packetJson += "      \"length\": " + String(length) + ",\n";
    packetJson += "      \"channel\": " + String(channel) + ",\n";
    packetJson += "      \"rssi\": " + String(rssi) + ",\n";
    packetJson += "      \"data\": \"";
    
    // Convert packet to hex string
    for (int i = 0; i < length; i++) {
        char hex[3];
        sprintf(hex, "%02X", packet[i]);
        packetJson += hex;
    }
    
    packetJson += "\"\n    }";
    
    return currentCaptureFile.print(packetJson) > 0;
}

bool WiFiPersistence::writeJsonFooter() {
    String footer = "\n  ]\n}";
    return currentCaptureFile.print(footer) > 0;
}

bool WiFiPersistence::writeCsvHeader() {
    String header = "timestamp,length,channel,rssi,packet_data\n";
    return currentCaptureFile.print(header) > 0;
}

bool WiFiPersistence::writeCsvPacket(const uint8_t* packet, uint16_t length, int32_t rssi, 
                                   uint32_t timestamp, uint32_t channel) {
    String csvLine = String(timestamp) + "," + String(length) + "," + 
                     String(channel) + "," + String(rssi) + ",\"";
    
    // Convert packet to hex string
    for (int i = 0; i < length; i++) {
        char hex[3];
        sprintf(hex, "%02X", packet[i]);
        csvLine += hex;
    }
    
    csvLine += "\"\n";
    
    return currentCaptureFile.print(csvLine) > 0;
}