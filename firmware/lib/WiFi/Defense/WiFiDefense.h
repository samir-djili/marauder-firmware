#ifndef WIFI_DEFENSE_H
#define WIFI_DEFENSE_H

#include <Arduino.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include <esp_err.h>
#include <vector>
#include <map>

struct ThreatSignature {
    String name;
    String description;
    uint8_t severity; // 1-10
    std::vector<uint8_t> pattern;
    uint32_t minPacketLength;
    uint32_t maxPacketLength;
    bool enabled;
};

struct DetectedThreat {
    String threatName;
    String sourceMAC;
    String targetMAC;
    uint32_t channel;
    uint32_t timestamp;
    uint8_t severity;
    uint32_t occurrenceCount;
    String description;
};

struct RogueAP {
    String ssid;
    String bssid;
    uint32_t channel;
    int32_t rssi;
    uint32_t firstSeen;
    uint32_t lastSeen;
    uint32_t beaconCount;
    String suspiciousReason;
    uint8_t threatLevel; // 1-10
};

struct AnomalousStation {
    String mac;
    uint32_t channel;
    int32_t rssi;
    uint32_t firstSeen;
    uint32_t lastSeen;
    uint32_t packetCount;
    String suspiciousActivity;
    uint8_t threatLevel;
};

enum DefenseMode {
    DEFENSE_PASSIVE,        // Monitor only
    DEFENSE_ACTIVE,         // Block detected threats
    DEFENSE_AGGRESSIVE,     // Proactive threat neutralization
    DEFENSE_LEARNING        // Machine learning mode
};

class WiFiDefense {
public:
    WiFiDefense();
    ~WiFiDefense();
    
    // Core functionality
    bool begin();
    void update();
    void stop();
    
    // Defense modes
    void setDefenseMode(DefenseMode mode);
    DefenseMode getDefenseMode();
    
    // Threat detection
    void startThreatMonitoring(uint32_t channel = 0); // 0 = all channels
    void stopThreatMonitoring();
    void addThreatSignature(const ThreatSignature& signature);
    void removeThreatSignature(const String& name);
    void loadThreatDatabase(const String& filename);
    
    // Rogue AP detection
    void startRogueAPDetection();
    void stopRogueAPDetection();
    void addTrustedAP(const String& bssid, const String& ssid = "");
    void removeTrustedAP(const String& bssid);
    void setRogueAPThreshold(uint8_t threshold);
    
    // Deauth attack detection
    void enableDeauthDetection(bool enabled);
    void setDeauthThreshold(uint32_t packetsPerSecond);
    
    // Evil twin detection
    void enableEvilTwinDetection(bool enabled);
    void addKnownNetwork(const String& ssid, const String& bssid);
    
    // Beacon spam detection
    void enableBeaconSpamDetection(bool enabled);
    void setBeaconSpamThreshold(uint32_t beaconsPerSecond);
    
    // Active defense
    void enableActiveDefense(bool enabled);
    void setCounterAttackMode(bool enabled);
    void addProtectedNetwork(const String& bssid);
    void removeProtectedNetwork(const String& bssid);
    
    // Whitelist/Blacklist management
    void addToWhitelist(const String& mac);
    void removeFromWhitelist(const String& mac);
    void addToBlacklist(const String& mac);
    void removeFromBlacklist(const String& mac);
    void clearWhitelist();
    void clearBlacklist();
    
    // Data access
    std::vector<DetectedThreat>& getDetectedThreats();
    std::vector<RogueAP>& getRogueAPs();
    std::vector<AnomalousStation>& getAnomalousStations();
    std::vector<ThreatSignature>& getThreatSignatures();
    
    // Analysis and reporting
    uint32_t getThreatCount();
    uint32_t getRogueAPCount();
    String getThreatReport();
    String getSecurityScore(); // 0-100
    std::map<String, uint32_t> getThreatStatistics();
    
    // Configuration
    void setSensitivity(uint8_t level); // 1-10
    void setAlertThreshold(uint8_t severity);
    void enableLogging(bool enabled);
    void setMaxThreats(uint32_t maxThreats);
    
    // Status
    bool isMonitoring();
    String getStatusString();
    uint32_t getProcessedPackets();
    
private:
    bool initialized;
    bool monitoringActive;
    DefenseMode currentMode;
    
    // Detection settings
    bool deauthDetectionEnabled;
    bool evilTwinDetectionEnabled;
    bool beaconSpamDetectionEnabled;
    bool rogueAPDetectionEnabled;
    bool activeDefenseEnabled;
    bool counterAttackEnabled;
    
    // Thresholds
    uint32_t deauthThreshold;
    uint32_t beaconSpamThreshold;
    uint8_t rogueAPThreshold;
    uint8_t sensitivityLevel;
    uint8_t alertThreshold;
    
    // Data storage
    std::vector<DetectedThreat> detectedThreats;
    std::vector<RogueAP> rogueAPs;
    std::vector<AnomalousStation> anomalousStations;
    std::vector<ThreatSignature> threatSignatures;
    
    // Network lists
    std::vector<String> trustedAPs;
    std::vector<String> protectedNetworks;
    std::vector<String> whitelist;
    std::vector<String> blacklist;
    std::map<String, String> knownNetworks; // ssid -> bssid
    
    // Statistics and tracking
    std::map<String, uint32_t> deauthPacketCount;
    std::map<String, uint32_t> beaconCount;
    std::map<String, uint32_t> threatOccurrences;
    uint32_t totalProcessedPackets;
    unsigned long lastStatsReset;
    
    // Channel management
    uint32_t currentChannel;
    bool channelHopping;
    unsigned long lastChannelHop;
    
    // Static callback
    static void promiscuousCallback(void* buf, wifi_promiscuous_pkt_type_t type);
    
    // Internal methods
    void processPacketForThreats(void* buf, wifi_promiscuous_pkt_type_t type);
    void analyzeManagementFrame(const uint8_t* frame, uint16_t len, int32_t rssi, uint32_t channel);
    void analyzeDataFrame(const uint8_t* frame, uint16_t len, int32_t rssi, uint32_t channel);
    
    // Threat detection algorithms
    bool detectDeauthAttack(const uint8_t* frame, uint16_t len, uint32_t channel);
    bool detectBeaconSpam(const uint8_t* frame, uint16_t len, uint32_t channel);
    bool detectEvilTwin(const uint8_t* frame, uint16_t len, uint32_t channel);
    bool detectRogueAP(const uint8_t* frame, uint16_t len, int32_t rssi, uint32_t channel);
    bool detectAnomalousStation(const uint8_t* frame, uint16_t len, uint32_t channel);
    bool matchThreatSignature(const uint8_t* frame, uint16_t len);
    
    // Active defense methods
    void executeCounterAttack(const String& attackerMAC, uint32_t channel);
    void sendDeauthToAttacker(const String& attackerMAC, uint32_t channel);
    void jamAttackerChannel(uint32_t channel);
    
    // Utility functions
    bool isInWhitelist(const String& mac);
    bool isInBlacklist(const String& mac);
    bool isTrustedAP(const String& bssid);
    bool isProtectedNetwork(const String& bssid);
    void addThreat(const String& name, const String& source, const String& target, 
                   uint32_t channel, uint8_t severity, const String& description);
    void updateThreatStatistics();
    String macToString(const uint8_t* mac);
    bool parseMAC(const String& macStr, uint8_t* mac);
    uint8_t calculateSecurityScore();
    
    // Built-in threat signatures
    void loadBuiltinSignatures();
    ThreatSignature createDeauthSignature();
    ThreatSignature createDisassocSignature();
    ThreatSignature createBeaconFloodSignature();
    ThreatSignature createProbeFloodSignature();
};

#endif // WIFI_DEFENSE_H