#ifndef WIFI_ATTACK_H
#define WIFI_ATTACK_H

#include <Arduino.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include <esp_err.h>
#include <vector>
#include <map>
#include <ESPAsyncWebServer.h>
#include <DNSServer.h>

enum WiFiAttackType {
    ATTACK_NONE,
    ATTACK_DEAUTH,
    ATTACK_DISASSOC,
    ATTACK_BEACON_SPAM,
    ATTACK_PROBE_SPAM,
    ATTACK_PMKID,
    ATTACK_EVIL_TWIN,
    ATTACK_CAPTIVE_PORTAL,
    ATTACK_WPS_PIXIE,
    ATTACK_KARMA,
    ATTACK_BROADCAST_DEAUTH
};

struct DeauthTarget {
    String targetMAC;
    String apBSSID;
    uint32_t channel;
    uint32_t packetsPerSecond;
    uint32_t packetsSent;
    bool isActive;
};

struct BeaconSpamConfig {
    std::vector<String> ssidList;
    uint32_t channel;
    uint32_t beaconsPerSecond;
    bool randomizeMAC;
    bool useRandomChannels;
    wifi_auth_mode_t encryptionType;
};

struct EvilTwinConfig {
    String targetSSID;
    String targetBSSID;
    uint32_t channel;
    String password;
    bool openNetwork;
    bool captivePortal;
    String portalTitle;
    String portalMessage;
};

struct CaptivePortalConfig {
    String ssid;
    String password;
    bool openNetwork;
    String portalTitle;
    String portalMessage;
    String redirectURL;
    bool logCredentials;
    std::vector<String> capturedCredentials;
};

class WiFiAttack {
public:
    WiFiAttack();
    ~WiFiAttack();
    
    // Core functionality
    bool begin();
    void update();
    void stop();
    
    // Deauthentication attacks
    void startDeauthAttack(const String& targetMAC, const String& apBSSID, uint32_t channel, uint32_t packetsPerSecond = 10);
    void startBroadcastDeauth(const String& apBSSID, uint32_t channel, uint32_t packetsPerSecond = 10);
    void startMultiTargetDeauth(const std::vector<DeauthTarget>& targets);
    void addDeauthTarget(const String& targetMAC, const String& apBSSID, uint32_t channel);
    void removeDeauthTarget(const String& targetMAC);
    
    // Disassociation attacks
    void startDisassocAttack(const String& targetMAC, const String& apBSSID, uint32_t channel);
    
    // Beacon spam attacks
    void startBeaconSpam(const BeaconSpamConfig& config);
    void addSpamSSID(const String& ssid);
    void loadSSIDWordlist(const String& filename);
    void generateRandomSSIDs(uint32_t count, uint32_t length = 8);
    
    // Probe spam attacks
    void startProbeSpam(const std::vector<String>& ssidList, uint32_t probesPerSecond = 50);
    
    // Evil Twin attacks
    void startEvilTwin(const EvilTwinConfig& config);
    void stopEvilTwin();
    
    // Captive Portal attacks
    void startCaptivePortal(const CaptivePortalConfig& config);
    void stopCaptivePortal();
    std::vector<String> getCapturedCredentials();
    
    // PMKID attacks
    void startPMKIDAttack(const String& targetBSSID, uint32_t channel);
    
    // Karma attacks
    void startKarmaAttack(const std::vector<String>& probeSSIDs);
    
    // WPS attacks
    void startWPSPixieDust(const String& targetBSSID, uint32_t channel);
    
    // Frame injection
    void injectCustomFrame(const std::vector<uint8_t>& frame);
    void injectDeauthFrame(const uint8_t* targetMAC, const uint8_t* apBSSID, uint16_t reason = 7);
    void injectDisassocFrame(const uint8_t* targetMAC, const uint8_t* apBSSID, uint16_t reason = 8);
    void injectBeaconFrame(const String& ssid, const uint8_t* bssid, uint32_t channel, wifi_auth_mode_t encryption);
    
    // Control
    void stopAttack();
    void pauseAttack();
    void resumeAttack();
    
    // Configuration
    void setTxPower(int8_t power); // 0-20 dBm
    void setRandomMAC(bool enabled);
    void setAttackInterval(uint32_t intervalMs);
    void setChannel(uint32_t channel);
    
    // Status and statistics
    bool isAttackActive();
    WiFiAttackType getCurrentAttack();
    String getStatusString();
    uint32_t getPacketsSent();
    uint32_t getTargetCount();
    std::vector<DeauthTarget>& getDeauthTargets();
    
private:
    bool initialized;
    bool attackActive;
    bool attackPaused;
    WiFiAttackType currentAttack;
    
    // Timing
    unsigned long lastAttackPacket;
    unsigned long attackInterval;
    unsigned long lastUpdate;
    
    // Attack configurations
    std::vector<DeauthTarget> deauthTargets;
    BeaconSpamConfig beaconConfig;
    EvilTwinConfig evilTwinConfig;
    CaptivePortalConfig captiveConfig;
    std::vector<String> probeSpamSSIDs;
    
    // Network components
    AsyncWebServer* webServer;
    DNSServer* dnsServer;
    
    // Statistics
    uint32_t totalPacketsSent;
    uint32_t packetsPerSecond;
    unsigned long lastStatsUpdate;
    
    // Frame templates and builders
    void buildDeauthFrame(uint8_t* frame, const uint8_t* targetMAC, const uint8_t* apBSSID, uint16_t reason);
    void buildDisassocFrame(uint8_t* frame, const uint8_t* targetMAC, const uint8_t* apBSSID, uint16_t reason);
    void buildBeaconFrame(uint8_t* frame, const String& ssid, const uint8_t* bssid, uint32_t channel, wifi_auth_mode_t encryption);
    void buildProbeResponseFrame(uint8_t* frame, const String& ssid, const uint8_t* bssid, uint32_t channel);
    
    // Attack implementations
    void executeDeauthAttack();
    void executeBeaconSpam();
    void executeProbeSpam();
    void executePMKIDAttack();
    void executeKarmaAttack();
    
    // Evil Twin / Captive Portal implementations
    void setupEvilTwinAP();
    void setupCaptivePortal();
    void handleCaptivePortalRequest(AsyncWebServerRequest* request);
    void handleCredentialCapture(AsyncWebServerRequest* request);
    
    // Utility functions
    bool parseMAC(const String& macStr, uint8_t* mac);
    String macToString(const uint8_t* mac);
    void generateRandomMAC(uint8_t* mac);
    uint16_t calculateChecksum(const uint8_t* data, uint16_t length);
    void setWiFiChannel(uint32_t channel);
    
    // Static callback handlers
    static void webServerHandler(AsyncWebServerRequest* request);
    static void dnsServerHandler();
    
    // HTML templates
    String getCaptivePortalHTML();
    String getLoginFormHTML();
    String getSuccessPageHTML();
};

#endif // WIFI_ATTACK_H