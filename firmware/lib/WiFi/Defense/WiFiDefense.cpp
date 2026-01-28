#include "WiFiDefense.h"

// Static instance for callbacks
static WiFiDefense* defenseInstance = nullptr;

WiFiDefense::WiFiDefense() :
    initialized(false),
    monitoringActive(false),
    currentMode(DEFENSE_PASSIVE),
    deauthDetectionEnabled(true),
    evilTwinDetectionEnabled(true),
    beaconSpamDetectionEnabled(true),
    rogueAPDetectionEnabled(true),
    activeDefenseEnabled(false),
    counterAttackEnabled(false),
    deauthThreshold(10),
    beaconSpamThreshold(50),
    rogueAPThreshold(7),
    sensitivityLevel(5),
    alertThreshold(5),
    totalProcessedPackets(0),
    lastStatsReset(0),
    currentChannel(1),
    channelHopping(false),
    lastChannelHop(0) {
    
    defenseInstance = this;
    loadBuiltinSignatures();
}

WiFiDefense::~WiFiDefense() {
    stop();
    defenseInstance = nullptr;
}

bool WiFiDefense::begin() {
    if (initialized) {
        return true;
    }
    
    Serial.println("[Defense] Initializing WiFi defense module...");
    
    // Initialize WiFi
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    delay(100);
    
    initialized = true;
    Serial.println("[Defense] Defense module initialized successfully");
    return true;
}

void WiFiDefense::update() {
    if (!initialized) return;
    
    // Update threat statistics periodically
    if (millis() - lastStatsReset > 60000) { // Every minute
        updateThreatStatistics();
        lastStatsReset = millis();
    }
    
    // Handle channel hopping if enabled
    if (channelHopping && (millis() - lastChannelHop > 1000)) {
        currentChannel = (currentChannel % 14) + 1;
        esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
        lastChannelHop = millis();
    }
}

void WiFiDefense::stop() {
    if (!initialized) return;
    
    Serial.println("[Defense] Stopping WiFi defense module...");
    
    stopThreatMonitoring();
    stopRogueAPDetection();
    
    initialized = false;
    Serial.println("[Defense] Defense module stopped");
}

void WiFiDefense::setDefenseMode(DefenseMode mode) {
    currentMode = mode;
    
    const char* modeStr[] = {"PASSIVE", "ACTIVE", "AGGRESSIVE", "LEARNING"};
    Serial.printf("[Defense] Defense mode set to: %s\n", modeStr[mode]);
    
    switch (mode) {
        case DEFENSE_PASSIVE:
            activeDefenseEnabled = false;
            counterAttackEnabled = false;
            break;
        case DEFENSE_ACTIVE:
            activeDefenseEnabled = true;
            counterAttackEnabled = false;
            break;
        case DEFENSE_AGGRESSIVE:
            activeDefenseEnabled = true;
            counterAttackEnabled = true;
            break;
        case DEFENSE_LEARNING:
            // TODO: Implement machine learning mode
            break;
    }
}

DefenseMode WiFiDefense::getDefenseMode() {
    return currentMode;
}

void WiFiDefense::startThreatMonitoring(uint32_t channel) {
    if (!initialized) return;
    
    if (channel == 0) {
        Serial.println("[Defense] Starting threat monitoring on all channels");
        channelHopping = true;
    } else {
        Serial.printf("[Defense] Starting threat monitoring on channel %d\n", channel);
        currentChannel = channel;
        channelHopping = false;
    }
    
    // Enable promiscuous mode
    WiFi.mode(WIFI_MODE_NULL);
    delay(100);
    esp_wifi_set_promiscuous_rx_cb(&promiscuousCallback);
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
    
    monitoringActive = true;
    Serial.println("[Defense] Threat monitoring started");
}

void WiFiDefense::stopThreatMonitoring() {
    if (!monitoringActive) return;
    
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(nullptr);
    monitoringActive = false;
    channelHopping = false;
    
    // Return to station mode
    WiFi.mode(WIFI_STA);
    delay(100);
    
    Serial.println("[Defense] Threat monitoring stopped");
}

void WiFiDefense::addThreatSignature(const ThreatSignature& signature) {
    threatSignatures.push_back(signature);
    Serial.printf("[Defense] Added threat signature: %s\n", signature.name.c_str());
}

void WiFiDefense::removeThreatSignature(const String& name) {
    threatSignatures.erase(
        std::remove_if(threatSignatures.begin(), threatSignatures.end(),
            [&name](const ThreatSignature& sig) {
                return sig.name == name;
            }), threatSignatures.end());
    
    Serial.printf("[Defense] Removed threat signature: %s\n", name.c_str());
}

void WiFiDefense::loadThreatDatabase(const String& filename) {
    // TODO: Implement file loading
    Serial.printf("[Defense] Loading threat database from: %s\n", filename.c_str());
}

void WiFiDefense::startRogueAPDetection() {
    rogueAPDetectionEnabled = true;
    Serial.println("[Defense] Rogue AP detection enabled");
    
    if (!monitoringActive) {
        startThreatMonitoring();
    }
}

void WiFiDefense::stopRogueAPDetection() {
    rogueAPDetectionEnabled = false;
    Serial.println("[Defense] Rogue AP detection disabled");
}

void WiFiDefense::addTrustedAP(const String& bssid, const String& ssid) {
    trustedAPs.push_back(bssid);
    if (!ssid.isEmpty()) {
        knownNetworks[ssid] = bssid;
    }
    Serial.printf("[Defense] Added trusted AP: %s (%s)\n", bssid.c_str(), ssid.c_str());
}

void WiFiDefense::removeTrustedAP(const String& bssid) {
    trustedAPs.erase(
        std::remove(trustedAPs.begin(), trustedAPs.end(), bssid),
        trustedAPs.end());
    
    Serial.printf("[Defense] Removed trusted AP: %s\n", bssid.c_str());
}

void WiFiDefense::setRogueAPThreshold(uint8_t threshold) {
    rogueAPThreshold = threshold;
    Serial.printf("[Defense] Rogue AP threshold set to: %d\n", threshold);
}

void WiFiDefense::enableDeauthDetection(bool enabled) {
    deauthDetectionEnabled = enabled;
    Serial.printf("[Defense] Deauth detection %s\n", enabled ? "enabled" : "disabled");
}

void WiFiDefense::setDeauthThreshold(uint32_t packetsPerSecond) {
    deauthThreshold = packetsPerSecond;
    Serial.printf("[Defense] Deauth threshold set to: %d pps\n", packetsPerSecond);
}

void WiFiDefense::enableEvilTwinDetection(bool enabled) {
    evilTwinDetectionEnabled = enabled;
    Serial.printf("[Defense] Evil twin detection %s\n", enabled ? "enabled" : "disabled");
}

void WiFiDefense::addKnownNetwork(const String& ssid, const String& bssid) {
    knownNetworks[ssid] = bssid;
    Serial.printf("[Defense] Added known network: %s -> %s\n", ssid.c_str(), bssid.c_str());
}

void WiFiDefense::enableBeaconSpamDetection(bool enabled) {
    beaconSpamDetectionEnabled = enabled;
    Serial.printf("[Defense] Beacon spam detection %s\n", enabled ? "enabled" : "disabled");
}

void WiFiDefense::setBeaconSpamThreshold(uint32_t beaconsPerSecond) {
    beaconSpamThreshold = beaconsPerSecond;
    Serial.printf("[Defense] Beacon spam threshold set to: %d bps\n", beaconsPerSecond);
}

void WiFiDefense::enableActiveDefense(bool enabled) {
    activeDefenseEnabled = enabled;
    Serial.printf("[Defense] Active defense %s\n", enabled ? "enabled" : "disabled");
}

void WiFiDefense::setCounterAttackMode(bool enabled) {
    counterAttackEnabled = enabled;
    Serial.printf("[Defense] Counter-attack mode %s\n", enabled ? "enabled" : "disabled");
}

void WiFiDefense::addProtectedNetwork(const String& bssid) {
    protectedNetworks.push_back(bssid);
    Serial.printf("[Defense] Added protected network: %s\n", bssid.c_str());
}

void WiFiDefense::removeProtectedNetwork(const String& bssid) {
    protectedNetworks.erase(
        std::remove(protectedNetworks.begin(), protectedNetworks.end(), bssid),
        protectedNetworks.end());
    
    Serial.printf("[Defense] Removed protected network: %s\n", bssid.c_str());
}

void WiFiDefense::addToWhitelist(const String& mac) {
    whitelist.push_back(mac);
    Serial.printf("[Defense] Added to whitelist: %s\n", mac.c_str());
}

void WiFiDefense::removeFromWhitelist(const String& mac) {
    whitelist.erase(
        std::remove(whitelist.begin(), whitelist.end(), mac),
        whitelist.end());
    
    Serial.printf("[Defense] Removed from whitelist: %s\n", mac.c_str());
}

void WiFiDefense::addToBlacklist(const String& mac) {
    blacklist.push_back(mac);
    Serial.printf("[Defense] Added to blacklist: %s\n", mac.c_str());
}

void WiFiDefense::removeFromBlacklist(const String& mac) {
    blacklist.erase(
        std::remove(blacklist.begin(), blacklist.end(), mac),
        blacklist.end());
    
    Serial.printf("[Defense] Removed from blacklist: %s\n", mac.c_str());
}

void WiFiDefense::clearWhitelist() {
    whitelist.clear();
    Serial.println("[Defense] Whitelist cleared");
}

void WiFiDefense::clearBlacklist() {
    blacklist.clear();
    Serial.println("[Defense] Blacklist cleared");
}

std::vector<DetectedThreat>& WiFiDefense::getDetectedThreats() {
    return detectedThreats;
}

std::vector<RogueAP>& WiFiDefense::getRogueAPs() {
    return rogueAPs;
}

std::vector<AnomalousStation>& WiFiDefense::getAnomalousStations() {
    return anomalousStations;
}

std::vector<ThreatSignature>& WiFiDefense::getThreatSignatures() {
    return threatSignatures;
}

uint32_t WiFiDefense::getThreatCount() {
    return detectedThreats.size();
}

uint32_t WiFiDefense::getRogueAPCount() {
    return rogueAPs.size();
}

String WiFiDefense::getThreatReport() {
    String report = "=== THREAT REPORT ===\n";
    report += "Total threats detected: " + String(detectedThreats.size()) + "\n";
    report += "Rogue APs: " + String(rogueAPs.size()) + "\n";
    report += "Anomalous stations: " + String(anomalousStations.size()) + "\n";
    report += "Security score: " + getSecurityScore() + "/100\n";
    report += "\nRecent threats:\n";
    
    int count = 0;
    for (auto it = detectedThreats.rbegin(); it != detectedThreats.rend() && count < 10; ++it, ++count) {
        report += "- " + it->threatName + " from " + it->sourceMAC + " (Severity: " + String(it->severity) + ")\n";
    }
    
    return report;
}

String WiFiDefense::getSecurityScore() {
    uint8_t score = calculateSecurityScore();
    return String(score);
}

std::map<String, uint32_t> WiFiDefense::getThreatStatistics() {
    std::map<String, uint32_t> stats;
    
    for (const auto& threat : detectedThreats) {
        stats[threat.threatName]++;
    }
    
    return stats;
}

void WiFiDefense::setSensitivity(uint8_t level) {
    sensitivityLevel = level;
    Serial.printf("[Defense] Sensitivity level set to: %d\n", level);
}

void WiFiDefense::setAlertThreshold(uint8_t severity) {
    alertThreshold = severity;
    Serial.printf("[Defense] Alert threshold set to: %d\n", severity);
}

void WiFiDefense::enableLogging(bool enabled) {
    // TODO: Implement logging
    Serial.printf("[Defense] Logging %s\n", enabled ? "enabled" : "disabled");
}

void WiFiDefense::setMaxThreats(uint32_t maxThreats) {
    // TODO: Implement threat limit management
    Serial.printf("[Defense] Max threats set to: %d\n", maxThreats);
}

bool WiFiDefense::isMonitoring() {
    return monitoringActive;
}

String WiFiDefense::getStatusString() {
    if (!initialized) return "Not initialized";
    if (!monitoringActive) return "Ready";
    
    String status = "Monitoring";
    if (channelHopping) {
        status += " (Hopping)";
    } else {
        status += " (Ch" + String(currentChannel) + ")";
    }
    
    const char* modeStr[] = {"PASSIVE", "ACTIVE", "AGGRESSIVE", "LEARNING"};
    status += " - " + String(modeStr[currentMode]);
    
    return status;
}

uint32_t WiFiDefense::getProcessedPackets() {
    return totalProcessedPackets;
}

// Static callback
void WiFiDefense::promiscuousCallback(void* buf, wifi_promiscuous_pkt_type_t type) {
    if (defenseInstance) {
        defenseInstance->processPacketForThreats(buf, type);
    }
}

void WiFiDefense::processPacketForThreats(void* buf, wifi_promiscuous_pkt_type_t type) {
    totalProcessedPackets++;
    
    wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
    wifi_pkt_rx_ctrl_t* ctrl = &pkt->rx_ctrl;
    
    const uint8_t* frame = pkt->payload;
    uint16_t len = ctrl->sig_len;
    int32_t rssi = ctrl->rssi;
    
    if (len < 24) return; // Minimum 802.11 frame size
    
    // Parse frame control
    uint8_t frameType = (frame[0] & 0x0C) >> 2;
    
    // Process based on frame type
    switch (frameType) {
        case 0: // Management frame
            analyzeManagementFrame(frame, len, rssi, currentChannel);
            break;
        case 2: // Data frame
            analyzeDataFrame(frame, len, rssi, currentChannel);
            break;
    }
    
    // Check against threat signatures
    if (matchThreatSignature(frame, len)) {
        // Threat signature matched - handled in matchThreatSignature
    }
}

void WiFiDefense::analyzeManagementFrame(const uint8_t* frame, uint16_t len, int32_t rssi, uint32_t channel) {
    uint8_t frameSubtype = (frame[0] & 0xF0) >> 4;
    
    switch (frameSubtype) {
        case 0x08: // Beacon
            if (beaconSpamDetectionEnabled) {
                detectBeaconSpam(frame, len, channel);
            }
            if (rogueAPDetectionEnabled) {
                detectRogueAP(frame, len, rssi, channel);
            }
            if (evilTwinDetectionEnabled) {
                detectEvilTwin(frame, len, channel);
            }
            break;
            
        case 0x0C: // Deauth
            if (deauthDetectionEnabled) {
                detectDeauthAttack(frame, len, channel);
            }
            break;
    }
}

void WiFiDefense::analyzeDataFrame(const uint8_t* frame, uint16_t len, int32_t rssi, uint32_t channel) {
    String srcMAC = macToString(&frame[10]);
    
    // Check for anomalous station behavior
    detectAnomalousStation(frame, len, channel);
    
    // Check if source is blacklisted
    if (isInBlacklist(srcMAC)) {
        addThreat("Blacklisted Device Activity", srcMAC, "", channel, 8, 
                 "Activity detected from blacklisted device");
        
        if (activeDefenseEnabled) {
            executeCounterAttack(srcMAC, channel);
        }
    }
}

bool WiFiDefense::detectDeauthAttack(const uint8_t* frame, uint16_t len, uint32_t channel) {
    String srcMAC = macToString(&frame[10]);
    String dstMAC = macToString(&frame[4]);
    
    // Track deauth packets from this source
    deauthPacketCount[srcMAC]++;
    
    // Check threshold
    if (deauthPacketCount[srcMAC] > deauthThreshold) {
        addThreat("Deauthentication Attack", srcMAC, dstMAC, channel, 9,
                 "High rate of deauthentication frames detected");
        
        if (counterAttackEnabled && !isInWhitelist(srcMAC)) {
            executeCounterAttack(srcMAC, channel);
        }
        
        return true;
    }
    
    return false;
}

bool WiFiDefense::detectBeaconSpam(const uint8_t* frame, uint16_t len, uint32_t channel) {
    beaconCount[macToString(&frame[10])]++;
    
    // Count total beacons on this channel
    uint32_t totalBeacons = 0;
    for (const auto& entry : beaconCount) {
        totalBeacons += entry.second;
    }
    
    // Check for beacon spam
    if (totalBeacons > beaconSpamThreshold) {
        addThreat("Beacon Spam Attack", macToString(&frame[10]), "", channel, 6,
                 "High rate of beacon frames detected");
        return true;
    }
    
    return false;
}

bool WiFiDefense::detectEvilTwin(const uint8_t* frame, uint16_t len, uint32_t channel) {
    if (len < 36) return false;
    
    // Extract SSID
    String ssid = "";
    uint16_t offset = 36;
    while (offset + 2 < len) {
        uint8_t elementId = frame[offset];
        uint8_t elementLen = frame[offset + 1];
        
        if (offset + 2 + elementLen > len) break;
        
        if (elementId == 0 && elementLen > 0) { // SSID element
            for (int i = 0; i < elementLen; i++) {
                ssid += (char)frame[offset + 2 + i];
            }
            break;
        }
        
        offset += 2 + elementLen;
    }
    
    String bssid = macToString(&frame[10]);
    
    // Check if this SSID should have a different BSSID
    auto it = knownNetworks.find(ssid);
    if (it != knownNetworks.end() && it->second != bssid) {
        addThreat("Evil Twin Access Point", bssid, "", channel, 9,
                 "Duplicate SSID with different BSSID detected: " + ssid);
        return true;
    }
    
    return false;
}

bool WiFiDefense::detectRogueAP(const uint8_t* frame, uint16_t len, int32_t rssi, uint32_t channel) {
    String bssid = macToString(&frame[10]);
    
    // Check if this is a trusted AP
    if (isTrustedAP(bssid)) {
        return false;
    }
    
    // Look for signs of rogue AP
    uint8_t threatLevel = 0;
    String reason = "";
    
    // Check for weak signal (might indicate close proximity)
    if (rssi > -30) {
        threatLevel += 2;
        reason += "Very strong signal; ";
    }
    
    // Check for suspicious SSID patterns
    String ssid = "";
    uint16_t offset = 36;
    while (offset + 2 < len) {
        uint8_t elementId = frame[offset];
        uint8_t elementLen = frame[offset + 1];
        
        if (offset + 2 + elementLen > len) break;
        
        if (elementId == 0 && elementLen > 0) { // SSID element
            for (int i = 0; i < elementLen; i++) {
                ssid += (char)frame[offset + 2 + i];
            }
            break;
        }
        
        offset += 2 + elementLen;
    }
    
    // Check for common rogue AP SSIDs
    if (ssid.indexOf("Free") != -1 || ssid.indexOf("WiFi") != -1 || 
        ssid.indexOf("Internet") != -1 || ssid.indexOf("Guest") != -1) {
        threatLevel += 3;
        reason += "Suspicious SSID pattern; ";
    }
    
    // Check if threat level exceeds threshold
    if (threatLevel >= rogueAPThreshold) {
        // Add to rogue AP list
        RogueAP rogue;
        rogue.ssid = ssid;
        rogue.bssid = bssid;
        rogue.channel = channel;
        rogue.rssi = rssi;
        rogue.firstSeen = millis();
        rogue.lastSeen = millis();
        rogue.beaconCount = 1;
        rogue.suspiciousReason = reason;
        rogue.threatLevel = threatLevel;
        
        rogueAPs.push_back(rogue);
        
        addThreat("Rogue Access Point", bssid, "", channel, threatLevel,
                 "Suspicious AP detected: " + reason);
        return true;
    }
    
    return false;
}

bool WiFiDefense::detectAnomalousStation(const uint8_t* frame, uint16_t len, uint32_t channel) {
    String srcMAC = macToString(&frame[10]);
    
    // Simple anomaly detection - high packet rate
    // TODO: Implement more sophisticated anomaly detection
    
    return false;
}

bool WiFiDefense::matchThreatSignature(const uint8_t* frame, uint16_t len) {
    for (const auto& signature : threatSignatures) {
        if (!signature.enabled) continue;
        
        if (len < signature.minPacketLength || len > signature.maxPacketLength) {
            continue;
        }
        
        // Simple pattern matching
        if (signature.pattern.size() <= len) {
            bool match = true;
            for (size_t i = 0; i < signature.pattern.size(); i++) {
                if (frame[i] != signature.pattern[i]) {
                    match = false;
                    break;
                }
            }
            
            if (match) {
                addThreat(signature.name, macToString(&frame[10]), macToString(&frame[4]), 
                         currentChannel, signature.severity, signature.description);
                return true;
            }
        }
    }
    
    return false;
}

void WiFiDefense::executeCounterAttack(const String& attackerMAC, uint32_t channel) {
    if (!counterAttackEnabled) return;
    
    Serial.printf("[Defense] Executing counter-attack against: %s\n", attackerMAC.c_str());
    
    // Send deauth frames back to attacker
    sendDeauthToAttacker(attackerMAC, channel);
}

void WiFiDefense::sendDeauthToAttacker(const String& attackerMAC, uint32_t channel) {
    uint8_t mac[6];
    if (!parseMAC(attackerMAC, mac)) return;
    
    // Build deauth frame
    uint8_t deauthFrame[26];
    memset(deauthFrame, 0, 26);
    
    // Frame Control (Deauth = 0xC0)
    deauthFrame[0] = 0xC0;
    deauthFrame[1] = 0x00;
    
    // Destination (attacker)
    memcpy(&deauthFrame[4], mac, 6);
    
    // Source (broadcast)
    memset(&deauthFrame[10], 0xFF, 6);
    
    // BSSID (broadcast)
    memset(&deauthFrame[16], 0xFF, 6);
    
    // Reason Code
    deauthFrame[24] = 0x08; // Disassociated because sending STA is leaving BSS
    deauthFrame[25] = 0x00;
    
    // Send multiple frames
    for (int i = 0; i < 5; i++) {
        esp_wifi_80211_tx(WIFI_IF_STA, deauthFrame, sizeof(deauthFrame), false);
        delay(10);
    }
}

void WiFiDefense::jamAttackerChannel(uint32_t channel) {
    // TODO: Implement channel jamming (be careful with regulations)
}

// Utility functions
bool WiFiDefense::isInWhitelist(const String& mac) {
    return std::find(whitelist.begin(), whitelist.end(), mac) != whitelist.end();
}

bool WiFiDefense::isInBlacklist(const String& mac) {
    return std::find(blacklist.begin(), blacklist.end(), mac) != blacklist.end();
}

bool WiFiDefense::isTrustedAP(const String& bssid) {
    return std::find(trustedAPs.begin(), trustedAPs.end(), bssid) != trustedAPs.end();
}

bool WiFiDefense::isProtectedNetwork(const String& bssid) {
    return std::find(protectedNetworks.begin(), protectedNetworks.end(), bssid) != protectedNetworks.end();
}

void WiFiDefense::addThreat(const String& name, const String& source, const String& target, 
                          uint32_t channel, uint8_t severity, const String& description) {
    DetectedThreat threat;
    threat.threatName = name;
    threat.sourceMAC = source;
    threat.targetMAC = target;
    threat.channel = channel;
    threat.timestamp = millis();
    threat.severity = severity;
    threat.occurrenceCount = 1;
    threat.description = description;
    
    // Check if this threat already exists
    for (auto& existingThreat : detectedThreats) {
        if (existingThreat.threatName == name && existingThreat.sourceMAC == source) {
            existingThreat.occurrenceCount++;
            existingThreat.timestamp = millis();
            return;
        }
    }
    
    detectedThreats.push_back(threat);
    threatOccurrences[name]++;
    
    if (severity >= alertThreshold) {
        Serial.printf("[THREAT ALERT] %s - Source: %s, Severity: %d\n", 
                      name.c_str(), source.c_str(), severity);
    }
}

void WiFiDefense::updateThreatStatistics() {
    // Reset counters that are time-based
    deauthPacketCount.clear();
    beaconCount.clear();
}

String WiFiDefense::macToString(const uint8_t* mac) {
    char macStr[18];
    snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return String(macStr);
}

bool WiFiDefense::parseMAC(const String& macStr, uint8_t* mac) {
    if (macStr.length() != 17) return false;
    
    for (int i = 0; i < 6; i++) {
        String byte = macStr.substring(i * 3, i * 3 + 2);
        mac[i] = strtol(byte.c_str(), nullptr, 16);
    }
    return true;
}

uint8_t WiFiDefense::calculateSecurityScore() {
    // Simple security scoring algorithm
    uint8_t score = 100;
    
    // Deduct points for detected threats
    score -= std::min(50, (int)(detectedThreats.size() * 2));
    
    // Deduct points for rogue APs
    score -= std::min(30, (int)(rogueAPs.size() * 5));
    
    // Deduct points for anomalous stations
    score -= std::min(20, (int)(anomalousStations.size() * 3));
    
    return score;
}

// Built-in threat signatures
void WiFiDefense::loadBuiltinSignatures() {
    // Add built-in signatures
    threatSignatures.push_back(createDeauthSignature());
    threatSignatures.push_back(createDisassocSignature());
    threatSignatures.push_back(createBeaconFloodSignature());
    threatSignatures.push_back(createProbeFloodSignature());
    
    Serial.printf("[Defense] Loaded %d built-in threat signatures\n", threatSignatures.size());
}

ThreatSignature WiFiDefense::createDeauthSignature() {
    ThreatSignature sig;
    sig.name = "Deauthentication Frame";
    sig.description = "802.11 deauthentication management frame";
    sig.severity = 8;
    sig.pattern = {0xC0, 0x00}; // Deauth frame control
    sig.minPacketLength = 24;
    sig.maxPacketLength = 1500;
    sig.enabled = true;
    return sig;
}

ThreatSignature WiFiDefense::createDisassocSignature() {
    ThreatSignature sig;
    sig.name = "Disassociation Frame";
    sig.description = "802.11 disassociation management frame";
    sig.severity = 7;
    sig.pattern = {0xA0, 0x00}; // Disassoc frame control
    sig.minPacketLength = 24;
    sig.maxPacketLength = 1500;
    sig.enabled = true;
    return sig;
}

ThreatSignature WiFiDefense::createBeaconFloodSignature() {
    ThreatSignature sig;
    sig.name = "Beacon Frame";
    sig.description = "802.11 beacon management frame (potential flood)";
    sig.severity = 5;
    sig.pattern = {0x80, 0x00}; // Beacon frame control
    sig.minPacketLength = 64;
    sig.maxPacketLength = 1500;
    sig.enabled = false; // Disabled by default as beacons are normal
    return sig;
}

ThreatSignature WiFiDefense::createProbeFloodSignature() {
    ThreatSignature sig;
    sig.name = "Probe Request";
    sig.description = "802.11 probe request frame (potential flood)";
    sig.severity = 4;
    sig.pattern = {0x40, 0x00}; // Probe request frame control
    sig.minPacketLength = 24;
    sig.maxPacketLength = 1500;
    sig.enabled = false; // Disabled by default as probe requests are normal
    return sig;
}