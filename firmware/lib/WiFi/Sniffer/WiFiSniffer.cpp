#include "WiFiSniffer.h"

// Static instance for callbacks
static WiFiSniffer* snifferInstance = nullptr;

WiFiSniffer::WiFiSniffer() :
    initialized(false),
    apScanActive(false),
    stationScanActive(false),
    packetCaptureActive(false),
    handshakeCaptureActive(false),
    channelHoppingEnabled(false),
    currentChannel(1),
    channelHopInterval(250),
    lastChannelHop(0),
    channelIndex(0),
    channelFilter(0),
    maxPackets(10000),
    maxAPs(500),
    maxStations(1000),
    totalPacketCount(0) {
    
    snifferInstance = this;
    
    // Initialize channel list (1-14 for 2.4GHz)
    for (uint32_t i = 1; i <= 14; i++) {
        channelList.push_back(i);
    }
}

WiFiSniffer::~WiFiSniffer() {
    stop();
    snifferInstance = nullptr;
}

bool WiFiSniffer::begin() {
    if (initialized) {
        return true;
    }
    
    Serial.println("[Sniffer] Initializing WiFi sniffer...");
    
    // Initialize WiFi in station mode
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    delay(100);
    
    // Set promiscuous callback
    esp_wifi_set_promiscuous_rx_cb(&promiscuousCallback);
    
    initialized = true;
    Serial.println("[Sniffer] Sniffer initialized successfully");
    return true;
}

void WiFiSniffer::update() {
    if (!initialized) return;
    
    // Handle channel hopping
    if (channelHoppingEnabled && (millis() - lastChannelHop > channelHopInterval)) {
        hopToNextChannel();
        lastChannelHop = millis();
    }
    
    // Process AP scan completion
    if (apScanActive) {
        int scanResult = WiFi.scanComplete();
        if (scanResult >= 0) {
            // Scan completed, process results
            for (int i = 0; i < scanResult; i++) {
                AccessPoint ap;
                ap.ssid = WiFi.SSID(i);
                ap.bssid = WiFi.BSSIDstr(i);
                ap.rssi = WiFi.RSSI(i);
                ap.channel = WiFi.channel(i);
                ap.encryption = WiFi.encryptionType(i);
                ap.hidden = ap.ssid.isEmpty();
                ap.timestamp = millis();
                ap.beaconCount = 0; // Will be updated by promiscuous mode
                ap.beaconInterval = 100; // Default value
                ap.vendor = getVendorFromMAC((uint8_t*)WiFi.BSSID(i));
                
                addOrUpdateAP(ap);
            }
            
            apScanActive = false;
            WiFi.scanDelete();
            Serial.printf("[Sniffer] AP scan completed: %d APs found\n", scanResult);
        }
    }
    
    // Clean up old data if needed
    if (capturedPackets.size() > maxPackets) {
        capturedPackets.erase(capturedPackets.begin(), capturedPackets.begin() + (capturedPackets.size() - maxPackets));
    }
    
    if (accessPoints.size() > maxAPs) {
        accessPoints.erase(accessPoints.begin(), accessPoints.begin() + (accessPoints.size() - maxAPs));
    }
    
    if (stations.size() > maxStations) {
        stations.erase(stations.begin(), stations.begin() + (stations.size() - maxStations));
    }
}

void WiFiSniffer::stop() {
    if (!initialized) return;
    
    Serial.println("[Sniffer] Stopping WiFi sniffer...");
    
    stopAllScans();
    esp_wifi_set_promiscuous_rx_cb(nullptr);
    esp_wifi_set_promiscuous(false);
    
    initialized = false;
    Serial.println("[Sniffer] Sniffer stopped");
}

void WiFiSniffer::startAPScan(bool showHidden) {
    if (!initialized || apScanActive) return;
    
    Serial.println("[Sniffer] Starting AP scan...");
    
    // Switch to station mode for scanning
    WiFi.mode(WIFI_STA);
    delay(100);
    
    accessPoints.clear();
    apScanActive = true;
    
    // Start async scan
    WiFi.scanNetworks(true, showHidden);
}

void WiFiSniffer::startStationScan() {
    if (!initialized) return;
    
    Serial.println("[Sniffer] Starting station scan...");
    stations.clear();
    stationScanActive = true;
    startPacketCapture();
}

void WiFiSniffer::startPacketCapture(uint32_t channel) {
    if (!initialized) return;
    
    if (channel == 0) {
        Serial.println("[Sniffer] Starting packet capture with channel hopping");
        enableChannelHopping(true);
    } else {
        Serial.printf("[Sniffer] Starting packet capture on channel %d\n", channel);
        setChannel(channel);
        enableChannelHopping(false);
    }
    
    // Enable promiscuous mode
    WiFi.mode(WIFI_MODE_NULL);
    delay(100);
    esp_wifi_set_promiscuous(true);
    
    packetCaptureActive = true;
}

void WiFiSniffer::startHandshakeCapture(const String& targetBSSID) {
    if (!initialized) return;
    
    if (targetBSSID.isEmpty()) {
        Serial.println("[Sniffer] Starting handshake capture for all APs");
    } else {
        Serial.printf("[Sniffer] Starting handshake capture for BSSID: %s\n", targetBSSID.c_str());
    }
    
    handshakeCaptureActive = true;
    startPacketCapture();
}

void WiFiSniffer::stopAllScans() {
    if (apScanActive) {
        WiFi.scanDelete();
        apScanActive = false;
        Serial.println("[Sniffer] AP scan stopped");
    }
    
    if (stationScanActive) {
        stationScanActive = false;
        Serial.println("[Sniffer] Station scan stopped");
    }
    
    if (packetCaptureActive) {
        esp_wifi_set_promiscuous(false);
        packetCaptureActive = false;
        Serial.println("[Sniffer] Packet capture stopped");
    }
    
    if (handshakeCaptureActive) {
        handshakeCaptureActive = false;
        Serial.println("[Sniffer] Handshake capture stopped");
    }
    
    enableChannelHopping(false);
    
    // Return to station mode
    WiFi.mode(WIFI_STA);
    delay(100);
}

void WiFiSniffer::setChannel(uint32_t channel) {
    if (!initialized || channel < 1 || channel > 14) return;
    
    currentChannel = channel;
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
}

void WiFiSniffer::enableChannelHopping(bool enabled, uint32_t hopInterval) {
    channelHoppingEnabled = enabled;
    channelHopInterval = hopInterval;
    
    if (enabled) {
        Serial.printf("[Sniffer] Channel hopping enabled (interval: %dms)\n", hopInterval);
    } else {
        Serial.println("[Sniffer] Channel hopping disabled");
    }
}

uint32_t WiFiSniffer::getCurrentChannel() {
    return currentChannel;
}

std::vector<AccessPoint>& WiFiSniffer::getAccessPoints() {
    return accessPoints;
}

std::vector<Station>& WiFiSniffer::getStations() {
    return stations;
}

std::vector<WiFiPacket>& WiFiSniffer::getCapturedPackets() {
    return capturedPackets;
}

std::vector<HandshakeData>& WiFiSniffer::getHandshakes() {
    return handshakes;
}

void WiFiSniffer::setSSIDFilter(const String& ssid) {
    ssidFilter = ssid;
    Serial.printf("[Sniffer] SSID filter set to: %s\n", ssid.c_str());
}

void WiFiSniffer::setBSSIDFilter(const String& bssid) {
    bssidFilter = bssid;
    Serial.printf("[Sniffer] BSSID filter set to: %s\n", bssid.c_str());
}

void WiFiSniffer::setChannelFilter(uint32_t channel) {
    channelFilter = channel;
    Serial.printf("[Sniffer] Channel filter set to: %d\n", channel);
}

void WiFiSniffer::clearFilters() {
    ssidFilter = "";
    bssidFilter = "";
    channelFilter = 0;
    Serial.println("[Sniffer] All filters cleared");
}

uint32_t WiFiSniffer::getPacketCount() {
    return totalPacketCount;
}

uint32_t WiFiSniffer::getUniqueAPCount() {
    return accessPoints.size();
}

uint32_t WiFiSniffer::getUniqueStationCount() {
    return stations.size();
}

String WiFiSniffer::getChannelUtilization() {
    String result = "Channel utilization:\n";
    for (const auto& entry : channelPacketCount) {
        result += "Ch" + String(entry.first) + ": " + String(entry.second) + " pkts\n";
    }
    return result;
}

String WiFiSniffer::getMostActiveAP() {
    if (accessPoints.empty()) return "None";
    
    AccessPoint* mostActive = &accessPoints[0];
    for (auto& ap : accessPoints) {
        if (ap.beaconCount > mostActive->beaconCount) {
            mostActive = &ap;
        }
    }
    
    return mostActive->ssid + " (" + mostActive->bssid + ")";
}

void WiFiSniffer::setMaxPackets(uint32_t maxPackets) {
    this->maxPackets = maxPackets;
}

void WiFiSniffer::setMaxAPs(uint32_t maxAPs) {
    this->maxAPs = maxAPs;
}

void WiFiSniffer::setMaxStations(uint32_t maxStations) {
    this->maxStations = maxStations;
}

bool WiFiSniffer::isScanActive() {
    return apScanActive || stationScanActive || packetCaptureActive || handshakeCaptureActive;
}

bool WiFiSniffer::isChannelHopping() {
    return channelHoppingEnabled;
}

String WiFiSniffer::getStatusString() {
    if (!initialized) return "Not initialized";
    
    String status = "";
    if (apScanActive) status += "AP Scan ";
    if (stationScanActive) status += "Station Scan ";
    if (packetCaptureActive) status += "Packet Capture ";
    if (handshakeCaptureActive) status += "Handshake Capture ";
    if (channelHoppingEnabled) status += "Channel Hopping ";
    
    if (status.isEmpty()) {
        status = "Ready";
    } else {
        status.trim();
        status += " (Ch" + String(currentChannel) + ")";
    }
    
    return status;
}

// Static callback
void WiFiSniffer::promiscuousCallback(void* buf, wifi_promiscuous_pkt_type_t type) {
    if (snifferInstance) {
        snifferInstance->processPromiscuousPacket(buf, type);
    }
}

void WiFiSniffer::processPromiscuousPacket(void* buf, wifi_promiscuous_pkt_type_t type) {
    totalPacketCount++;
    channelPacketCount[currentChannel]++;
    
    wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
    wifi_pkt_rx_ctrl_t* ctrl = &pkt->rx_ctrl;
    
    const uint8_t* frame = pkt->payload;
    uint16_t len = ctrl->sig_len;
    int32_t rssi = ctrl->rssi;
    
    if (len < 24) return; // Minimum 802.11 frame size
    
    // Parse frame control
    uint8_t frameType = (frame[0] & 0x0C) >> 2;
    uint8_t frameSubtype = (frame[0] & 0xF0) >> 4;
    
    // Create packet record if capture is active
    if (packetCaptureActive) {
        WiFiPacket packet;
        packet.timestamp = millis();
        packet.channel = currentChannel;
        packet.rssi = rssi;
        packet.frameType = frameType;
        packet.frameSubtype = frameSubtype;
        packet.sourceMAC = macToString(&frame[10]);
        packet.destMAC = macToString(&frame[4]);
        packet.bssid = macToString(&frame[16]);
        packet.sequenceNumber = (frame[22] | (frame[23] << 8)) >> 4;
        
        // Copy payload
        packet.payload.assign(frame, frame + len);
        
        addPacket(packet);
    }
    
    // Process based on frame type
    switch (frameType) {
        case WIFI_FRAME_MANAGEMENT:
            parseManagementFrame(frame, len, rssi, currentChannel);
            break;
        case WIFI_FRAME_DATA:
            parseDataFrame(frame, len, rssi, currentChannel);
            break;
    }
}

void WiFiSniffer::parseManagementFrame(const uint8_t* frame, uint16_t len, int32_t rssi, uint32_t channel) {
    uint8_t frameSubtype = (frame[0] & 0xF0) >> 4;
    
    switch (frameSubtype) {
        case WIFI_SUBTYPE_BEACON:
            parseBeaconFrame(frame, len, rssi, channel);
            break;
        case WIFI_SUBTYPE_PROBE_REQ:
            parseProbeRequest(frame, len, rssi, channel);
            break;
        case WIFI_SUBTYPE_PROBE_RESP:
            parseProbeResponse(frame, len, rssi, channel);
            break;
        case WIFI_SUBTYPE_AUTH:
        case WIFI_SUBTYPE_ASSOC_REQ:
        case WIFI_SUBTYPE_ASSOC_RESP:
            if (handshakeCaptureActive) {
                parseHandshakeFrame(frame, len, rssi, channel);
            }
            break;
    }
}

void WiFiSniffer::parseBeaconFrame(const uint8_t* frame, uint16_t len, int32_t rssi, uint32_t channel) {
    if (len < 36) return; // Minimum beacon frame size
    
    AccessPoint ap;
    ap.bssid = macToString(&frame[10]);
    ap.rssi = rssi;
    ap.channel = channel;
    ap.timestamp = millis();
    ap.hidden = false;
    
    // Parse beacon interval
    ap.beaconInterval = frame[32] | (frame[33] << 8);
    
    // Parse capabilities
    ap.capabilities = frame[34] | (frame[35] << 8);
    
    // Parse information elements
    uint16_t offset = 36;
    while (offset + 2 < len) {
        uint8_t elementId = frame[offset];
        uint8_t elementLen = frame[offset + 1];
        
        if (offset + 2 + elementLen > len) break;
        
        switch (elementId) {
            case 0: // SSID
                if (elementLen > 0 && elementLen <= 32) {
                    ap.ssid = "";
                    for (int i = 0; i < elementLen; i++) {
                        ap.ssid += (char)frame[offset + 2 + i];
                    }
                } else {
                    ap.hidden = true;
                }
                break;
            case 1: // Supported rates
                ap.supportedRates.clear();
                for (int i = 0; i < elementLen; i++) {
                    ap.supportedRates.push_back(frame[offset + 2 + i] & 0x7F);
                }
                break;
        }
        
        offset += 2 + elementLen;
    }
    
    // Determine encryption type from capabilities
    if (ap.capabilities & 0x10) {
        ap.encryption = WIFI_AUTH_WEP;
    } else {
        ap.encryption = WIFI_AUTH_OPEN;
    }
    
    ap.vendor = getVendorFromMAC(&frame[10]);
    
    if (passesFilters(ap.ssid, ap.bssid, channel)) {
        addOrUpdateAP(ap);
    }
}

void WiFiSniffer::parseProbeRequest(const uint8_t* frame, uint16_t len, int32_t rssi, uint32_t channel) {
    if (!stationScanActive || len < 24) return;
    
    Station station;
    station.mac = macToString(&frame[10]);
    station.rssi = rssi;
    station.channel = channel;
    station.timestamp = millis();
    station.lastActivity = millis();
    station.isConnected = false;
    station.packetCount = 1;
    station.vendor = getVendorFromMAC(&frame[10]);
    
    addOrUpdateStation(station);
}

void WiFiSniffer::parseProbeResponse(const uint8_t* frame, uint16_t len, int32_t rssi, uint32_t channel) {
    // Similar to beacon parsing but for probe responses
    parseBeaconFrame(frame, len, rssi, channel);
}

void WiFiSniffer::parseDataFrame(const uint8_t* frame, uint16_t len, int32_t rssi, uint32_t channel) {
    if (!stationScanActive || len < 24) return;
    
    // Extract source and destination MAC addresses
    String srcMAC = macToString(&frame[10]);
    String dstMAC = macToString(&frame[4]);
    String bssid = macToString(&frame[16]);
    
    // Update station information
    Station station;
    station.mac = srcMAC;
    station.rssi = rssi;
    station.channel = channel;
    station.timestamp = millis();
    station.lastActivity = millis();
    station.associatedAP = bssid;
    station.isConnected = true;
    station.packetCount = 1;
    station.vendor = getVendorFromMAC(&frame[10]);
    
    addOrUpdateStation(station);
}

void WiFiSniffer::parseHandshakeFrame(const uint8_t* frame, uint16_t len, int32_t rssi, uint32_t channel) {
    // Implement WPA handshake parsing logic
    // This is a complex implementation that would parse EAPOL frames
    // For now, we'll add a placeholder
    
    HandshakeData handshake;
    handshake.apBSSID = macToString(&frame[16]);
    handshake.clientMAC = macToString(&frame[10]);
    handshake.timestamp = millis();
    handshake.hasMsg1 = handshake.hasMsg2 = handshake.hasMsg3 = handshake.hasMsg4 = false;
    
    // TODO: Implement full handshake parsing
    handshakes.push_back(handshake);
}

void WiFiSniffer::addOrUpdateAP(const AccessPoint& ap) {
    // Find existing AP
    for (auto& existingAP : accessPoints) {
        if (existingAP.bssid == ap.bssid) {
            // Update existing AP
            existingAP.rssi = ap.rssi;
            existingAP.timestamp = ap.timestamp;
            existingAP.beaconCount++;
            if (!ap.ssid.isEmpty()) {
                existingAP.ssid = ap.ssid;
                existingAP.hidden = false;
            }
            return;
        }
    }
    
    // Add new AP
    accessPoints.push_back(ap);
}

void WiFiSniffer::addOrUpdateStation(const Station& station) {
    // Find existing station
    for (auto& existingStation : stations) {
        if (existingStation.mac == station.mac) {
            // Update existing station
            existingStation.rssi = station.rssi;
            existingStation.lastActivity = station.timestamp;
            existingStation.packetCount++;
            if (!station.associatedAP.isEmpty()) {
                existingStation.associatedAP = station.associatedAP;
                existingStation.isConnected = true;
            }
            return;
        }
    }
    
    // Add new station
    stations.push_back(station);
}

void WiFiSniffer::addPacket(const WiFiPacket& packet) {
    capturedPackets.push_back(packet);
}

bool WiFiSniffer::passesFilters(const String& ssid, const String& bssid, uint32_t channel) {
    if (!ssidFilter.isEmpty() && ssid.indexOf(ssidFilter) == -1) {
        return false;
    }
    
    if (!bssidFilter.isEmpty() && bssid.indexOf(bssidFilter) == -1) {
        return false;
    }
    
    if (channelFilter != 0 && channel != channelFilter) {
        return false;
    }
    
    return true;
}

String WiFiSniffer::macToString(const uint8_t* mac) {
    char macStr[18];
    snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return String(macStr);
}

bool WiFiSniffer::parseMAC(const String& macStr, uint8_t* mac) {
    if (macStr.length() != 17) return false;
    
    for (int i = 0; i < 6; i++) {
        String byte = macStr.substring(i * 3, i * 3 + 2);
        mac[i] = strtol(byte.c_str(), nullptr, 16);
    }
    return true;
}

String WiFiSniffer::encryptionTypeStr(wifi_auth_mode_t encType) {
    switch (encType) {
        case WIFI_AUTH_OPEN: return "Open";
        case WIFI_AUTH_WEP: return "WEP";
        case WIFI_AUTH_WPA_PSK: return "WPA";
        case WIFI_AUTH_WPA2_PSK: return "WPA2";
        case WIFI_AUTH_WPA_WPA2_PSK: return "WPA/WPA2";
        case WIFI_AUTH_WPA2_ENTERPRISE: return "WPA2-ENT";
        case WIFI_AUTH_WPA3_PSK: return "WPA3";
        default: return "Unknown";
    }
}

String WiFiSniffer::getVendorFromMAC(const uint8_t* mac) {
    return lookupOUI(mac);
}

void WiFiSniffer::hopToNextChannel() {
    channelIndex = (channelIndex + 1) % channelList.size();
    setChannel(channelList[channelIndex]);
}

String WiFiSniffer::lookupOUI(const uint8_t* mac) {
    // Create OUI from first 3 bytes
    uint32_t oui = (mac[0] << 16) | (mac[1] << 8) | mac[2];
    
    // Basic vendor lookup (could be expanded with full OUI database)
    switch (oui) {
        case 0x001122: return "Apple";
        case 0x334455: return "Samsung";
        case 0x667788: return "Intel";
        case 0x99AABB: return "Broadcom";
        default: return "Unknown";
    }
}