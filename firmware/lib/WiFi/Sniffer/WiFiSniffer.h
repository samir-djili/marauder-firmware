#ifndef WIFI_SNIFFER_H
#define WIFI_SNIFFER_H

#include <Arduino.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include <esp_err.h>
#include <vector>
#include <map>

// WiFi Frame Types
#define WIFI_FRAME_MANAGEMENT   0x00
#define WIFI_FRAME_CONTROL      0x01
#define WIFI_FRAME_DATA         0x02

// Management Frame Subtypes
#define WIFI_SUBTYPE_ASSOC_REQ      0x00
#define WIFI_SUBTYPE_ASSOC_RESP     0x01
#define WIFI_SUBTYPE_REASSOC_REQ    0x02
#define WIFI_SUBTYPE_REASSOC_RESP   0x03
#define WIFI_SUBTYPE_PROBE_REQ      0x04
#define WIFI_SUBTYPE_PROBE_RESP     0x05
#define WIFI_SUBTYPE_BEACON         0x08
#define WIFI_SUBTYPE_ATIM           0x09
#define WIFI_SUBTYPE_DISASSOC       0x0A
#define WIFI_SUBTYPE_AUTH           0x0B
#define WIFI_SUBTYPE_DEAUTH         0x0C

struct AccessPoint {
    String ssid;
    String bssid;
    int32_t rssi;
    uint32_t channel;
    wifi_auth_mode_t encryption;
    bool hidden;
    uint32_t timestamp;
    uint32_t beaconCount;
    uint16_t beaconInterval;
    uint16_t capabilities;
    String vendor;
    std::vector<uint32_t> supportedRates;
};

struct Station {
    String mac;
    int32_t rssi;
    uint32_t channel;
    String associatedAP;
    uint32_t timestamp;
    uint32_t packetCount;
    String vendor;
    bool isConnected;
    uint32_t lastActivity;
};

struct WiFiPacket {
    uint32_t timestamp;
    uint32_t channel;
    int32_t rssi;
    uint8_t frameType;
    uint8_t frameSubtype;
    String sourceMAC;
    String destMAC;
    String bssid;
    uint16_t sequenceNumber;
    std::vector<uint8_t> payload;
};

struct HandshakeData {
    String apBSSID;
    String clientMAC;
    String ssid;
    uint32_t timestamp;
    bool hasMsg1;
    bool hasMsg2;
    bool hasMsg3;
    bool hasMsg4;
    std::vector<uint8_t> msg1;
    std::vector<uint8_t> msg2;
    std::vector<uint8_t> msg3;
    std::vector<uint8_t> msg4;
    uint8_t anonce[32];
    uint8_t snonce[32];
};

class WiFiSniffer {
public:
    WiFiSniffer();
    ~WiFiSniffer();
    
    // Core functionality
    bool begin();
    void update();
    void stop();
    
    // Scanning operations
    void startAPScan(bool showHidden = true);
    void startStationScan();
    void startPacketCapture(uint32_t channel = 0); // 0 = hop all channels
    void startHandshakeCapture(const String& targetBSSID = "");
    void stopAllScans();
    
    // Channel management
    void setChannel(uint32_t channel);
    void enableChannelHopping(bool enabled, uint32_t hopInterval = 250);
    uint32_t getCurrentChannel();
    
    // Data access
    std::vector<AccessPoint>& getAccessPoints();
    std::vector<Station>& getStations();
    std::vector<WiFiPacket>& getCapturedPackets();
    std::vector<HandshakeData>& getHandshakes();
    
    // Filtering
    void setSSIDFilter(const String& ssid);
    void setBSSIDFilter(const String& bssid);
    void setChannelFilter(uint32_t channel);
    void clearFilters();
    
    // Analysis
    uint32_t getPacketCount();
    uint32_t getUniqueAPCount();
    uint32_t getUniqueStationCount();
    String getChannelUtilization();
    String getMostActiveAP();
    
    // Configuration
    void setMaxPackets(uint32_t maxPackets);
    void setMaxAPs(uint32_t maxAPs);
    void setMaxStations(uint32_t maxStations);
    
    // Status
    bool isScanActive();
    bool isChannelHopping();
    String getStatusString();
    
private:
    bool initialized;
    bool apScanActive;
    bool stationScanActive;
    bool packetCaptureActive;
    bool handshakeCaptureActive;
    bool channelHoppingEnabled;
    
    // Channel management
    uint32_t currentChannel;
    uint32_t channelHopInterval;
    unsigned long lastChannelHop;
    std::vector<uint32_t> channelList;
    uint32_t channelIndex;
    
    // Data storage
    std::vector<AccessPoint> accessPoints;
    std::vector<Station> stations;
    std::vector<WiFiPacket> capturedPackets;
    std::vector<HandshakeData> handshakes;
    
    // Filtering
    String ssidFilter;
    String bssidFilter;
    uint32_t channelFilter;
    
    // Configuration
    uint32_t maxPackets;
    uint32_t maxAPs;
    uint32_t maxStations;
    
    // Statistics
    uint32_t totalPacketCount;
    std::map<uint32_t, uint32_t> channelPacketCount;
    
    // Static callbacks
    static void promiscuousCallback(void* buf, wifi_promiscuous_pkt_type_t type);
    
    // Internal methods
    void processPromiscuousPacket(void* buf, wifi_promiscuous_pkt_type_t type);
    void parseManagementFrame(const uint8_t* frame, uint16_t len, int32_t rssi, uint32_t channel);
    void parseBeaconFrame(const uint8_t* frame, uint16_t len, int32_t rssi, uint32_t channel);
    void parseProbeRequest(const uint8_t* frame, uint16_t len, int32_t rssi, uint32_t channel);
    void parseProbeResponse(const uint8_t* frame, uint16_t len, int32_t rssi, uint32_t channel);
    void parseDataFrame(const uint8_t* frame, uint16_t len, int32_t rssi, uint32_t channel);
    void parseHandshakeFrame(const uint8_t* frame, uint16_t len, int32_t rssi, uint32_t channel);
    
    void addOrUpdateAP(const AccessPoint& ap);
    void addOrUpdateStation(const Station& station);
    void addPacket(const WiFiPacket& packet);
    
    bool passesFilters(const String& ssid, const String& bssid, uint32_t channel);
    String macToString(const uint8_t* mac);
    bool parseMAC(const String& macStr, uint8_t* mac);
    String encryptionTypeStr(wifi_auth_mode_t encType);
    String getVendorFromMAC(const uint8_t* mac);
    void hopToNextChannel();
    
    // OUI (Organizationally Unique Identifier) lookup
    String lookupOUI(const uint8_t* mac);
};

#endif // WIFI_SNIFFER_H