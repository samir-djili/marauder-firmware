# ESP32 Marauder WiFi Module Architecture

## Overview
Complete modular WiFi implementation for ESP32 Marauder with full attack, defense, sniffing, and persistence capabilities.

## Directory Structure
```
lib/WiFi/
├── WiFiModule.h/cpp          # Main coordinator module
├── Sniffer/
│   ├── WiFiSniffer.h         # Packet sniffing and reconnaissance
│   └── WiFiSniffer.cpp
├── Attack/
│   ├── WiFiAttack.h          # WiFi attack implementations
│   └── WiFiAttack.cpp
├── Defense/
│   ├── WiFiDefense.h         # Threat detection and defense
│   └── WiFiDefense.cpp
└── Persistence/
    ├── WiFiPersistence.h     # Data capture and storage
    └── WiFiPersistence.cpp
```

## Core Features

### WiFiSniffer (Reconnaissance)
- **Promiscuous Mode**: Complete 802.11 frame capture and parsing
- **AP Detection**: Automatic access point discovery with detailed information
- **Station Tracking**: Client device monitoring and behavior analysis
- **Handshake Capture**: WPA/WPA2 handshake detection and logging
- **Channel Hopping**: Multi-channel monitoring with configurable intervals
- **OUI Lookup**: Vendor identification from MAC addresses
- **Beacon Analysis**: SSID extraction, encryption detection, channel mapping
- **Probe Request Monitoring**: Device tracking through probe requests

### WiFiAttack (Offensive)
- **Deauthentication Attack**: Targeted and broadcast deauth frame injection
- **Beacon Spam**: Multiple fake AP generation with configurable SSIDs
- **Evil Twin**: Rogue AP creation with captive portal integration
- **Captive Portal**: Complete web server with credential harvesting
- **Frame Injection**: Raw 802.11 frame construction and transmission
- **Multi-target Support**: Simultaneous attacks on multiple targets
- **Custom Templates**: Configurable captive portal HTML templates

### WiFiDefense (Protective)
- **Threat Detection**: Real-time analysis of wireless attacks
- **Deauth Detection**: Abnormal deauthentication frame monitoring
- **Evil Twin Detection**: Duplicate SSID/suspicious AP identification
- **Beacon Spam Detection**: High-rate beacon frame analysis
- **Rogue AP Detection**: Unauthorized access point identification
- **Active Defense**: Counter-attack capabilities and threat mitigation
- **Threat Signatures**: Customizable attack pattern matching
- **Whitelist/Blacklist**: MAC address filtering and management

### WiFiPersistence (Data Management)
- **PCAP Capture**: Standard packet capture with Wireshark compatibility
- **Multiple Formats**: PCAP, PCAPNG, JSON, and CSV export options
- **Storage Management**: SPIFFS and SD card support with auto-selection
- **Session Tracking**: Capture session management and statistics
- **Auto-rotation**: File size-based capture rotation
- **Configuration Persistence**: Settings and wordlist management
- **Export Utilities**: Format conversion and data extraction

## Hardware Requirements
- **ESP32-S3**: Primary microcontroller with WiFi capabilities
- **Display**: TFT screen for user interface (TFT_eSPI)
- **Storage**: SD card recommended for large captures
- **NFC**: Optional PN532 module for additional attack vectors

## Dependencies
```ini
lib_deps = 
    bodmer/TFT_eSPI
    adafruit/Adafruit PN532
    bblanchon/ArduinoJson
    mathieucarbou/AsyncTCP
    mathieucarbou/ESPAsyncWebServer
    DNSServer
    ESP32 BLE Arduino
```

## Usage Examples

### Basic Initialization
```cpp
#include "WiFi/WiFiModule.h"

WiFiModule wifi;

void setup() {
    wifi.begin();
}

void loop() {
    wifi.update();
}
```

### Packet Sniffing
```cpp
// Start sniffing on channel 6
wifi.getSniffer().startSniffing(6);

// Start channel hopping mode
wifi.getSniffer().startChannelHopping(500); // 500ms intervals

// Get discovered access points
auto aps = wifi.getSniffer().getAccessPoints();
```

### Attack Operations
```cpp
// Deauth attack on specific target
String targetBSSID = "AA:BB:CC:DD:EE:FF";
wifi.getAttack().executeDeauthAttack(targetBSSID);

// Start beacon spam with custom SSIDs
std::vector<String> fakeSSIDs = {"FreeWiFi", "Starbucks", "Hotel_Guest"};
wifi.getAttack().executeBeaconSpam(fakeSSIDs);

// Launch evil twin with captive portal
wifi.getAttack().executeEvilTwin("Target_Network", "password123");
```

### Defense Monitoring
```cpp
// Enable all defense mechanisms
wifi.getDefense().enableDeauthDetection(true);
wifi.getDefense().enableEvilTwinDetection(true);
wifi.getDefense().enableBeaconSpamDetection(true);

// Start threat monitoring
wifi.getDefense().startThreatMonitoring();

// Get threat report
String report = wifi.getDefense().getThreatReport();
```

### Data Persistence
```cpp
// Start packet capture
wifi.getPersistence().startCapture("scan_results.pcap");

// Capture individual packets (in sniffer callback)
wifi.getPersistence().capturePacket(packetData, length, rssi, timestamp, channel);

// Stop capture and save
wifi.getPersistence().stopCapture();

// Export data in different formats
wifi.getPersistence().exportCapture("scan.pcap", "scan.json", EXPORT_JSON);
```

## Integration with Main Firmware

### SystemManager Integration
```cpp
// In SystemManager.cpp
#include "WiFi/WiFiModule.h"

class SystemManager {
private:
    WiFiModule* wifiModule;
    
public:
    void initializeModules() {
        wifiModule = new WiFiModule();
        wifiModule->begin();
    }
    
    void updateModules() {
        wifiModule->update();
    }
    
    WiFiModule& getWiFi() { return *wifiModule; }
};
```

### Display Integration
```cpp
// In main.cpp or display handler
void displayWiFiStatus() {
    String status = systemManager.getWiFi().getStatusString();
    display.println(status);
    
    // Show sniffer results
    auto aps = systemManager.getWiFi().getSniffer().getAccessPoints();
    for (const auto& ap : aps) {
        display.printf("%s [%s] Ch:%d RSSI:%d\n", 
                      ap.ssid.c_str(), ap.bssid.c_str(), 
                      ap.channel, ap.rssi);
    }
}
```

## Security Considerations
- All attack features are for authorized penetration testing only
- Ensure compliance with local wireless regulations
- Implement proper access controls in production deployments
- Consider legal implications of active defense mechanisms

## Performance Notes
- Promiscuous mode packet processing can be CPU intensive
- Large PCAP files may require SD card storage
- Channel hopping intervals should be balanced with capture completeness
- Buffer management is critical for high packet rate scenarios

## Future Enhancements
- Machine learning-based anomaly detection
- Bluetooth integration for hybrid attacks
- Advanced cryptographic analysis
- Cloud-based threat intelligence integration
- Mobile app interface for remote control