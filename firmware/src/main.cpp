#include <Arduino.h>
#include "config.h"
#include "Core/SystemManager.h"
#include "Display/DisplayManager.h"
#include "WiFi/WiFiModule.h"
#include "NFC/NFCModule.h"
#include "Bluetooth/BluetoothModule.h"
#include "Defense/DefenseModule.h"

// Global system objects
SystemManager systemManager;
DisplayManager displayManager;
WiFiModule wifiModule;
NFCModule nfcModule;
BluetoothModule bluetoothModule;
DefenseModule defenseModule;

void setup() {
    Serial.begin(115200);
    delay(1000);
    
    Serial.println("========================================");
    Serial.println(DEVICE_NAME " v" FIRMWARE_VERSION);
    Serial.println("========================================");
    
    // Initialize core system
    if (!systemManager.begin()) {
        Serial.println("FATAL: System initialization failed");
        while(1) delay(1000);
    }
    
    // Initialize display
    if (!displayManager.begin()) {
        Serial.println("FATAL: Display initialization failed");
        while(1) delay(1000);
    }
    
    // Initialize modules
    wifiModule.begin();
    nfcModule.begin();
    bluetoothModule.begin();
    defenseModule.begin();
    
    Serial.println("System initialization complete");
    displayManager.showBootScreen();
}

void loop() {
    // Main system loop
    systemManager.update();
    displayManager.update();
    
    // Module updates
    wifiModule.update();
    nfcModule.update();
    bluetoothModule.update();
    defenseModule.update();
    
    delay(10); // Small delay to prevent watchdog issues
}