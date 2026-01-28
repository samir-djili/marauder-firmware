#include "WiFiModule.h"

// Simplified compilation test to verify basic structure
void testBasicCompilation() {
    WiFiModule wifi;
    
    // Test basic initialization
    bool initialized = wifi.begin();
    
    // Test sub-module access (just check they exist)
    auto& sniffer = wifi.getSniffer();
    auto& attack = wifi.getAttack();  
    auto& defense = wifi.getDefense();
    auto& persistence = wifi.getPersistence();
    
    // Test basic status methods
    String status = wifi.getStatusString();
    bool isInit = wifi.isInitialized();
    
    // Test basic sniffer methods
    sniffer.setChannel(6);
    String snifferStatus = sniffer.getStatusString();
    
    // Test basic attack methods (without parameters that cause issues)
    String attackStatus = attack.getStatusString();
    
    // Test basic defense methods  
    String defenseStatus = defense.getStatusString();
    
    // Test basic persistence methods
    String persistStatus = persistence.getStatusString();
    
    // Update all modules
    wifi.update();
    
    // Stop everything
    wifi.stop();
}