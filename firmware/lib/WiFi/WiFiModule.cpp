#include "WiFiModule.h"

WiFiModule::WiFiModule() : initialized(false) {
    sniffer = new WiFiSniffer();
    attack = new WiFiAttack();
    defense = new WiFiDefense();
    persistence = new WiFiPersistence();
}

WiFiModule::~WiFiModule() {
    stop();
    delete sniffer;
    delete attack;
    delete defense;
    delete persistence;
}

bool WiFiModule::begin() {
    if (initialized) {
        return true;
    }
    
    Serial.println("[WiFi] Initializing WiFi module...");
    
    // Initialize all sub-modules
    if (!sniffer->begin()) {
        Serial.println("[WiFi] Failed to initialize sniffer");
        return false;
    }
    
    if (!attack->begin()) {
        Serial.println("[WiFi] Failed to initialize attack module");
        return false;
    }
    
    if (!defense->begin()) {
        Serial.println("[WiFi] Failed to initialize defense module");
        return false;
    }
    
    if (!persistence->begin()) {
        Serial.println("[WiFi] Failed to initialize persistence module");
        return false;
    }
    
    initialized = true;
    Serial.println("[WiFi] All modules initialized successfully");
    return true;
}

void WiFiModule::update() {
    if (!initialized) return;
    
    // Update all sub-modules
    sniffer->update();
    attack->update();
    defense->update();
    persistence->update();
}

void WiFiModule::stop() {
    if (!initialized) return;
    
    Serial.println("[WiFi] Stopping WiFi module...");
    
    // Stop all sub-modules
    sniffer->stop();
    attack->stop();
    defense->stop();
    persistence->stop();
    
    initialized = false;
    Serial.println("[WiFi] Module stopped");
}

WiFiSniffer& WiFiModule::getSniffer() {
    return *sniffer;
}

WiFiAttack& WiFiModule::getAttack() {
    return *attack;
}

WiFiDefense& WiFiModule::getDefense() {
    return *defense;
}

WiFiPersistence& WiFiModule::getPersistence() {
    return *persistence;
}

String WiFiModule::getStatusString() {
    if (!initialized) return "Not initialized";
    
    String status = "WiFi Module Status:\n";
    status += "  Sniffer: " + sniffer->getStatusString() + "\n";
    status += "  Attack: " + attack->getStatusString() + "\n";
    status += "  Defense: " + defense->getStatusString() + "\n";
    status += "  Persistence: " + persistence->getStatusString();
    
    return status;
}

bool WiFiModule::isInitialized() {
    return initialized;
}
