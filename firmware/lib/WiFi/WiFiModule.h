#ifndef WIFI_MODULE_H
#define WIFI_MODULE_H

#include <Arduino.h>
#include "Sniffer/WiFiSniffer.h"
#include "Attack/WiFiAttack.h"
#include "Defense/WiFiDefense.h"
#include "Persistence/WiFiPersistence.h"

class WiFiModule {
public:
    WiFiModule();
    ~WiFiModule();
    
    // Core functionality
    bool begin();
    void update();
    void stop();
    
    // Sub-module access
    WiFiSniffer& getSniffer();
    WiFiAttack& getAttack();
    WiFiDefense& getDefense();
    WiFiPersistence& getPersistence();
    
    // Status
    String getStatusString();
    bool isInitialized();

private:
    bool initialized;
    
    // Sub-modules
    WiFiSniffer* sniffer;
    WiFiAttack* attack;
    WiFiDefense* defense;
    WiFiPersistence* persistence;
};

#endif // WIFI_MODULE_H