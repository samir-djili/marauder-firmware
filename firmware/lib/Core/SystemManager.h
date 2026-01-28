#ifndef SYSTEM_MANAGER_H
#define SYSTEM_MANAGER_H

#include <Arduino.h>

class SystemManager {
private:
    bool initialized;
    unsigned long bootTime;
    
public:
    SystemManager();
    
    bool begin();
    void update();
    
    // System info
    String getSystemInfo();
    unsigned long getUptime();
    void reboot();
    
    // Power management
    void enterDeepSleep(uint64_t sleepTime);
    void enterLightSleep(uint64_t sleepTime);
    
    // System status
    bool isInitialized() { return initialized; }
    float getCPUUsage();
    size_t getFreeHeap();
};

#endif