#ifndef COMMS_MANAGER_H
#define COMMS_MANAGER_H

#include <Arduino.h>
#include <ArduinoJson.h>

class CommsManager {
public:
    static void sendEvent(const String& module, const String& event, JsonDocument* data = nullptr);
    static void sendError(const String& module, const String& errCode, const String& message = "");
};

#endif