#include "CommsManager.h"
#include "CryptoManager.h"

void CommsManager::sendEvent(const String& module, const String& event, JsonDocument* data) {
    JsonDocument doc;
    doc["type"] = "event";
    doc["module"] = module;
    doc["event"] = event;
    if (data != nullptr && !data->isNull()) {
        doc["data"] = *data;
    }
    String output;
    serializeJson(doc, output);
    Terminal.println(output);
    Terminal.flush();
}

void CommsManager::sendError(const String& module, const String& errCode, const String& message) {
    JsonDocument doc;
    doc["type"] = "error";
    doc["module"] = module;
    doc["error_code"] = errCode;
    if (message.length() > 0) {
        doc["message"] = message;
    }
    String output;
    serializeJson(doc, output);
    Terminal.println(output);
    Terminal.flush();
}