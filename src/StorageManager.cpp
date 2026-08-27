#include "StorageManager.h"
#include "CryptoManager.h"
#include "SPIFFS.h"
#include <ArduinoJson.h>
#include "Globals.h"
#include <vector>

static byte storageKey[32] = {0};
static bool isStorageKeyLoaded = false;

void deriveStorageKey(const String &pin) {
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 0);
    mbedtls_md_starts(&ctx);
    mbedtls_md_update(&ctx, (const unsigned char *)pin.c_str(), pin.length());
    mbedtls_md_finish(&ctx, storageKey);
    mbedtls_md_free(&ctx);
    isStorageKeyLoaded = true;
}

void clearStorageKey() {
    memset(storageKey, 0, sizeof(storageKey));
    isStorageKeyLoaded = false;
}

bool initStorage() {
    xSemaphoreTake(storageMutex, portMAX_DELAY);
    bool res = SPIFFS.begin(true);
    xSemaphoreGive(storageMutex);
    return res;
}

String hashPin(const String &pin) {
    byte shaResult[32];
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 0);
    mbedtls_md_starts(&ctx);
    mbedtls_md_update(&ctx, (const unsigned char *)pin.c_str(), pin.length());
    mbedtls_md_finish(&ctx, shaResult);
    mbedtls_md_free(&ctx);
    return toHex(shaResult, 32);
}

bool isPinSet() {
    xSemaphoreTake(storageMutex, portMAX_DELAY);
    bool res = SPIFFS.exists("/pin.txt");
    xSemaphoreGive(storageMutex);
    return res;
}

void createPin(const String &pin) {
    String hashedPin = hashPin(pin);
    xSemaphoreTake(storageMutex, portMAX_DELAY);
    File file = SPIFFS.open("/pin.txt", "w");
    if (file) {
        file.print(hashedPin);
        file.close();
    }
    xSemaphoreGive(storageMutex);
}

int getFailedPinAttempts() {
    xSemaphoreTake(storageMutex, portMAX_DELAY);
    if (!SPIFFS.exists("/failures.txt")) {
        xSemaphoreGive(storageMutex);
        return 0;
    }
    File file = SPIFFS.open("/failures.txt", "r");
    if (!file) {
        xSemaphoreGive(storageMutex);
        return 0;
    }
    String val = file.readString();
    file.close();
    xSemaphoreGive(storageMutex);
    return val.toInt();
}

void incrementFailedPinAttempts() {
    int attempts = getFailedPinAttempts() + 1;
    xSemaphoreTake(storageMutex, portMAX_DELAY);
    File file = SPIFFS.open("/failures.txt", "w");
    if (file) {
        file.print(attempts);
        file.close();
    }
    xSemaphoreGive(storageMutex);
}

void resetFailedPinAttempts() {
    xSemaphoreTake(storageMutex, portMAX_DELAY);
    if (SPIFFS.exists("/failures.txt")) {
        SPIFFS.remove("/failures.txt");
    }
    xSemaphoreGive(storageMutex);
}

void factoryResetSystem() {
    xSemaphoreTake(storageMutex, portMAX_DELAY);
    SPIFFS.remove("/passwords.json");
    SPIFFS.remove("/passkeys.json");
    SPIFFS.remove("/totp.json");
    SPIFFS.remove("/pin.txt");
    SPIFFS.remove("/failures.txt");
    xSemaphoreGive(storageMutex);
}

bool deletePin() {
    if (isPinSet()) {
        factoryResetSystem();
        return true;
    }
    return false;
}

bool verifyPin(const String &pin) {
    xSemaphoreTake(storageMutex, portMAX_DELAY);
    File file = SPIFFS.open("/pin.txt", "r");
    if (!file) {
        xSemaphoreGive(storageMutex);
        return false;
    }
    String storedHash = file.readString();
    file.close();
    xSemaphoreGive(storageMutex);
    
    if (storedHash == hashPin(pin)) {
        resetFailedPinAttempts();
        return true;
    } else {
        incrementFailedPinAttempts();
        int totalFailures = getFailedPinAttempts();
        if (totalFailures >= 10) {
            Terminal.println("[SECURITY] CRITICAL:MAX_ATTEMPTS_EXCEEDED_WIPING_DEVICE");
            Terminal.flush();
            factoryResetSystem();
            ESP.restart();
        } else {
            Terminal.print("[SECURITY] WARN:PIN_BAD_ATTEMPT:");
            Terminal.printf("%d/10\n", totalFailures);
        }
        return false;
    }
}

bool isPasswordExists(const String &name) {
    xSemaphoreTake(storageMutex, portMAX_DELAY);
    if (!SPIFFS.exists("/passwords.json")) {
        xSemaphoreGive(storageMutex);
        return false;
    }
    File file = SPIFFS.open("/passwords.json", "r");
    if (!file) {
        xSemaphoreGive(storageMutex);
        return false;
    }
    JsonDocument doc;
    DeserializationError error = deserializeJson(doc, file);
    file.close();
    xSemaphoreGive(storageMutex);
    return !error && doc[name].is<JsonVariant>();
}

void savePassword(const String &name, const String &password) {
    if (!isStorageKeyLoaded) { Terminal.println("[ERR] CODE:STORAGE_KEY_LOCKED"); return; }
    if (name.length() > 32) { Terminal.println("[ERR] CODE:NAME_TOO_LONG"); return; }
    if (password.length() > 4000) { Terminal.println("[ERR] CODE:PASS_TOO_LONG"); return; }
    if (isPasswordExists(name)) { Terminal.println("[ERR] CODE:ALREADY_EXISTS"); return; }

    xSemaphoreTake(storageMutex, portMAX_DELAY);
    JsonDocument doc;
    if (SPIFFS.exists("/passwords.json")) {
        File file = SPIFFS.open("/passwords.json", "r");
        if (file) {
            deserializeJson(doc, file);
            file.close();
        }
    }

    JsonObject obj = doc.as<JsonObject>();
    if (obj.size() >= 1000) {
        xSemaphoreGive(storageMutex);
        Terminal.println("[ERR] CODE:MAX_LIMIT_REACHED");
        return;
    }

    String encryptedValue = encryptStoragePayload(password, storageKey);
    if (encryptedValue == "") {
        xSemaphoreGive(storageMutex);
        Terminal.println("[ERR] CODE:ENC_FAILED");
        return;
    }

    doc[name] = encryptedValue;
    File file = SPIFFS.open("/passwords.json", "w");
    if (!file) {
        xSemaphoreGive(storageMutex);
        Terminal.println("[ERR] CODE:FILE_CREATE_FAILED");
        return;
    }
    serializeJson(doc, file);
    file.close();
    xSemaphoreGive(storageMutex);
    Terminal.println("[PASS] OUT:SAVED");
}

String getPasswordFromStorage(const String &name) {
    if (!isStorageKeyLoaded) return "";
    xSemaphoreTake(storageMutex, portMAX_DELAY);
    File file = SPIFFS.open("/passwords.json", "r");
    if (!file) {
        xSemaphoreGive(storageMutex);
        return "";
    }
    JsonDocument doc;
    deserializeJson(doc, file);
    file.close();
    xSemaphoreGive(storageMutex);
    
    if (!doc[name].is<JsonVariant>()) return "";
    String encryptedValue = doc[name].as<String>();
    return decryptStoragePayload(encryptedValue, storageKey);
}

bool deletePassword(const String &name) {
    xSemaphoreTake(storageMutex, portMAX_DELAY);
    if (!SPIFFS.exists("/passwords.json")) {
        xSemaphoreGive(storageMutex);
        return false;
    }
    File file = SPIFFS.open("/passwords.json", "r");
    if (!file) {
        xSemaphoreGive(storageMutex);
        return false;
    }
    JsonDocument doc;
    deserializeJson(doc, file);
    file.close();
    
    if (!doc[name].is<JsonVariant>()) {
        xSemaphoreGive(storageMutex);
        return false;
    }
    doc.remove(name);

    file = SPIFFS.open("/passwords.json", "w");
    if (!file) {
        xSemaphoreGive(storageMutex);
        return false;
    }
    serializeJson(doc, file);
    file.close();
    xSemaphoreGive(storageMutex);
    return true;
}

void listPasswords() {
    xSemaphoreTake(storageMutex, portMAX_DELAY);
    if (!SPIFFS.exists("/passwords.json")) {
        xSemaphoreGive(storageMutex);
        Terminal.println("[PASS] OUT:EMPTY");
        return;
    }
    File file = SPIFFS.open("/passwords.json", "r");
    if (!file) {
        xSemaphoreGive(storageMutex);
        Terminal.println("[ERR] CODE:READ_FAILED");
        return;
    }
    JsonDocument doc;
    deserializeJson(doc, file);
    file.close();
    xSemaphoreGive(storageMutex);

    JsonObject obj = doc.as<JsonObject>();
    for (JsonPair pair : obj) {
        Terminal.print("[PASS] ITEM:");
        Terminal.println(pair.key().c_str());
    }
    Terminal.println("[PASS] OUT:LIST_END");
}

void showStorageInfo() {
    xSemaphoreTake(storageMutex, portMAX_DELAY);
    size_t total = SPIFFS.totalBytes();
    size_t used = SPIFFS.usedBytes();
    size_t free = total - used;
    float usage = ((float)used / total) * 100;
    
    int count = 0; size_t chars = 0; float avg = 0;
    if (SPIFFS.exists("/passwords.json")) {
        File file = SPIFFS.open("/passwords.json", "r");
        JsonDocument doc;
        if (!deserializeJson(doc, file)) {
            JsonObject obj = doc.as<JsonObject>();
            for (JsonPair pair : obj) {
                count++;
                chars += String(pair.value().as<const char *>()).length();
            }
            if (count > 0) avg = (float)chars / count;
        }
        file.close();
    }
    xSemaphoreGive(storageMutex);
    Terminal.printf("[STORAGE] STATS:%d,%d,%d,%.2f,%d,%d,%.2f\n", total, used, free, usage, count, chars, avg);
}

void clearAllStoredPasswords() {
    xSemaphoreTake(storageMutex, portMAX_DELAY);
    if (SPIFFS.exists("/passwords.json")) {
        SPIFFS.remove("/passwords.json");
    }
    if (SPIFFS.exists("/passkeys.json")) {
        SPIFFS.remove("/passkeys.json");
    }
    xSemaphoreGive(storageMutex);
    clearStorageKey();
    Serial.println("[STORAGE] VAULT PURGE COMPLETE");
}

bool isPasskeyExists(const String &credentialIdHex) {
    xSemaphoreTake(storageMutex, portMAX_DELAY);
    if (!SPIFFS.exists("/passkeys.json")) {
        xSemaphoreGive(storageMutex);
        return false;
    }
    File file = SPIFFS.open("/passkeys.json", "r");
    if (!file) {
        xSemaphoreGive(storageMutex);
        return false;
    }
    JsonDocument doc;
    DeserializationError error = deserializeJson(doc, file);
    file.close();
    xSemaphoreGive(storageMutex);
    return !error && doc[credentialIdHex].is<JsonVariant>();
}

bool savePasskeyRecord(const String &credentialIdHex, const String &rpId, const String &userIdHex, const String &userName, const String &privateKeyHex, int algId) {
    
    // 1. Generate the hardware-bound key
    byte fidoKey[32];
    getFidoHardwareKey(fidoKey);

    xSemaphoreTake(storageMutex, portMAX_DELAY);
    JsonDocument doc;
    if (SPIFFS.exists("/passkeys.json")) {
        File file = SPIFFS.open("/passkeys.json", "r");
        if (file) {
            deserializeJson(doc, file);
            file.close();
        }
    }

    JsonObject record = doc[credentialIdHex].to<JsonObject>();
    record["rpId"] = rpId;

    JsonDocument payloadDoc;
    payloadDoc["uId"] = userIdHex;
    payloadDoc["uName"] = userName;
    payloadDoc["pKey"] = privateKeyHex;

    String rawPayload;
    serializeJson(payloadDoc, rawPayload);

    // 2. Use fidoKey instead of storageKey for encryption
    String encryptedPayload = encryptStoragePayload(rawPayload, fidoKey);
    
    if (encryptedPayload == "") {
        xSemaphoreGive(storageMutex);
        Terminal.println("[ERR] CODE:PASSKEY_ENC_FAILED");
        return false;
    }
    
    record["payload"] = encryptedPayload;
    record["alg"] = algId;
    File file = SPIFFS.open("/passkeys.json", "w");
    if (!file) {
        xSemaphoreGive(storageMutex);
        Terminal.println("[ERR] CODE:FILE_CREATE_FAILED");
        return false;
    }
    
    serializeJson(doc, file);
    file.close();
    xSemaphoreGive(storageMutex);
    Terminal.println("[PASS] OUT:PASSKEY_SAVED");
    return true;
}

bool getPasskeyRecord(const String &credentialIdHex, String &rpIdOut, 
                      String &userIdHexOut, String &userNameOut, 
                      String &privateKeyHexOut, int &algId) {
    
    // 1. Generate the hardware-bound key
    byte fidoKey[32];
    getFidoHardwareKey(fidoKey);

    xSemaphoreTake(storageMutex, portMAX_DELAY);
    if (!SPIFFS.exists("/passkeys.json")) {
        xSemaphoreGive(storageMutex);
        return false;
    }
    File file = SPIFFS.open("/passkeys.json", "r");
    if (!file) {
        xSemaphoreGive(storageMutex);
        return false;
    }
    JsonDocument doc;
    DeserializationError error = deserializeJson(doc, file);
    file.close();
    xSemaphoreGive(storageMutex);

    if (error || !doc[credentialIdHex].is<JsonVariant>()) return false;

    JsonObject record = doc[credentialIdHex].as<JsonObject>();
    rpIdOut = record["rpId"].as<String>();
    String encryptedPayload = record["payload"].as<String>();

    // 2. Use fidoKey instead of storageKey for decryption
    String decryptedPayload = decryptStoragePayload(encryptedPayload, fidoKey);
    
    if (decryptedPayload == "") return false;

    JsonDocument payloadDoc;
    DeserializationError payloadError = deserializeJson(payloadDoc, decryptedPayload);
    if (payloadError) return false;

    userIdHexOut = payloadDoc["uId"].as<String>();
    userNameOut = payloadDoc["uName"].as<String>();
    privateKeyHexOut = payloadDoc["pKey"].as<String>();
    algId = payloadDoc["alg"] | -7;
    return true;
}

String findCredentialIdByRpAndUser(const String &rpId, const String &userIdHex) {
    xSemaphoreTake(storageMutex, portMAX_DELAY);
    if (!SPIFFS.exists("/passkeys.json")) {
        xSemaphoreGive(storageMutex);
        return "";
    }
    File file = SPIFFS.open("/passkeys.json", "r");
    if (!file) {
        xSemaphoreGive(storageMutex);
        return "";
    }
    JsonDocument doc;
    DeserializationError error = deserializeJson(doc, file);
    file.close();
    xSemaphoreGive(storageMutex);
    
    if (error) return "";

    JsonObject obj = doc.as<JsonObject>();
    for (JsonPair pair : obj) {
        String recordRpId = pair.value()["rpId"].as<String>();
        if (recordRpId.equals(rpId)) {
            String encryptedPayload = pair.value()["payload"].as<String>();
            String decryptedPayload = decryptStoragePayload(encryptedPayload, storageKey);
            
            if (decryptedPayload != "") {
                JsonDocument payloadDoc;
                if (!deserializeJson(payloadDoc, decryptedPayload)) {
                    String recordUserId = payloadDoc["uId"].as<String>();
                    if (userIdHex == "" || recordUserId.equals(userIdHex)) {
                        return String(pair.key().c_str()); 
                    }
                }
            }
        }
    }
    return "";
}

size_t getBinaryCredentialId(const String &rpId, const String &userIdHex, uint8_t* outBuffer, size_t maxOutLen) {
    String credentialIdHex = findCredentialIdByRpAndUser(rpId, userIdHex);
    if (credentialIdHex.length() == 0) {
        return 0; 
    }
    size_t binIdLen = credentialIdHex.length() / 2;
    if (binIdLen > maxOutLen) {
        return 0; 
    }
    fromHex(credentialIdHex, outBuffer, binIdLen);
    return binIdLen;
}

void listFidoWebsites() {
    xSemaphoreTake(storageMutex, portMAX_DELAY);
    if (!SPIFFS.exists("/passkeys.json")) {
        xSemaphoreGive(storageMutex);
        Terminal.println("[FIDO2] OUT:EMPTY");
        return;
    }
    File file = SPIFFS.open("/passkeys.json", "r");
    if (!file) {
        xSemaphoreGive(storageMutex);
        Terminal.println("[ERR] CODE:READ_FAILED");
        return;
    }
    JsonDocument doc;
    DeserializationError error = deserializeJson(doc, file);
    file.close();
    xSemaphoreGive(storageMutex);
    
    if (error) {
        Terminal.println("[ERR] CODE:JSON_PARSE_FAILED");
        return;
    }

    JsonObject obj = doc.as<JsonObject>();
    std::vector<String> rpIds;

    for (JsonPair pair : obj) {
        JsonObject rec = pair.value().as<JsonObject>();
        if (rec["rpId"].is<const char*>()) {
            String rpId = rec["rpId"].as<String>();
            bool exists = false;
            for (const String &s : rpIds) {
                if (s == rpId) { exists = true; break; }
            }
            if (!exists) {
                rpIds.push_back(rpId);
            }
        }
    }

    if (rpIds.empty()) {
        Terminal.println("[FIDO2] OUT:EMPTY");
        return;
    }

    for (const String &rp : rpIds) {
        Terminal.print("[FIDO2] ITEM:");
        Terminal.println(rp.c_str());
    }
    Terminal.println("[FIDO2] OUT:LIST_END");
}

bool deleteFidoWebsite(const String &rpId) {
    xSemaphoreTake(storageMutex, portMAX_DELAY);
    if (!SPIFFS.exists("/passkeys.json")) {
        xSemaphoreGive(storageMutex);
        return false;
    }
    File file = SPIFFS.open("/passkeys.json", "r");
    if (!file) {
        xSemaphoreGive(storageMutex);
        return false;
    }
    JsonDocument doc;
    DeserializationError error = deserializeJson(doc, file);
    file.close();
    
    if (error) {
        xSemaphoreGive(storageMutex);
        return false;
    }

    JsonObject obj = doc.as<JsonObject>();
    std::vector<String> keysToRemove;

    for (JsonPair pair : obj) {
        JsonObject record = pair.value().as<JsonObject>();
        if (record["rpId"].is<const char*>()) {
            String recRpId = record["rpId"].as<String>();
            if (recRpId.equals(rpId)) {
                keysToRemove.push_back(String(pair.key().c_str()));
            }
        }
    }

    if (keysToRemove.empty()) {
        xSemaphoreGive(storageMutex);
        return false;
    }

    for (const String &key : keysToRemove) {
        doc.remove(key);
    }

    file = SPIFFS.open("/passkeys.json", "w");
    if (!file) {
        xSemaphoreGive(storageMutex);
        return false;
    }
    serializeJson(doc, file);
    file.close();
    xSemaphoreGive(storageMutex);
    return true;
}

String getFidoWebsiteInfo(const String &rpId) {
    if (!isStorageKeyLoaded) return "";
    xSemaphoreTake(storageMutex, portMAX_DELAY);
    if (!SPIFFS.exists("/passkeys.json")) {
        xSemaphoreGive(storageMutex);
        return "";
    }
    File file = SPIFFS.open("/passkeys.json", "r");
    if (!file) {
        xSemaphoreGive(storageMutex);
        return "";
    }

    JsonDocument doc;
    DeserializationError error = deserializeJson(doc, file);
    file.close();
    xSemaphoreGive(storageMutex);
    
    if (error) return "";

    JsonObject obj = doc.as<JsonObject>();
    String result = "";

    for (JsonPair pair : obj) {
        JsonObject record = pair.value().as<JsonObject>();
        if (record["rpId"].is<const char*>() && record["rpId"].as<String>().equals(rpId)) {
            String encryptedPayload = record["payload"].as<String>();
            String decryptedPayload = decryptStoragePayload(encryptedPayload, storageKey);
            if (decryptedPayload != "") {
                JsonDocument payloadDoc;
                if (!deserializeJson(payloadDoc, decryptedPayload)) {
                    String userName = payloadDoc["uName"].as<String>();
                    result += "[FIDO2] USER:" + (userName.length() > 0 ? userName : "N/A") + " | CRED_ID:" + String(pair.key().c_str()) + "\n";
                }
            }
        }
    }
    return result;
}

void saveTotpSecret(const String &name, const String &secret) {
    if (!isStorageKeyLoaded) return;
    
    xSemaphoreTake(storageMutex, portMAX_DELAY);
    JsonDocument doc;
    if (SPIFFS.exists("/totp.json")) {
        File file = SPIFFS.open("/totp.json", "r");
        if (file) {
            deserializeJson(doc, file);
            file.close();
        }
    }
    
    String encryptedValue = encryptStoragePayload(secret, storageKey);
    if (encryptedValue == "") {
        xSemaphoreGive(storageMutex);
        return;
    }
    
    doc[name] = encryptedValue;
    File file = SPIFFS.open("/totp.json", "w");
    if (!file) {
        xSemaphoreGive(storageMutex);
        return;
    }
    
    serializeJson(doc, file);
    file.close();
    xSemaphoreGive(storageMutex);
    Terminal.println("[TOTP] OUT:SAVED");
}

String getTotpSecret(const String &name) {
    if (!isStorageKeyLoaded) return "";
    
    xSemaphoreTake(storageMutex, portMAX_DELAY);
    File file = SPIFFS.open("/totp.json", "r");
    if (!file) {
        xSemaphoreGive(storageMutex);
        return "";
    }
    
    JsonDocument doc;
    deserializeJson(doc, file);
    file.close();
    xSemaphoreGive(storageMutex);
    
    if (!doc[name].is<JsonVariant>()) return "";
    
    String encryptedValue = doc[name].as<String>();
    return decryptStoragePayload(encryptedValue, storageKey);
}