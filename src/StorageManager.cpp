#include "StorageManager.h"
#include "CryptoManager.h"
#include "CommsManager.h"
#include "SPIFFS.h"
#include <ArduinoJson.h>
#include "Globals.h"
#include <vector>
#include "mbedtls/pkcs5.h"
#include "mbedtls/aes.h"
#include <nvs_flash.h>
#include <nvs.h>

static byte storageKey[32] = {0};
static bool isStorageKeyLoaded = false;

static String readSpiffsString(File &file) {
    uint16_t len;
    if (file.read((uint8_t*)&len, 2) != 2) return "";
    if (len == 0) return "";
    char* buf = (char*)malloc(len + 1);
    if (!buf) return "";
    file.read((uint8_t*)buf, len);
    buf[len] = '\0';
    String res(buf);
    free(buf);
    return res;
}

void deriveStorageKey(const String &pin) {
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);

    const unsigned char salt[] = "VAULT_STORAGE_SALT";
    
    mbedtls_pkcs5_pbkdf2_hmac(
        &ctx, 
        (const unsigned char *)pin.c_str(), 
        pin.length(), 
        salt, 
        sizeof(salt) - 1, 
        10000, 
        32, 
        storageKey
    );
                              
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
    SPIFFS.remove("/passkeys.bin");
    SPIFFS.remove("/passkeys.tmp");
    SPIFFS.remove("/totp.json");
    SPIFFS.remove("/pin.txt");
    SPIFFS.remove("/failures.txt");
    SPIFFS.remove("/crypto_alg.txt");
    SPIFFS.remove("/largeblob.bin");
    xSemaphoreGive(storageMutex);
}

// --- CTAP 2.1 authenticatorLargeBlobs backing store ---
// The serialized large-blob array is opaque to the authenticator: each
// entry inside it is already encrypted by the platform under the owning
// credential's largeBlobKey, and the whole array carries its own trailing
// integrity hash. We therefore just persist and return the raw bytes
// as-is; FIDO2Manager is responsible for fragmenting/reassembling and
// verifying the integrity hash.
bool getLargeBlobArray(uint8_t** outData, size_t &outLen) {
    *outData = nullptr;
    outLen = 0;

    xSemaphoreTake(storageMutex, portMAX_DELAY);
    if (!SPIFFS.exists("/largeblob.bin")) {
        xSemaphoreGive(storageMutex);
        return false;
    }
    File file = SPIFFS.open("/largeblob.bin", "r");
    if (!file) {
        xSemaphoreGive(storageMutex);
        return false;
    }

    size_t sz = file.size();
    uint8_t* buf = (uint8_t*)malloc(sz > 0 ? sz : 1);
    if (!buf) {
        file.close();
        xSemaphoreGive(storageMutex);
        return false;
    }
    file.read(buf, sz);
    file.close();
    xSemaphoreGive(storageMutex);

    *outData = buf;
    outLen = sz;
    return true;
}

bool setLargeBlobArray(const uint8_t* data, size_t len) {
    xSemaphoreTake(storageMutex, portMAX_DELAY);
    File file = SPIFFS.open("/largeblob.bin", "w");
    if (!file) {
        xSemaphoreGive(storageMutex);
        return false;
    }
    size_t written = (len > 0) ? file.write(data, len) : 0;
    file.close();
    xSemaphoreGive(storageMutex);
    return written == len;
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
            CommsManager::sendError("SECURITY", "MAX_ATTEMPTS_EXCEEDED", "Maximum PIN attempts reached. Device wiped.");
            factoryResetSystem();
            ESP.restart();
        } else {
            CommsManager::sendError("SECURITY", "BAD_PIN_ATTEMPT", String(totalFailures) + "/10 attempts used.");
        }
        return false;
    }
}

bool isPasswordExists(const String &website, const String &login) {
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
    return !error && doc[website].is<JsonObject>() && doc[website][login].is<JsonVariant>();
}

bool savePassword(const String &website, const String &login, const String &password) {
    if (!isStorageKeyLoaded) { CommsManager::sendError("PASS", "KEY_LOCKED", "Storage key is not unlocked."); return false; }
    if (website.length() > 64 || login.length() > 64) { CommsManager::sendError("PASS", "IDENTIFIER_TOO_LONG", "Website or login parameter is too long."); return false; }
    if (password.length() > 4000) { CommsManager::sendError("PASS", "PASS_TOO_LONG", "Password length exceeds limits."); return false; }
    if (isPasswordExists(website, login)) { CommsManager::sendError("PASS", "ALREADY_EXISTS", "Credential record already exists."); return false; }

    xSemaphoreTake(storageMutex, portMAX_DELAY);
    JsonDocument doc;
    if (SPIFFS.exists("/passwords.json")) {
        File file = SPIFFS.open("/passwords.json", "r");
        if (file) {
            deserializeJson(doc, file);
            file.close();
        }
    }

    int totalLogins = 0;
    for (JsonPair sitePair : doc.as<JsonObject>()) {
        totalLogins += sitePair.value().as<JsonObject>().size();
    }
    if (totalLogins >= 1000) {
        xSemaphoreGive(storageMutex);
        CommsManager::sendError("PASS", "MAX_LIMIT_REACHED", "Vault capacity reached.");
        return false;
    }

    String encryptedValue = encryptStoragePayload(password, storageKey);
    if (encryptedValue == "") {
        xSemaphoreGive(storageMutex);
        CommsManager::sendError("PASS", "ENC_FAILED", "Failed to encrypt password payload.");
        return false;
    }

    JsonObject siteObj = doc[website].is<JsonObject>() ? doc[website].as<JsonObject>() : doc[website].to<JsonObject>();
    siteObj[login] = encryptedValue;

    File file = SPIFFS.open("/passwords.json", "w");
    if (!file) {
        xSemaphoreGive(storageMutex);
        CommsManager::sendError("PASS", "FILE_CREATE_FAILED", "Unable to open vault storage file.");
        return false;
    }
    serializeJson(doc, file);
    file.close();
    xSemaphoreGive(storageMutex);
    return true;
}

String getPasswordFromStorage(const String &website, const String &login) {
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

    if (!doc[website].is<JsonObject>() || !doc[website][login].is<JsonVariant>()) return "";
    String encryptedValue = doc[website][login].as<String>();
    return decryptStoragePayload(encryptedValue, storageKey);
}

bool deletePassword(const String &website, const String &login) {
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

    if (!doc[website].is<JsonObject>() || !doc[website][login].is<JsonVariant>()) {
        xSemaphoreGive(storageMutex);
        return false;
    }
    
    doc[website].as<JsonObject>().remove(login);
    if (doc[website].as<JsonObject>().size() == 0) {
        doc.remove(website);
    }

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
        JsonDocument data;
        data["items"].to<JsonArray>();
        CommsManager::sendEvent("PASS", "LIST", &data);
        return;
    }
    File file = SPIFFS.open("/passwords.json", "r");
    if (!file) {
        xSemaphoreGive(storageMutex);
        CommsManager::sendError("PASS", "READ_FAILED", "Failed to open passwords file.");
        return;
    }
    JsonDocument doc;
    DeserializationError error = deserializeJson(doc, file);
    file.close();
    xSemaphoreGive(storageMutex);

    if (error) {
        CommsManager::sendError("PASS", "READ_FAILED", "Failed to parse password JSON payload.");
        return;
    }

    std::vector<String> websites;
    std::vector<String> logins;
    std::vector<String> passwords;

    for (JsonPair sitePair : doc.as<JsonObject>()) {
        String website = sitePair.key().c_str();
        JsonObject lgs = sitePair.value().as<JsonObject>();
        for (JsonPair loginPair : lgs) {
            websites.push_back(website);
            logins.push_back(loginPair.key().c_str());
            passwords.push_back(decryptStoragePayload(loginPair.value().as<String>(), storageKey));
        }
    }

    JsonDocument responseData;
    JsonArray itemsArray = responseData["items"].to<JsonArray>();

    for (size_t i = 0; i < websites.size(); i++) {
        String pwd = passwords[i];
        bool isWeak = false;

        if (pwd.length() < 12) {
            isWeak = true;
        } else {
            bool hasNum = false, hasUpper = false, hasLower = false, hasSpec = false;
            for (int c = 0; c < pwd.length(); c++) {
                char ch = pwd[c];
                if (isdigit(ch)) hasNum = true;
                else if (isupper(ch)) hasUpper = true;
                else if (islower(ch)) hasLower = true;
                else hasSpec = true;
            }
            if (!hasNum || !hasUpper || !hasLower || !hasSpec) isWeak = true;
        }

        int freq = 0;
        for (size_t j = 0; j < passwords.size(); j++) {
            if (passwords[j] == pwd) freq++;
        }
        if (freq > 1) isWeak = true;

        JsonObject item = itemsArray.add<JsonObject>();
        item["website"] = websites[i];
        item["login"] = logins[i];
        item["status"] = isWeak ? "WEAK" : "OK";
    }

    for (size_t i = 0; i < passwords.size(); i++) {
        if (passwords[i].length() > 0) {
            memset(const_cast<char*>(passwords[i].c_str()), 0, passwords[i].length());
            passwords[i] = "";
        }
    }

    CommsManager::sendEvent("PASS", "LIST", &responseData);
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
            for (JsonPair sitePair : doc.as<JsonObject>()) {
                JsonObject lgs = sitePair.value().as<JsonObject>();
                for (JsonPair loginPair : lgs) {
                    count++;
                    chars += String(loginPair.value().as<const char *>()).length();
                }
            }
            if (count > 0) avg = (float)chars / count;
        }
        file.close();
    }

    int passkeyCount = 0;
    if (SPIFFS.exists("/passkeys.bin")) {
        File file = SPIFFS.open("/passkeys.bin", "r");
        if (file) {
            while (file.available()) {
                uint8_t status;
                if (file.read(&status, 1) != 1) break;
                file.seek(4, SeekCur);

                uint16_t len;
                if (file.read((uint8_t*)&len, 2) == 2) file.seek(len, SeekCur);
                if (file.read((uint8_t*)&len, 2) == 2) file.seek(len, SeekCur);
                if (file.read((uint8_t*)&len, 2) == 2) file.seek(len, SeekCur);

                if (status == 1) {
                    passkeyCount++;
                }
            }
            file.close();
        }
    }
    xSemaphoreGive(storageMutex);
    
    JsonDocument data;
    data["total_bytes"] = total;
    data["used_bytes"] = used;
    data["free_bytes"] = free;
    data["usage_percent"] = usage;
    data["passwords_count"] = count;
    data["avg_login_length"] = avg;
    data["passkeys_count"] = passkeyCount;

    CommsManager::sendEvent("STORAGE", "STATS", &data);
}

void clearAllStoredPasswords() {
    xSemaphoreTake(storageMutex, portMAX_DELAY);
    if (SPIFFS.exists("/passwords.json")) {
        SPIFFS.remove("/passwords.json");
    }
    if (SPIFFS.exists("/passkeys.json")) {
        SPIFFS.remove("/passkeys.json");
    }
    if (SPIFFS.exists("/passkeys.bin")) {
        SPIFFS.remove("/passkeys.bin");
    }
    xSemaphoreGive(storageMutex);
    clearStorageKey();
    CommsManager::sendEvent("STORAGE", "PURGE_COMPLETE");
}

bool isPasskeyExists(const String &credentialIdHex) {
    xSemaphoreTake(storageMutex, portMAX_DELAY);
    File file = SPIFFS.open("/passkeys.bin", "r");
    if (!file) {
        xSemaphoreGive(storageMutex);
        return false;
    }
    bool found = false;
    while (file.available()) {
        uint8_t status;
        if (file.read(&status, 1) != 1) break;
        file.seek(4, SeekCur);
        String cid = readSpiffsString(file);
        uint16_t len;
        file.read((uint8_t*)&len, 2);
        file.seek(len, SeekCur);
        file.read((uint8_t*)&len, 2);
        file.seek(len, SeekCur);
        if (status == 1 && cid == credentialIdHex) {
            found = true;
            break;
        }
    }
    file.close();
    xSemaphoreGive(storageMutex);
    return found;
}

// --- CTAP 2.1: credProtect + largeBlobKey support for resident credentials ---
// Extended records append two fields to the encrypted payload:
//   userIdHex \n userName \n privateKeyHex \n credProtect \n largeBlobKeyHex
// Records written before this feature existed simply lack the trailing two
// fields; getPasskeyRecord (extended overload) falls back to credProtect=1
// and an empty largeBlobKeyHex when they're absent, so old credentials keep
// working unchanged.
bool savePasskeyRecord(const String &credentialIdHex, const String &rpId, const String &userIdHex, const String &userName, const String &privateKeyHex, int algId, int credProtect, const String &largeBlobKeyHex) {
    byte fidoKey[32];
    getFidoHardwareKey(fidoKey);
    String rawPayload = userIdHex + "\n" + userName + "\n" + privateKeyHex + "\n" + String(credProtect) + "\n" + largeBlobKeyHex;
    String encryptedPayload = encryptStoragePayload(rawPayload, fidoKey);
    
    if (encryptedPayload == "") {
        CommsManager::sendError("FIDO2", "PASSKEY_ENC_FAILED", "Failed to encrypt passkey.");
        return false;
    }

    xSemaphoreTake(storageMutex, portMAX_DELAY);
    File file = SPIFFS.open("/passkeys.bin", "a");
    if (!file) {
        xSemaphoreGive(storageMutex);
        CommsManager::sendError("FIDO2", "FILE_CREATE_FAILED", "Failed to open passkeys file.");
        return false;
    }

    uint8_t status = 1;
    file.write(&status, 1);
    file.write((uint8_t*)&algId, 4);
    
    uint16_t len = credentialIdHex.length();
    file.write((uint8_t*)&len, 2);
    file.write((uint8_t*)credentialIdHex.c_str(), len);
    
    len = rpId.length();
    file.write((uint8_t*)&len, 2);
    file.write((uint8_t*)rpId.c_str(), len);
    
    len = encryptedPayload.length();
    file.write((uint8_t*)&len, 2);
    file.write((uint8_t*)encryptedPayload.c_str(), len);
    
    file.close();
    xSemaphoreGive(storageMutex);
    CommsManager::sendEvent("FIDO2", "PASSKEY_SAVED");
    return true;
}

// Backward-compatible wrapper for call sites that don't care about
// credProtect / largeBlobKey: stores the CTAP2.0 defaults (credProtect=1,
// no largeBlobKey).
bool savePasskeyRecord(const String &credentialIdHex, const String &rpId, const String &userIdHex, const String &userName, const String &privateKeyHex, int algId) {
    return savePasskeyRecord(credentialIdHex, rpId, userIdHex, userName, privateKeyHex, algId, 1, "");
}

bool getPasskeyRecord(const String &credentialIdHex, String &rpIdOut, String &userIdHexOut, String &userNameOut, String &privateKeyHexOut, int &algId, int &credProtectOut, String &largeBlobKeyHexOut) {
    byte fidoKey[32];
    getFidoHardwareKey(fidoKey);

    xSemaphoreTake(storageMutex, portMAX_DELAY);
    File file = SPIFFS.open("/passkeys.bin", "r");
    if (!file) {
        xSemaphoreGive(storageMutex);
        return false;
    }

    bool found = false;
    String encryptedPayload = "";

    while (file.available()) {
        uint8_t status;
        if (file.read(&status, 1) != 1) break;
        int currentAlgId;
        file.read((uint8_t*)&currentAlgId, 4);
        String cid = readSpiffsString(file);
        String rp = readSpiffsString(file);
        
        uint16_t payLen;
        file.read((uint8_t*)&payLen, 2);
        
        if (status == 1 && cid == credentialIdHex) {
            char* payBuf = (char*)malloc(payLen + 1);
            if (payBuf) {
                file.read((uint8_t*)payBuf, payLen);
                payBuf[payLen] = '\0';
                encryptedPayload = String(payBuf);
                free(payBuf);
            }
            rpIdOut = rp;
            algId = currentAlgId;
            found = true;
            break;
        } else {
            file.seek(payLen, SeekCur);
        }
    }
    file.close();
    xSemaphoreGive(storageMutex);

    if (!found || encryptedPayload == "") return false;

    String decryptedPayload = decryptStoragePayload(encryptedPayload, fidoKey);
    if (decryptedPayload == "") return false;

    int firstNewline = decryptedPayload.indexOf('\n');
    int secondNewline = decryptedPayload.indexOf('\n', firstNewline + 1);
    if (firstNewline == -1 || secondNewline == -1) return false;

    userIdHexOut = decryptedPayload.substring(0, firstNewline);
    userNameOut = decryptedPayload.substring(firstNewline + 1, secondNewline);

    // Fields beyond privateKeyHex are optional (older records won't have
    // them): default credProtect to 1 (userVerificationOptional) and
    // largeBlobKeyHex to empty when absent.
    int thirdNewline = decryptedPayload.indexOf('\n', secondNewline + 1);
    int fourthNewline = (thirdNewline == -1) ? -1 : decryptedPayload.indexOf('\n', thirdNewline + 1);

    credProtectOut = 1;
    largeBlobKeyHexOut = "";

    if (thirdNewline == -1) {
        privateKeyHexOut = decryptedPayload.substring(secondNewline + 1);
    } else {
        privateKeyHexOut = decryptedPayload.substring(secondNewline + 1, thirdNewline);
        if (fourthNewline == -1) {
            String cp = decryptedPayload.substring(thirdNewline + 1);
            if (cp.length() > 0) credProtectOut = cp.toInt();
        } else {
            String cp = decryptedPayload.substring(thirdNewline + 1, fourthNewline);
            if (cp.length() > 0) credProtectOut = cp.toInt();
            largeBlobKeyHexOut = decryptedPayload.substring(fourthNewline + 1);
        }
    }

    return true;
}

// Backward-compatible wrapper for call sites that don't need
// credProtect / largeBlobKey.
bool getPasskeyRecord(const String &credentialIdHex, String &rpIdOut, String &userIdHexOut, String &userNameOut, String &privateKeyHexOut, int &algId) {
    int dummyCredProtect;
    String dummyLargeBlobKeyHex;
    return getPasskeyRecord(credentialIdHex, rpIdOut, userIdHexOut, userNameOut, privateKeyHexOut, algId, dummyCredProtect, dummyLargeBlobKeyHex);
}

String findCredentialIdByRpAndUser(const String &rpId, const String &userIdHex) {
    xSemaphoreTake(storageMutex, portMAX_DELAY);
    File file = SPIFFS.open("/passkeys.bin", "r");
    if (!file) {
        xSemaphoreGive(storageMutex);
        return "";
    }
    
    String foundCid = "";
    while (file.available()) {
        uint8_t status;
        if (file.read(&status, 1) != 1) break;
        file.seek(4, SeekCur);
        String cid = readSpiffsString(file);
        String rp = readSpiffsString(file);
        
        uint16_t payLen;
        file.read((uint8_t*)&payLen, 2);
        
        if (status == 1 && rp == rpId) {
            char* payBuf = (char*)malloc(payLen + 1);
            if (payBuf) {
                file.read((uint8_t*)payBuf, payLen);
                payBuf[payLen] = '\0';
                String encryptedPayload(payBuf);
                free(payBuf);
                
                String decryptedPayload = decryptStoragePayload(encryptedPayload, storageKey);
                if (decryptedPayload != "") {
                    int firstNewline = decryptedPayload.indexOf('\n');
                    if (firstNewline != -1) {
                        String recUserId = decryptedPayload.substring(0, firstNewline);
                        if (userIdHex == "" || recUserId == userIdHex) {
                            foundCid = cid;
                            break;
                        }
                    }
                }
            }
        } else {
            file.seek(payLen, SeekCur);
        }
    }
    file.close();
    xSemaphoreGive(storageMutex);
    return foundCid;
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
    File file = SPIFFS.open("/passkeys.bin", "r");
    if (!file) {
        xSemaphoreGive(storageMutex);
        JsonDocument data;
        data["websites"].to<JsonArray>();
        CommsManager::sendEvent("FIDO2", "LIST", &data);
        return;
    }

    std::vector<String> rpIds;
    while (file.available()) {
        uint8_t status;
        if (file.read(&status, 1) != 1) break;
        file.seek(4, SeekCur);
        
        uint16_t len;
        file.read((uint8_t*)&len, 2);
        file.seek(len, SeekCur);
        
        String rp = readSpiffsString(file);
        
        file.read((uint8_t*)&len, 2);
        file.seek(len, SeekCur);
        
        if (status == 1) {
            bool exists = false;
            for (const String &s : rpIds) {
                if (s == rp) { exists = true; break; }
            }
            if (!exists) rpIds.push_back(rp);
        }
    }
    file.close();
    xSemaphoreGive(storageMutex);

    JsonDocument responseData;
    JsonArray websitesArray = responseData["websites"].to<JsonArray>();
    for (const String &rp : rpIds) {
        websitesArray.add(rp);
    }

    CommsManager::sendEvent("FIDO2", "LIST", &responseData);
}

bool deleteFidoWebsite(const String &rpId) {
    xSemaphoreTake(storageMutex, portMAX_DELAY);
    File file = SPIFFS.open("/passkeys.bin", "r");
    if (!file) {
        xSemaphoreGive(storageMutex);
        return false;
    }

    File tempFile = SPIFFS.open("/passkeys.tmp", "w");
    if (!tempFile) {
        file.close();
        xSemaphoreGive(storageMutex);
        return false;
    }

    bool deletedAny = false;

    while (file.available()) {
        uint8_t status;
        if (file.read(&status, 1) != 1) break;
        int algId;
        file.read((uint8_t*)&algId, 4);
        
        String cid = readSpiffsString(file);
        String rp = readSpiffsString(file);
        String pay = readSpiffsString(file);
        
        if (status == 1 && rp == rpId) {
            deletedAny = true;
        } else if (status == 1) {
            tempFile.write(&status, 1);
            tempFile.write((uint8_t*)&algId, 4);
            
            uint16_t len = cid.length();
            tempFile.write((uint8_t*)&len, 2);
            tempFile.write((uint8_t*)cid.c_str(), len);
            
            len = rp.length();
            tempFile.write((uint8_t*)&len, 2);
            tempFile.write((uint8_t*)rp.c_str(), len);
            
            len = pay.length();
            tempFile.write((uint8_t*)&len, 2);
            tempFile.write((uint8_t*)pay.c_str(), len);
        }
    }
    
    file.close();
    tempFile.close();

    if (deletedAny) {
        SPIFFS.remove("/passkeys.bin");
        SPIFFS.rename("/passkeys.tmp", "/passkeys.bin");
    } else {
        SPIFFS.remove("/passkeys.tmp");
    }

    xSemaphoreGive(storageMutex);
    return deletedAny;
}

String getFidoWebsiteInfo(const String &rpId) {
    if (!isStorageKeyLoaded) return "";
    xSemaphoreTake(storageMutex, portMAX_DELAY);
    File file = SPIFFS.open("/passkeys.bin", "r");
    if (!file) {
        xSemaphoreGive(storageMutex);
        return "";
    }

    String result = "";
    while (file.available()) {
        uint8_t status;
        if (file.read(&status, 1) != 1) break;
        file.seek(4, SeekCur);
        
        String cid = readSpiffsString(file);
        String rp = readSpiffsString(file);
        
        uint16_t payLen;
        file.read((uint8_t*)&payLen, 2);
        
        if (status == 1 && rp == rpId) {
            char* payBuf = (char*)malloc(payLen + 1);
            if (payBuf) {
                file.read((uint8_t*)payBuf, payLen);
                payBuf[payLen] = '\0';
                String encryptedPayload(payBuf);
                free(payBuf);
                
                String decryptedPayload = decryptStoragePayload(encryptedPayload, storageKey);
                if (decryptedPayload != "") {
                    int firstNewline = decryptedPayload.indexOf('\n');
                    int secondNewline = decryptedPayload.indexOf('\n', firstNewline + 1);
                    if (firstNewline != -1 && secondNewline != -1) {
                        String userName = decryptedPayload.substring(firstNewline + 1, secondNewline);
                        result += userName + " | CRED_ID:" + cid + "\n";
                    }
                }
            }
        } else {
            file.seek(payLen, SeekCur);
        }
    }
    file.close();
    xSemaphoreGive(storageMutex);
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
        CommsManager::sendError("TOTP", "ENC_FAILED", "Failed to encrypt secret.");
        return;
    }

    doc[name] = encryptedValue;
    File file = SPIFFS.open("/totp.json", "w");
    if (!file) {
        xSemaphoreGive(storageMutex);
        CommsManager::sendError("TOTP", "FILE_WRITE_FAILED", "Unable to save secret.");
        return;
    }

    serializeJson(doc, file);
    file.close();
    xSemaphoreGive(storageMutex);
    CommsManager::sendEvent("TOTP", "SAVED");
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

void saveDefaultCryptoAlg(int algId) {
    xSemaphoreTake(storageMutex, portMAX_DELAY);
    File file = SPIFFS.open("/crypto_alg.txt", "w");
    if (file) {
        file.print(algId);
        file.close();
    }
    xSemaphoreGive(storageMutex);
}

int loadDefaultCryptoAlg() {
    xSemaphoreTake(storageMutex, portMAX_DELAY);
    if (!SPIFFS.exists("/crypto_alg.txt")) {
        xSemaphoreGive(storageMutex);
        return -7;
    }
    File file = SPIFFS.open("/crypto_alg.txt", "r");
    if (!file) {
        xSemaphoreGive(storageMutex);
        return -7;
    }
    String val = file.readString();
    file.close();
    xSemaphoreGive(storageMutex);
    return val.toInt();
}

void handleTotpGetAll(uint32_t currentEpoch) {
    if (!isStorageKeyLoaded || !SPIFFS.exists("/totp.json")) {
        JsonDocument data;
        data["codes"].to<JsonObject>();
        CommsManager::sendEvent("TOTP", "CODES", &data);
        return;
    }

    File file = SPIFFS.open("/totp.json", "r");
    JsonDocument doc;
    JsonDocument responseData;
    JsonObject codesObj = responseData["codes"].to<JsonObject>();

    if (deserializeJson(doc, file) == DeserializationError::Ok) {
        JsonObject obj = doc.as<JsonObject>();
        for (JsonPair pair : obj) {
            const char* accountName = pair.key().c_str();
            String encryptedValue = pair.value().as<String>();
            
            String decryptedSecret = decryptStoragePayload(encryptedValue, storageKey);
            if (decryptedSecret != "") {
                String codeStr = generateTOTP(decryptedSecret, currentEpoch);
                codesObj[accountName] = codeStr;
            }
        }
    }
    file.close();
    CommsManager::sendEvent("TOTP", "CODES", &responseData);
}

bool deleteTotpSecret(const String &name) {
    xSemaphoreTake(storageMutex, portMAX_DELAY);
    if (!SPIFFS.exists("/totp.json")) {
        xSemaphoreGive(storageMutex);
        return false;
    }
    
    File file = SPIFFS.open("/totp.json", "r");
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

    file = SPIFFS.open("/totp.json", "w");
    if (!file) {
        xSemaphoreGive(storageMutex);
        return false;
    }
    
    serializeJson(doc, file);
    file.close();
    xSemaphoreGive(storageMutex);
    
    return true;
}

void secureWipe(String &str) {
    if (str.length() > 0) {
        memset(const_cast<char*>(str.c_str()), 0, str.length());
        str = "";
    }
}

bool isFidoPinSet() {
    xSemaphoreTake(storageMutex, portMAX_DELAY);
    bool res = SPIFFS.exists("/fido_pin.txt");
    xSemaphoreGive(storageMutex);
    return res;
}

void createFidoPin(const String &pin) {
    String hashedPin = hashPin(pin);
    xSemaphoreTake(storageMutex, portMAX_DELAY);
    File file = SPIFFS.open("/fido_pin.txt", "w");
    if (file) {
        file.print(hashedPin);
        file.close();
    }
    xSemaphoreGive(storageMutex);
}

int getFailedFidoPinAttempts() {
    xSemaphoreTake(storageMutex, portMAX_DELAY);
    if (!SPIFFS.exists("/fido_fail.txt")) {
        xSemaphoreGive(storageMutex);
        return 0;
    }
    File file = SPIFFS.open("/fido_fail.txt", "r");
    if (!file) {
        xSemaphoreGive(storageMutex);
        return 0;
    }
    String val = file.readString();
    file.close();
    xSemaphoreGive(storageMutex);
    return val.toInt();
}

void resetFido2System() {
    xSemaphoreTake(storageMutex, portMAX_DELAY);
    if (SPIFFS.exists("/passkeys.json")) SPIFFS.remove("/passkeys.json");
    if (SPIFFS.exists("/passkeys.bin")) SPIFFS.remove("/passkeys.bin");
    if (SPIFFS.exists("/passkeys.tmp")) SPIFFS.remove("/passkeys.tmp");
    if (SPIFFS.exists("/fido_pin.txt")) SPIFFS.remove("/fido_pin.txt");
    if (SPIFFS.exists("/fido_fail.txt")) SPIFFS.remove("/fido_fail.txt");
    if (SPIFFS.exists("/fido_uv_fail.txt")) SPIFFS.remove("/fido_uv_fail.txt");
    if (SPIFFS.exists("/fido_force_pin.txt")) SPIFFS.remove("/fido_force_pin.txt");
    if (SPIFFS.exists("/fido_min_pin.txt")) SPIFFS.remove("/fido_min_pin.txt");
    if (SPIFFS.exists("/largeblob.bin")) SPIFFS.remove("/largeblob.bin");
    rotateStatelessMasterSecret();
    xSemaphoreGive(storageMutex);
    CommsManager::sendEvent("FIDO2", "RESET_COMPLETE");
}

std::vector<String> findAllCredentialsByRp(const String &rpId) {
    std::vector<String> results;
    xSemaphoreTake(storageMutex, portMAX_DELAY);
    File file = SPIFFS.open("/passkeys.bin", "r");
    if (!file) {
        xSemaphoreGive(storageMutex);
        return results;
    }
    while (file.available()) {
        uint8_t status;
        if (file.read(&status, 1) != 1) break;
        file.seek(4, SeekCur);
        String cid = readSpiffsString(file);
        String rp = readSpiffsString(file);
        uint16_t payLen;
        file.read((uint8_t*)&payLen, 2);
        if (status == 1 && rp == rpId) {
            results.push_back(cid);
        }
        file.seek(payLen, SeekCur);
    }
    file.close();
    xSemaphoreGive(storageMutex);
    return results;
}

std::vector<String> getAllStoredCredentialIds() {
    std::vector<String> results;
    xSemaphoreTake(storageMutex, portMAX_DELAY);
    File file = SPIFFS.open("/passkeys.bin", "r");
    if (!file) {
        xSemaphoreGive(storageMutex);
        return results;
    }
    while (file.available()) {
        uint8_t status;
        if (file.read(&status, 1) != 1) break;
        file.seek(4, SeekCur);
        String cid = readSpiffsString(file);
        readSpiffsString(file); // skip rp
        uint16_t payLen;
        file.read((uint8_t*)&payLen, 2);
        file.seek(payLen, SeekCur);
        if (status == 1) {
            results.push_back(cid);
        }
    }
    file.close();
    xSemaphoreGive(storageMutex);
    return results;
}

std::vector<String> getAllStoredRpIds() {
    std::vector<String> results;
    xSemaphoreTake(storageMutex, portMAX_DELAY);
    File file = SPIFFS.open("/passkeys.bin", "r");
    if (!file) {
        xSemaphoreGive(storageMutex);
        return results;
    }
    while (file.available()) {
        uint8_t status;
        if (file.read(&status, 1) != 1) break;
        file.seek(4, SeekCur);
        readSpiffsString(file); // skip cid
        String rp = readSpiffsString(file);
        uint16_t payLen;
        file.read((uint8_t*)&payLen, 2);
        file.seek(payLen, SeekCur);
        if (status == 1) {
            bool exists = false;
            for (const String &s : results) {
                if (s == rp) { exists = true; break; }
            }
            if (!exists) results.push_back(rp);
        }
    }
    file.close();
    xSemaphoreGive(storageMutex);
    return results;
}

bool deletePasskeyRecord(const String &credentialIdHex) {
    xSemaphoreTake(storageMutex, portMAX_DELAY);
    File file = SPIFFS.open("/passkeys.bin", "r");
    if (!file) {
        xSemaphoreGive(storageMutex);
        return false;
    }

    File tempFile = SPIFFS.open("/passkeys.tmp", "w");
    if (!tempFile) {
        file.close();
        xSemaphoreGive(storageMutex);
        return false;
    }

    bool deleted = false;
    while (file.available()) {
        uint8_t status;
        if (file.read(&status, 1) != 1) break;
        int algId;
        file.read((uint8_t*)&algId, 4);
        
        String cid = readSpiffsString(file);
        String rp = readSpiffsString(file);
        String pay = readSpiffsString(file);
        
        if (status == 1 && cid == credentialIdHex) {
            deleted = true;
        } else if (status == 1) {
            tempFile.write(&status, 1);
            tempFile.write((uint8_t*)&algId, 4);
            
            uint16_t len = cid.length();
            tempFile.write((uint8_t*)&len, 2);
            tempFile.write((uint8_t*)cid.c_str(), len);
            
            len = rp.length();
            tempFile.write((uint8_t*)&len, 2);
            tempFile.write((uint8_t*)rp.c_str(), len);
            
            len = pay.length();
            tempFile.write((uint8_t*)&len, 2);
            tempFile.write((uint8_t*)pay.c_str(), len);
        }
    }
    
    file.close();
    tempFile.close();

    if (deleted) {
        SPIFFS.remove("/passkeys.bin");
        SPIFFS.rename("/passkeys.tmp", "/passkeys.bin");
    } else {
        SPIFFS.remove("/passkeys.tmp");
    }

    xSemaphoreGive(storageMutex);
    return deleted;
}

static void getStatelessMasterKeys(uint8_t* aesKey, uint8_t* hmacKey) {
    uint8_t secret[32];
    getStatelessMasterSecret(secret);

    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 0);

    mbedtls_md_starts(&ctx);
    mbedtls_md_update(&ctx, secret, 32);
    mbedtls_md_update(&ctx, (const uint8_t*)"STATELESS_AES_KEY_SALT", 22);
    mbedtls_md_finish(&ctx, aesKey);

    mbedtls_md_starts(&ctx);
    mbedtls_md_update(&ctx, secret, 32);
    mbedtls_md_update(&ctx, (const uint8_t*)"STATELESS_HMAC_KEY_SALT", 23);
    mbedtls_md_finish(&ctx, hmacKey);

    mbedtls_md_free(&ctx);
}

bool wrapStatelessCredential(const String &rpId, const uint8_t *userId, size_t userIdLen,
                             const String &userName, const String &privateKeyHex, int algId,
                             uint8_t *outCredId, size_t &outCredIdLen) {
    uint8_t aesKey[32], hmacKey[32];
    getStatelessMasterKeys(aesKey, hmacKey);

    // Compute RP ID Hash
    uint8_t rpHash[32];
    mbedtls_md_context_t md_ctx;
    mbedtls_md_init(&md_ctx);
    mbedtls_md_setup(&md_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 0);
    mbedtls_md_starts(&md_ctx);
    mbedtls_md_update(&md_ctx, (const uint8_t*)rpId.c_str(), rpId.length());
    mbedtls_md_finish(&md_ctx, rpHash);
    mbedtls_md_free(&md_ctx);

    size_t privLen = privateKeyHex.length() / 2;
    size_t payloadBaseLen = 108 + privLen;
    size_t paddedLen = (payloadBaseLen + 15) & ~15; // Round up to nearest 16 for CBC padding

    uint8_t* plaintext = (uint8_t*)calloc(1, paddedLen);
    if (!plaintext) return false;

    // Magic header
    plaintext[0] = 'S'; plaintext[1] = 'T'; plaintext[2] = 'A'; plaintext[3] = 'T'; 

    int32_t netAlg = (int32_t)algId;
    plaintext[4] = (netAlg >> 24) & 0xFF;
    plaintext[5] = (netAlg >> 16) & 0xFF;
    plaintext[6] = (netAlg >> 8) & 0xFF;
    plaintext[7] = netAlg & 0xFF;

    memcpy(&plaintext[8], rpHash, 32);

    plaintext[40] = (uint8_t)(userIdLen > 32 ? 32 : userIdLen);
    if (userId && userIdLen > 0) {
        memcpy(&plaintext[41], userId, plaintext[40]);
    }

    uint8_t uNameLen = (uint8_t)(userName.length() > 32 ? 32 : userName.length());
    plaintext[73] = uNameLen;
    memcpy(&plaintext[74], userName.c_str(), uNameLen);

    plaintext[106] = (privLen >> 8) & 0xFF;
    plaintext[107] = privLen & 0xFF;
    fromHex(privateKeyHex, &plaintext[108], privLen);

    // IV and Encryption
    uint8_t iv[16], iv_copy[16];
    esp_fill_random(iv, 16);
    memcpy(iv_copy, iv, 16);

    uint8_t* encrypted = (uint8_t*)malloc(paddedLen);
    if (!encrypted) { free(plaintext); return false; }

    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_enc(&aes, aesKey, 256);
    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, paddedLen, iv_copy, plaintext, encrypted);
    mbedtls_aes_free(&aes);

    // Compute HMAC-SHA256 tag
    uint8_t hmac[32];
    mbedtls_md_init(&md_ctx);
    mbedtls_md_setup(&md_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
    mbedtls_md_hmac_starts(&md_ctx, hmacKey, 32);
    mbedtls_md_hmac_update(&md_ctx, iv, 16);
    mbedtls_md_hmac_update(&md_ctx, encrypted, paddedLen);
    mbedtls_md_hmac_finish(&md_ctx, hmac);
    mbedtls_md_free(&md_ctx);

    // Assemble Credential ID: IV (16) + Encrypted (paddedLen) + HMAC (32)
    memcpy(&outCredId[0], iv, 16);
    memcpy(&outCredId[16], encrypted, paddedLen);
    memcpy(&outCredId[16 + paddedLen], hmac, 32);
    outCredIdLen = 16 + paddedLen + 32;

    free(plaintext);
    free(encrypted);
    return true;
}

bool unwrapStatelessCredential(const uint8_t *credId, size_t credIdLen, const String &rpId,
                               String &outUserIdHex, String &outUserName,
                               String &outPrivateKeyHex, int &outAlgId) {
    if (credIdLen < 123) return false; // Minimum size validation

    uint8_t aesKey[32], hmacKey[32];
    getStatelessMasterKeys(aesKey, hmacKey);

    size_t encryptedLen = credIdLen - 48; // Total minus IV(16) and HMAC(32)
    if (encryptedLen % 16 != 0) return false;

    const uint8_t* iv = &credId[0];
    const uint8_t* encrypted = &credId[16];
    const uint8_t* expectedHmac = &credId[16 + encryptedLen];

    // Verify HMAC
    uint8_t computedHmac[32];
    mbedtls_md_context_t md_ctx;
    mbedtls_md_init(&md_ctx);
    mbedtls_md_setup(&md_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
    mbedtls_md_hmac_starts(&md_ctx, hmacKey, 32);
    mbedtls_md_hmac_update(&md_ctx, iv, 16);
    mbedtls_md_hmac_update(&md_ctx, encrypted, encryptedLen);
    mbedtls_md_hmac_finish(&md_ctx, computedHmac);
    mbedtls_md_free(&md_ctx);

    if (memcmp(expectedHmac, computedHmac, 32) != 0) return false;

    // Decrypt
    uint8_t* plaintext = (uint8_t*)malloc(encryptedLen);
    if (!plaintext) return false;

    uint8_t iv_copy[16];
    memcpy(iv_copy, iv, 16);

    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_dec(&aes, aesKey, 256);
    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, encryptedLen, iv_copy, encrypted, plaintext);
    mbedtls_aes_free(&aes);

    if (plaintext[0] != 'S' || plaintext[1] != 'T' || plaintext[2] != 'A' || plaintext[3] != 'T') {
        free(plaintext);
        return false;
    }

    // Validate RP ID Hash
    uint8_t expectedRpHash[32];
    mbedtls_md_init(&md_ctx);
    mbedtls_md_setup(&md_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 0);
    mbedtls_md_starts(&md_ctx);
    mbedtls_md_update(&md_ctx, (const uint8_t*)rpId.c_str(), rpId.length());
    mbedtls_md_finish(&md_ctx, expectedRpHash);
    mbedtls_md_free(&md_ctx);

    if (memcmp(&plaintext[8], expectedRpHash, 32) != 0) {
        free(plaintext);
        return false;
    }

    int32_t netAlg = ((int32_t)plaintext[4] << 24) | ((int32_t)plaintext[5] << 16) | ((int32_t)plaintext[6] << 8) | plaintext[7];
    outAlgId = (int)netAlg;

    uint8_t uLen = plaintext[40] > 32 ? 32 : plaintext[40];
    outUserIdHex = toHex(&plaintext[41], uLen);

    uint8_t nLen = plaintext[73] > 32 ? 32 : plaintext[73];
    char nameBuf[33] = {0};
    memcpy(nameBuf, &plaintext[74], nLen);
    outUserName = String(nameBuf);

    uint16_t pLen = (plaintext[106] << 8) | plaintext[107];
    if (108 + pLen > encryptedLen) { free(plaintext); return false; }
    outPrivateKeyHex = toHex(&plaintext[108], pLen);

    free(plaintext);
    return true;
}

static void getStatelessMasterSecret(uint8_t secretOut[32]) {
    nvs_handle_t h;
    if (nvs_open("storage", NVS_READWRITE, &h) != ESP_OK) {
        memset(secretOut, 0, 32); // should not happen; fails safe/no-verify rather than crash
        return;
    }
    size_t len = 32;
    if (nvs_get_blob(h, "sl_secret", secretOut, &len) != ESP_OK || len != 32) {
        esp_fill_random(secretOut, 32);
        nvs_set_blob(h, "sl_secret", secretOut, 32);
        nvs_commit(h);
    }
    nvs_close(h);
}

void rotateStatelessMasterSecret() {
    nvs_handle_t h;
    if (nvs_open("storage", NVS_READWRITE, &h) == ESP_OK) {
        uint8_t fresh[32];
        esp_fill_random(fresh, 32);
        nvs_set_blob(h, "sl_secret", fresh, 32);
        nvs_commit(h);
        nvs_close(h);
    }
}

int getFailedUvAttempts() {
    xSemaphoreTake(storageMutex, portMAX_DELAY);
    if (!SPIFFS.exists("/fido_uv_fail.txt")) {
        xSemaphoreGive(storageMutex);
        return 0;
    }
    File file = SPIFFS.open("/fido_uv_fail.txt", "r");
    if (!file) {
        xSemaphoreGive(storageMutex);
        return 0;
    }
    String val = file.readString();
    file.close();
    xSemaphoreGive(storageMutex);
    return val.toInt();
}

void incrementFailedUvAttempts() {
    int attempts = getFailedUvAttempts() + 1;
    xSemaphoreTake(storageMutex, portMAX_DELAY);
    File file = SPIFFS.open("/fido_uv_fail.txt", "w");
    if (file) {
        file.print(attempts);
        file.close();
    }
    xSemaphoreGive(storageMutex);
}

void resetFailedUvAttempts() {
    xSemaphoreTake(storageMutex, portMAX_DELAY);
    if (SPIFFS.exists("/fido_uv_fail.txt")) {
        SPIFFS.remove("/fido_uv_fail.txt");
    }
    xSemaphoreGive(storageMutex);
}

bool getForcePinChange() {
    xSemaphoreTake(storageMutex, portMAX_DELAY);
    bool res = false;
    if (SPIFFS.exists("/fido_force_pin.txt")) {
        File f = SPIFFS.open("/fido_force_pin.txt", "r");
        if (f) {
            res = (f.readString().toInt() == 1);
            f.close();
        }
    }
    xSemaphoreGive(storageMutex);
    return res;
}

void setForcePinChange(bool force) {
    xSemaphoreTake(storageMutex, portMAX_DELAY);
    File f = SPIFFS.open("/fido_force_pin.txt", "w");
    if (f) {
        f.print(force ? "1" : "0");
        f.close();
    }
    xSemaphoreGive(storageMutex);
}

uint8_t getMinPinLength() {
    xSemaphoreTake(storageMutex, portMAX_DELAY);
    uint8_t res = 4;
    if (SPIFFS.exists("/fido_min_pin.txt")) {
        File f = SPIFFS.open("/fido_min_pin.txt", "r");
        if (f) {
            res = f.readString().toInt();
            f.close();
        }
    }
    xSemaphoreGive(storageMutex);
    return res < 4 ? 4 : res;
}

void setMinPinLength(uint8_t length) {
    xSemaphoreTake(storageMutex, portMAX_DELAY);
    File f = SPIFFS.open("/fido_min_pin.txt", "w");
    if (f) {
        f.print(length);
        f.close();
    }
    xSemaphoreGive(storageMutex);
}

void incrementFailedFidoPinAttempts() {
    int attempts = getFailedFidoPinAttempts() + 1;
    xSemaphoreTake(storageMutex, portMAX_DELAY);
    File file = SPIFFS.open("/fido_fail.txt", "w");
    if (file) {
        file.print(attempts);
        file.close();
    }
    xSemaphoreGive(storageMutex);
}

void resetFailedFidoPinAttempts() {
    xSemaphoreTake(storageMutex, portMAX_DELAY);
    if (SPIFFS.exists("/fido_fail.txt")) {
        SPIFFS.remove("/fido_fail.txt");
    }
    xSemaphoreGive(storageMutex);
}

bool verifyFidoPinInternal(const String& pin) {
    if (!isFidoPinSet()) return false;
    String hashedPin = hashPin(pin);
    xSemaphoreTake(storageMutex, portMAX_DELAY);
    File file = SPIFFS.open("/fido_pin.txt", "r");
    String storedHash = "";
    if (file) {
        storedHash = file.readString();
        file.close();
    }
    xSemaphoreGive(storageMutex);
    return storedHash == hashedPin;
}