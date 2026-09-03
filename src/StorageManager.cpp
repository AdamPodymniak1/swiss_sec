#include "StorageManager.h"
#include "CryptoManager.h"
#include "SPIFFS.h"
#include <ArduinoJson.h>
#include "Globals.h"
#include <vector>
#include "mbedtls/pkcs5.h"

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

void savePassword(const String &website, const String &login, const String &password) {
    if (!isStorageKeyLoaded) { Terminal.println("[ERR] CODE:STORAGE_KEY_LOCKED"); return; }
    if (website.length() > 64 || login.length() > 64) { Terminal.println("[ERR] CODE:IDENTIFIER_TOO_LONG"); return; }
    if (password.length() > 4000) { Terminal.println("[ERR] CODE:PASS_TOO_LONG"); return; }
    if (isPasswordExists(website, login)) { Terminal.println("[ERR] CODE:ALREADY_EXISTS"); return; }

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
        Terminal.println("[ERR] CODE:MAX_LIMIT_REACHED");
        return;
    }

    String encryptedValue = encryptStoragePayload(password, storageKey);
    if (encryptedValue == "") {
        xSemaphoreGive(storageMutex);
        Terminal.println("[ERR] CODE:ENC_FAILED");
        return;
    }

    JsonObject siteObj = doc[website].is<JsonObject>() ? doc[website].as<JsonObject>() : doc[website].to<JsonObject>();
    siteObj[login] = encryptedValue;

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
        Terminal.println("[PASS] LIST:EMPTY");
        return;
    }
    File file = SPIFFS.open("/passwords.json", "r");
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
        Terminal.println("[ERR] CODE:READ_FAILED");
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

        Terminal.print("[PASS] ITEM:");
        Terminal.print(websites[i]);
        Terminal.print("|");
        Terminal.print(logins[i]);
        if (isWeak) Terminal.println("|WEAK");
        else Terminal.println("|OK");
    }

    for (size_t i = 0; i < passwords.size(); i++) {
        if (passwords[i].length() > 0) {
            memset(const_cast<char*>(passwords[i].c_str()), 0, passwords[i].length());
            passwords[i] = "";
        }
    }
    Terminal.println("[PASS] LIST:LIST_END");
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
                file.seek(4, SeekCur); // Skip the algorithm identifier.

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
    
    Terminal.printf("[STORAGE] STATS:%d,%d,%d,%.2f,%d,%d,%.2f,%d\n", total, used, free, usage, count, chars, avg, passkeyCount);
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
    Serial.println("[STORAGE] VAULT PURGE COMPLETE");
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

bool savePasskeyRecord(const String &credentialIdHex, const String &rpId, const String &userIdHex, const String &userName, const String &privateKeyHex, int algId) {
    byte fidoKey[32];
    getFidoHardwareKey(fidoKey);
    String rawPayload = userIdHex + "\n" + userName + "\n" + privateKeyHex;
    String encryptedPayload = encryptStoragePayload(rawPayload, fidoKey);
    
    if (encryptedPayload == "") {
        Terminal.println("[ERR] CODE:PASSKEY_ENC_FAILED");
        return false;
    }

    xSemaphoreTake(storageMutex, portMAX_DELAY);
    File file = SPIFFS.open("/passkeys.bin", "a");
    if (!file) {
        xSemaphoreGive(storageMutex);
        Terminal.println("[ERR] CODE:FILE_CREATE_FAILED");
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
    Terminal.println("[PASS] OUT:PASSKEY_SAVED");
    return true;
}

bool getPasskeyRecord(const String &credentialIdHex, String &rpIdOut, String &userIdHexOut, String &userNameOut, String &privateKeyHexOut, int &algId) {
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
    privateKeyHexOut = decryptedPayload.substring(secondNewline + 1);

    return true;
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
        Terminal.println("[FIDO2] OUT:EMPTY");
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
                        result += "[FIDO2] USER:" + (userName.length() > 0 ? userName : "N/A") + " | CRED_ID:" + cid + "\n";
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
        Terminal.println("[TOTP] OUT: END_ALL");
        return;
    }

    File file = SPIFFS.open("/totp.json", "r");
    JsonDocument doc;
    if (deserializeJson(doc, file) == DeserializationError::Ok) {
        JsonObject obj = doc.as<JsonObject>();
        for (JsonPair pair : obj) {
            const char* accountName = pair.key().c_str();
            String encryptedValue = pair.value().as<String>();
            
            String decryptedSecret = decryptStoragePayload(encryptedValue, storageKey);
            if (decryptedSecret != "") {
                String codeStr = generateTOTP(decryptedSecret, currentEpoch);
                Terminal.printf("[TOTP] CODE:%s:%s\n", accountName, codeStr.c_str());
            }
        }
    }
    file.close();
    Terminal.println("[TOTP] OUT: END_ALL");
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