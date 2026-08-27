#include "StorageManager.h"
#include "CryptoManager.h"
#include "SPIFFS.h"
#include <ArduinoJson.h>

// Holds the transient hardware encryption key derived from user login credentials
static byte storageKey[32] = {0};
static bool isStorageKeyLoaded = false;

// Generates the hardware key via SHA-256 derivation of the authentic PIN sequence
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
  return SPIFFS.begin(true);
}

bool isMasterPinSet() { 
  return SPIFFS.exists("/master_hash.bin") && SPIFFS.exists("/master_salt.bin"); 
}

bool saveMasterPinData(const uint8_t *hash, size_t hashLen, const uint8_t *salt, size_t saltLen) {
  File hashFile = SPIFFS.open("/master_hash.bin", "w");
  if (!hashFile) return false;
  hashFile.write(hash, hashLen);
  hashFile.close();

  File saltFile = SPIFFS.open("/master_salt.bin", "w");
  if (!saltFile) {
    SPIFFS.remove("/master_hash.bin"); 
    return false;
  }
  saltFile.write(salt, saltLen);
  saltFile.close();
  return true;
}

bool readMasterPinData(uint8_t *hashOut, size_t hashLen, uint8_t *saltOut, size_t saltLen) {
  if (!isMasterPinSet()) return false;

  File hashFile = SPIFFS.open("/master_hash.bin", "r");
  if (!hashFile || hashFile.size() != hashLen) { 
    if (hashFile) hashFile.close(); 
    return false; 
  }
  hashFile.read(hashOut, hashLen);
  hashFile.close();

  File saltFile = SPIFFS.open("/master_salt.bin", "r");
  if (!saltFile || saltFile.size() != saltLen) { 
    if (saltFile) saltFile.close(); 
    return false; 
  }
  saltFile.read(saltOut, saltLen);
  saltFile.close();
  return true;
}

bool deleteMasterPin() {
  bool deletedHash = SPIFFS.remove("/master_hash.bin");
  bool deletedSalt = SPIFFS.remove("/master_salt.bin");
  return deletedHash || deletedSalt;
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

bool isPinSet() { return SPIFFS.exists("/pin.txt"); }

void createPin(const String &pin) {
  String hashedPin = hashPin(pin);
  File file = SPIFFS.open("/pin.txt", "w");
  if (!file) return;
  file.print(hashedPin);
  file.close();
}

bool verifyPin(const String &pin) {
  File file = SPIFFS.open("/pin.txt", "r");
  if (!file) return false;
  String storedHash = file.readString();
  file.close();
  return storedHash == hashPin(pin);
}

bool isPasswordExists(const String &name) {
  if (!SPIFFS.exists("/passwords.json")) return false;
  File file = SPIFFS.open("/passwords.json", "r");
  if (!file) return false;
  JsonDocument doc;
  DeserializationError error = deserializeJson(doc, file);
  file.close();
  return !error && doc[name].is<JsonVariant>();
}

void savePassword(const String &name, const String &password) {
  if (!isStorageKeyLoaded) { Terminal.println("[ERR] CODE:STORAGE_KEY_LOCKED"); return; }
  if (name.length() > 32) { Terminal.println("[ERR] CODE:NAME_TOO_LONG"); return; }
  if (password.length() > 4000) { Terminal.println("[ERR] CODE:PASS_TOO_LONG"); return; }
  if (isPasswordExists(name)) { Terminal.println("[ERR] CODE:ALREADY_EXISTS"); return; }

  JsonDocument doc;
  if (SPIFFS.exists("/passwords.json")) {
    File file = SPIFFS.open("/passwords.json", "r");
    if (file) {
      deserializeJson(doc, file);
      file.close();
    }
  }

  JsonObject obj = doc.as<JsonObject>();
  if (obj.size() >= 1000) { Terminal.println("[ERR] CODE:MAX_LIMIT_REACHED"); return; }

  // Secure Step: Encrypt password value via Hardware Accelerated AES-GCM before saving
  String encryptedValue = encryptStoragePayload(password, storageKey);
  if (encryptedValue == "") { Terminal.println("[ERR] CODE:ENC_FAILED"); return; }

  doc[name] = encryptedValue;
  File file = SPIFFS.open("/passwords.json", "w");
  if (!file) { Terminal.println("[ERR] CODE:FILE_CREATE_FAILED"); return; }
  serializeJson(doc, file);
  file.close();
  Terminal.println("[PASS] OUT:SAVED");
}

String getPasswordFromStorage(const String &name) {
  if (!isStorageKeyLoaded) return "";
  File file = SPIFFS.open("/passwords.json", "r");
  if (!file) return "";
  JsonDocument doc;
  deserializeJson(doc, file);
  file.close();
  
  if (!doc[name].is<JsonVariant>()) return "";
  
  String encryptedValue = doc[name].as<String>();
  
  // Secure Step: Decrypt the record token using the runtime Hardware AES-GCM engine context
  return decryptStoragePayload(encryptedValue, storageKey);
}

bool deletePassword(const String &name) {
  if (!SPIFFS.exists("/passwords.json")) return false;
  File file = SPIFFS.open("/passwords.json", "r");
  if (!file) return false;
  JsonDocument doc;
  deserializeJson(doc, file);
  file.close();
  
  if (!doc[name].is<JsonVariant>()) return false;
  doc.remove(name);

  file = SPIFFS.open("/passwords.json", "w");
  if (!file) return false;
  serializeJson(doc, file);
  file.close();
  return true;
}

void listPasswords() {
  if (!SPIFFS.exists("/passwords.json")) { Terminal.println("[PASS] OUT:EMPTY"); return; }
  File file = SPIFFS.open("/passwords.json", "r");
  if (!file) { Terminal.println("[ERR] CODE:READ_FAILED"); return; }
  JsonDocument doc;
  deserializeJson(doc, file);
  file.close();

  JsonObject obj = doc.as<JsonObject>();
  for (JsonPair pair : obj) {
    Terminal.print("[PASS] ITEM:");
    Terminal.println(pair.key().c_str());
  }
  Terminal.println("[PASS] OUT:LIST_END");
}

void showStorageInfo() {
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
  // Emits structured stats easily extracted via single string splits
  Terminal.printf("[STORAGE] STATS:%d,%d,%d,%.2f,%d,%d,%.2f\n", total, used, free, usage, count, chars, avg);
}

bool deletePin() {
  if (SPIFFS.exists("/pin.txt")) {
    return SPIFFS.remove("/pin.txt");
  }
  return false; // Return false if there was no PIN file to delete
}

int getFailedMasterAttempts() {
  if (!SPIFFS.exists("/failures.txt")) return 0;
  File file = SPIFFS.open("/failures.txt", "r");
  if (!file) return 0;
  String val = file.readString();
  file.close();
  return val.toInt();
}

void incrementFailedMasterAttempts() {
  int attempts = getFailedMasterAttempts() + 1;
  File file = SPIFFS.open("/failures.txt", "w");
  if (file) {
    file.print(attempts);
    file.close();
  }
}

void resetFailedMasterAttempts() {
  if (SPIFFS.exists("/failures.txt")) {
    SPIFFS.remove("/failures.txt");
  }
}

void factoryResetSystem() {
    SPIFFS.remove("/passwords.json");
    SPIFFS.remove("/passkeys.json");
    SPIFFS.remove("/pin.txt");
    SPIFFS.remove("/master_hash.bin");
    SPIFFS.remove("/master_salt.bin");
    SPIFFS.remove("/failures.txt");
}

void clearAllStoredPasswords() {
    if (SPIFFS.exists("/passwords.json")) {
        SPIFFS.remove("/passwords.json");
    }
    if (SPIFFS.exists("/passkeys.json")) {
        SPIFFS.remove("/passkeys.json");
    }
    
    clearStorageKey();
    Serial.println("[STORAGE] VAULT PURGE COMPLETE");
}

// =========================================================================
// FIDO2 RESIDENT KEY / PASSKEY STORAGE SUB-SYSTEM
// =========================================================================

bool isPasskeyExists(const String &credentialIdHex) {
    if (!SPIFFS.exists("/passkeys.json")) return false;
    File file = SPIFFS.open("/passkeys.json", "r");
    if (!file) return false;
    
    JsonDocument doc;
    DeserializationError error = deserializeJson(doc, file);
    file.close();
    
    return !error && doc[credentialIdHex].is<JsonVariant>();
}

bool savePasskeyRecord(const String &credentialIdHex, const String &rpId, const String &userIdHex, const String &userName, const String &privateKeyHex, int algId) {
    if (!isStorageKeyLoaded) { Terminal.println("[ERR] CODE:STORAGE_KEY_LOCKED"); return false; }
    
    JsonDocument doc;
    if (SPIFFS.exists("/passkeys.json")) {
        File file = SPIFFS.open("/passkeys.json", "r");
        if (file) {
            deserializeJson(doc, file);
            file.close();
        }
    }

    // Build the outer record layout
    JsonObject record = doc[credentialIdHex].to<JsonObject>();
    record["rpId"] = rpId;

    // Fix: Serialize payload safely into a nested JSON object instead of raw commas
    JsonDocument payloadDoc;
    payloadDoc["uId"] = userIdHex;
    payloadDoc["uName"] = userName;
    payloadDoc["pKey"] = privateKeyHex;

    String rawPayload;
    serializeJson(payloadDoc, rawPayload);

    String encryptedPayload = encryptStoragePayload(rawPayload, storageKey);
    if (encryptedPayload == "") {
        Terminal.println("[ERR] CODE:PASSKEY_ENC_FAILED");
        return false;
    }
    
    record["payload"] = encryptedPayload;
    record["alg"] = algId;
    File file = SPIFFS.open("/passkeys.json", "w");
    if (!file) { Terminal.println("[ERR] CODE:FILE_CREATE_FAILED"); return false; }
    
    serializeJson(doc, file);
    file.close();
    Terminal.println("[PASS] OUT:PASSKEY_SAVED");
    return true;
}

bool getPasskeyRecord(const String &credentialIdHex, String &rpIdOut, 
                      String &userIdHexOut, String &userNameOut, 
                      String &privateKeyHexOut, int &algId) {
    if (!isStorageKeyLoaded || !SPIFFS.exists("/passkeys.json")) return false;

    File file = SPIFFS.open("/passkeys.json", "r");
    if (!file) return false;
    
    JsonDocument doc;
    DeserializationError error = deserializeJson(doc, file);
    file.close();

    if (error || !doc[credentialIdHex].is<JsonVariant>()) return false;

    JsonObject record = doc[credentialIdHex].as<JsonObject>();
    rpIdOut = record["rpId"].as<String>();
    String encryptedPayload = record["payload"].as<String>();

    String decryptedPayload = decryptStoragePayload(encryptedPayload, storageKey);
    if (decryptedPayload == "") return false;

    // Fix: Safely unpack fields by parsing the nested JSON structure
    JsonDocument payloadDoc;
    DeserializationError payloadError = deserializeJson(payloadDoc, decryptedPayload);
    if (payloadError) return false;

    userIdHexOut = payloadDoc["uId"].as<String>();
    userNameOut = payloadDoc["uName"].as<String>();
    privateKeyHexOut = payloadDoc["pKey"].as<String>();
    algId = payloadDoc["alg"] | -7;
    return true;
}

// Searches for a registered credential mapped under a specific relying party ID (web domain)
// This is critical for the Assertion (Login) phase when the host asks: "Who do you have registered for webauthn.io?"
String findCredentialIdByRpAndUser(const String &rpId, const String &userIdHex) {
    if (!SPIFFS.exists("/passkeys.json")) return "";
    File file = SPIFFS.open("/passkeys.json", "r");
    if (!file) return "";
    
    JsonDocument doc;
    DeserializationError error = deserializeJson(doc, file);
    file.close();
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
    // 1. Find the credential ID as a Hex String using your existing function
    String credentialIdHex = findCredentialIdByRpAndUser(rpId, userIdHex);
    
    // 2. If not found, return 0 length
    if (credentialIdHex.length() == 0) {
        return 0; 
    }
    
    // 3. Calculate binary length
    size_t binIdLen = credentialIdHex.length() / 2;
    
    // 4. Prevent buffer overflows
    if (binIdLen > maxOutLen) {
        return 0; 
    }
    
    // 5. Decode into the provided raw binary buffer
    fromHex(credentialIdHex, outBuffer, binIdLen);
    
    // 6. Return the exact binary size to pack into CBOR
    return binIdLen;
}

#include <vector>

// Lists only unique FIDO2 website names (RP IDs)
void listFidoWebsites() {
  if (!SPIFFS.exists("/passkeys.json")) {
    Terminal.println("[FIDO2] OUT:EMPTY");
    return;
  }
  File file = SPIFFS.open("/passkeys.json", "r");
  if (!file) {
    Terminal.println("[ERR] CODE:READ_FAILED");
    return;
  }
  JsonDocument doc;
  DeserializationError error = deserializeJson(doc, file);
  file.close();
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

// Purges ALL credentials, keys, and metadata saved for the specified FIDO2 website
bool deleteFidoWebsite(const String &rpId) {
  if (!SPIFFS.exists("/passkeys.json")) return false;
  File file = SPIFFS.open("/passkeys.json", "r");
  if (!file) return false;
  
  JsonDocument doc;
  DeserializationError error = deserializeJson(doc, file);
  file.close();
  if (error) return false;

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

  if (keysToRemove.empty()) return false;

  for (const String &key : keysToRemove) {
    doc.remove(key);
  }

  file = SPIFFS.open("/passkeys.json", "w");
  if (!file) return false;
  serializeJson(doc, file);
  file.close();
  return true;
}

// Decrypts and retrieves stored account detail records for a given FIDO2 website
String getFidoWebsiteInfo(const String &rpId) {
  if (!isStorageKeyLoaded || !SPIFFS.exists("/passkeys.json")) return "";
  File file = SPIFFS.open("/passkeys.json", "r");
  if (!file) return "";

  JsonDocument doc;
  DeserializationError error = deserializeJson(doc, file);
  file.close();
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
    
    JsonDocument doc;
    if (SPIFFS.exists("/totp.json")) {
        File file = SPIFFS.open("/totp.json", "r");
        if (file) {
            deserializeJson(doc, file);
            file.close();
        }
    }
    
    String encryptedValue = encryptStoragePayload(secret, storageKey);
    if (encryptedValue == "") return;
    
    doc[name] = encryptedValue;
    File file = SPIFFS.open("/totp.json", "w");
    if (!file) return;
    
    serializeJson(doc, file);
    file.close();
    Terminal.println("[TOTP] OUT:SAVED");
}

String getTotpSecret(const String &name) {
    if (!isStorageKeyLoaded) return "";
    
    File file = SPIFFS.open("/totp.json", "r");
    if (!file) return "";
    
    JsonDocument doc;
    deserializeJson(doc, file);
    file.close();
    
    if (!doc[name].is<JsonVariant>()) return "";
    
    String encryptedValue = doc[name].as<String>();
    return decryptStoragePayload(encryptedValue, storageKey);
}