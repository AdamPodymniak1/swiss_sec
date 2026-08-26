#ifndef STORAGE_MANAGER_H
#define STORAGE_MANAGER_H

#include <Arduino.h>

void deriveStorageKey(const String &pin);
void clearStorageKey();

bool initStorage();
String hashPin(const String &pin);
bool isPinSet();
void createPin(const String &pin);
bool verifyPin(const String &pin);

bool isMasterPinSet();
bool saveMasterPinData(const uint8_t *hash, size_t hashLen, const uint8_t *salt, size_t saltLen);
bool readMasterPinData(uint8_t *hashOut, size_t hashLen, uint8_t *saltOut, size_t saltLen);
bool deleteMasterPin();

int getFailedMasterAttempts();
void incrementFailedMasterAttempts();
void resetFailedMasterAttempts();
void factoryResetSystem();

bool isPasswordExists(const String &name);
void savePassword(const String &name, const String &password);
String getPasswordFromStorage(const String &name);
bool deletePassword(const String &name);
void listPasswords();
void showStorageInfo();
bool deletePin();
void clearAllStoredPasswords();

bool isPasskeyExists(const String &credentialIdHex);
bool savePasskeyRecord(const String &credentialIdHex, const String &rpId, const String &userIdHex, const String &userName, const String &privateKeyHex, int algId);
bool getPasskeyRecord(const String &credentialIdHex, String &rpIdOut, String &userIdHexOut, String &userNameOut, String &privateKeyHexOut, int &algId);
String findCredentialIdByRpAndUser(const String &rpId, const String &userIdHex);

size_t getBinaryCredentialId(const String &rpId, const String &userIdHex, uint8_t *outBuffer, size_t maxOutLen);

void listFidoWebsites();
bool deleteFidoWebsite(const String &rpId);
String getFidoWebsiteInfo(const String &rpId);

#endif