#ifndef STORAGE_MANAGER_H
#define STORAGE_MANAGER_H

#include <Arduino.h>

// Storage APIs are split by PIN vault records, resident passkeys, and TOTP seeds.
void deriveStorageKey(const String &pin);
void clearStorageKey();

bool initStorage();
String hashPin(const String &pin);
bool isPinSet();
void createPin(const String &pin);
bool verifyPin(const String &pin);
int getFailedPinAttempts();
void incrementFailedPinAttempts();
void resetFailedPinAttempts();

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

void saveTotpSecret(const String &name, const String &secret);
String getTotpSecret(const String &name);
void handleTotpGetAll(uint32_t currentEpoch);
bool deleteTotpSecret(const String &name);

void saveDefaultCryptoAlg(int algId);
int loadDefaultCryptoAlg();

#endif
