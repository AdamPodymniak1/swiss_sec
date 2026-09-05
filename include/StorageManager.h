#ifndef STORAGE_MANAGER_H
#define STORAGE_MANAGER_H

#include <Arduino.h>
#include <vector>

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

bool isPasswordExists(const String &website, const String &login);
bool savePassword(const String &website, const String &login, const String &password);
String getPasswordFromStorage(const String &website, const String &login);
bool deletePassword(const String &website, const String &login);
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

void secureWipe(String &str);

bool isFidoPinSet();
void createFidoPin(const String &pin);
int getFailedFidoPinAttempts();
void resetFido2System();
std::vector<String> findAllCredentialsByRp(const String &rpId);
std::vector<String> getAllStoredCredentialIds();
std::vector<String> getAllStoredRpIds();
bool deletePasskeyRecord(const String &credentialIdHex);
bool wrapStatelessCredential(const String &rpId, const uint8_t *userId, size_t userIdLen, const String &userName, const String &privateKeyHex, int algId, uint8_t *outCredId, size_t &outCredIdLen);
bool unwrapStatelessCredential(const uint8_t *credId, size_t credIdLen, const String &rpId, String &outUserIdHex, String &outUserName, String &outPrivateKeyHex, int &outAlgId);
void rotateStatelessMasterSecret();
static void getStatelessMasterSecret(uint8_t secretOut[32]);
void rotateStatelessMasterSecret();

#endif