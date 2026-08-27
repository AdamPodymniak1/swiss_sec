#ifndef CRYPTO_MANAGER_H
#define CRYPTO_MANAGER_H

#include <Arduino.h>
#include "mbedtls/gcm.h"
#include "mbedtls/md.h"
#include <sodium.h>

extern bool encryptionActive;
extern byte aesKey[32];

void initCrypto();
size_t fromHex(const String &hex, byte *output, size_t max_len);
String toHex(const byte *data, size_t len);
String encryptMsg(const String &plainText);
String decryptMsg(const String &encryptedPayload);
void processHandshake(const String &browserPubKeyHex);

bool createMasterPinPBKDF2(const String &input);
bool verifyMasterPinPBKDF2(const String &input);

String generateRandomPassword(size_t length = 16);
String hashSHA256(const String &input);

String encryptStoragePayload(const String &plainText, const byte *key256);
String decryptStoragePayload(const String &payload, const byte *key256);

bool generateKeypairP256(uint8_t *privateKeyOut, uint8_t *publicKeyOut65);
bool signECDSA_P256(const uint8_t *privateKey32, const uint8_t *digest32, size_t digestLen, uint8_t *sigDerOut, size_t *sigDerLenOut);

class SecureTerminal : public Print {
public:
  String buffer;
  size_t write(uint8_t c) override;
  size_t write(const uint8_t *buf, size_t size) override;
  void flush();
};

extern SecureTerminal Terminal;

bool generateFido2Signature(const String &privateKeyHex, const uint8_t *clientDataHash, size_t hashLen, uint8_t *sigOutBuffer, size_t *sigOutLen);

static int mbedtls_fido2_rng(void *p_rng, unsigned char *output, size_t output_len);
bool generateEd25519KeyPair(String &privateKeyHexOut, uint8_t *pubKeyXOut);
bool generateRsa2048KeyPair(String& privateKeyHexOut, uint8_t* nOut, size_t* nLen, uint8_t* eOut, size_t* eLen);
bool generateAlgSignature(int algId, const String &privateKeyHex, const uint8_t *hash, size_t hashLen, uint8_t *sigOut, size_t *sigLen);

int decodeBase32(const char* b32, uint8_t* out);
String generateTOTP(const String& base32Secret, uint32_t unixTime);

#endif
