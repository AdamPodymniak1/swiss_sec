#include "CryptoManager.h"
#include <Arduino.h>
#include "mbedtls/md.h"
#include "mbedtls/gcm.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/pkcs5.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/pk.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/error.h"
#include "StorageManager.h"
#include <Ed25519.h>

#define PBKDF2_ITERATIONS 10000
#define HASH_SIZE 32
#define SALT_SIZE 16

// ==================================================
// ANTI-GLITCH / FAULT INJECTION (FI) CONSTANTS
// ==================================================
#define FI_MAGIC_START  0x1A2B3C4D
#define FI_MAGIC_PASSED 0x5E6F7A8B
#define FI_MAGIC_FAILED 0xDEADBEEF

// ==================================================
// GLOBAL STATE
// ==================================================

bool encryptionActive = false;
byte aesKey[32] = {0};

SecureTerminal Terminal;

// Safe entropy hardware callback bridge for mbedTLS
static int hw_rng_callback(void *p_rng, unsigned char *output, size_t output_len) {
  (void)p_rng;
  esp_fill_random(output, output_len);
  return 0; // Must return 0 on success for mbedTLS
}

// ==================================================
// HEX HELPERS (BOUNDS CHECKED)
// ==================================================

size_t fromHex(const String &hex, byte *output, size_t max_len) {
  size_t len = hex.length() / 2;
  if (len > max_len) len = max_len;

  memset(output, 0, max_len); 

  for (size_t i = 0; i < len; i++) {
    String byteString = hex.substring(i * 2, i * 2 + 2);
    output[i] = (byte)strtol(byteString.c_str(), NULL, 16);
  }

  return len; 
}

String toHex(const byte *data, size_t len) {
  String out;
  out.reserve(len * 2);

  for (size_t i = 0; i < len; i++) {
    char buf[3];
    sprintf(buf, "%02x", data[i]);
    out += buf;
  }
  return out;
}

// ==================================================
// CRYPTO INIT
// ==================================================

void initCrypto() {
  Serial.println("[SYS] CRYPTO_INIT");
  esp_fill_random(aesKey, sizeof(aesKey));
  encryptionActive = false;
}

// ==================================================
// AES-GCM
// ==================================================

String encryptMsg(const String &plainText) {
  if (!encryptionActive) return plainText;

  byte iv[12];
  esp_fill_random(iv, sizeof(iv));

  size_t len = plainText.length();
  byte *cipher = (byte *)malloc(len);
  byte tag[16];

  if (!cipher) return "";

  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);
  mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, aesKey, 256);

  mbedtls_gcm_crypt_and_tag(
      &gcm, MBEDTLS_GCM_ENCRYPT, len,
      iv, sizeof(iv), NULL, 0,
      (const byte *)plainText.c_str(), cipher, sizeof(tag), tag);

  mbedtls_gcm_free(&gcm);

  String result = "ENC:" + toHex(iv, 12) + ":" + toHex(cipher, len) + toHex(tag, 16);
  free(cipher);
  return result;
}

String decryptMsg(const String &payload) {
  int c1 = payload.indexOf(':');
  int c2 = payload.indexOf(':', c1 + 1);
  if (c1 == -1 || c2 == -1) return "";

  String ivHex = payload.substring(c1 + 1, c2);
  String dataHex = payload.substring(c2 + 1);

  // Buffer overrun protection
  if (ivHex.length() != 24) return ""; 
  
  size_t dataLen = dataHex.length() / 2;
  if (dataLen < 16) return "";

  byte iv[12];
  fromHex(ivHex, iv, sizeof(iv));

  byte *full = (byte *)malloc(dataLen);
  if (!full) return "";

  fromHex(dataHex, full, dataLen);

  size_t cipherLen = dataLen - 16;
  byte *tag = full + cipherLen;
  byte *plain = (byte *)malloc(cipherLen + 1);

  if (!plain) {
    free(full);
    return "";
  }

  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);
  mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, aesKey, 256);

  int ret = mbedtls_gcm_auth_decrypt(
      &gcm, cipherLen, iv, sizeof(iv),
      NULL, 0, tag, 16, full, plain);

  mbedtls_gcm_free(&gcm);
  free(full);

  if (ret != 0) {
    free(plain);
    return "";
  }

  plain[cipherLen] = '\0';
  String out = String((char *)plain);
  free(plain);

  return out;
}

// ==================================================
// NON-PANICKING ECDH HANDSHAKE WITH FI PROTECTION
// ==================================================

void processHandshake(const String &clientPubHex) {
  // Anti-Glitch State Tracking
  volatile uint32_t fi_state = FI_MAGIC_START;
  
  // SECP256R1 uncompressed keys are exactly 65 bytes (130 hex chars). 
  // Rejecting anomalies immediately prevents heap fragmentation crashes.
  if (clientPubHex.length() != 130) {
    Serial.println("[ERR] ECDH_INVALID_KEY_LENGTH");
    return;
  }

  // Random micro-delay to offset power analysis / timing attacks
  delay(esp_random() % 15 + 2); 

  mbedtls_ecdh_context ctx;
  mbedtls_ecdh_init(&ctx);

  int ret = mbedtls_ecp_group_load(&ctx.grp, MBEDTLS_ECP_DP_SECP256R1);
  if (ret != 0) {
    Serial.println("[ERR] ECDH_GRP_LOAD_FAIL");
    mbedtls_ecdh_free(&ctx);
    return;
  }

  ret = mbedtls_ecdh_gen_public(&ctx.grp, &ctx.d, &ctx.Q, hw_rng_callback, NULL);
  if (ret != 0) {
    Serial.println("[ERR] ECDH_GEN_PUB_FAIL");
    mbedtls_ecdh_free(&ctx);
    return;
  }

  yield(); // Feed the Task Watchdog

  // Use stack memory to avoid heap fragmentation
  byte clientPubBuf[65] = {0}; 
  fromHex(clientPubHex, clientPubBuf, sizeof(clientPubBuf));

  ret = mbedtls_ecp_point_read_binary(&ctx.grp, &ctx.Qp, clientPubBuf, sizeof(clientPubBuf));
  
  if (ret != 0) {
    Serial.println("[ERR] ECDH_PEER_KEY_INVALID");
    mbedtls_ecdh_free(&ctx);
    return;
  }

  delay(esp_random() % 10 + 1); // Second random delay

  ret = mbedtls_ecdh_compute_shared(&ctx.grp, &ctx.z, &ctx.Qp, &ctx.d, hw_rng_callback, NULL);
  if (ret != 0) {
    Serial.println("[ERR] ECDH_COMPUTE_SHARED_FAIL");
    mbedtls_ecdh_free(&ctx);
    return;
  }

  yield(); // Feed the Task Watchdog again

  byte sharedSecret[32];
  mbedtls_mpi_write_binary(&ctx.z, sharedSecret, sizeof(sharedSecret));
  mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), sharedSecret, sizeof(sharedSecret), aesKey);

  uint8_t exportBuf[70];
  size_t exportLen = 0;
  mbedtls_ecp_point_write_binary(&ctx.grp, &ctx.Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &exportLen, exportBuf, sizeof(exportBuf));

  // Redundant glitch check
  if (fi_state != FI_MAGIC_START) {
    ESP.restart(); // Glitch detected during math processing, kill system
  }
  
  fi_state = FI_MAGIC_PASSED;
  encryptionActive = true;

  Serial.print("DH_ACK:");
  Serial.println(toHex(exportBuf, exportLen));

  mbedtls_ecdh_free(&ctx);
}

// ==================================================
// SECURE TERMINAL (SAFE FLUSH)
// ==================================================

size_t SecureTerminal::write(uint8_t c) {
  buffer += (char)c;
  if (buffer.length() > 512) flush();
  return 1;
}

size_t SecureTerminal::write(const uint8_t *buf, size_t size) {
  for (size_t i = 0; i < size; i++) {
    buffer += (char)buf[i];
    if (buffer.length() > 512) flush();
  }
  return size;
}

void SecureTerminal::flush() {
  if (buffer.length() == 0) return;

  String out = buffer;
  buffer = "";

  if (encryptionActive)
    Serial.println(encryptMsg(out));
  else
    Serial.print(out);
}

// ==================================================
// RANDOM PASSWD GENERATOR WITH RF NOISE
// ==================================================

String generateRandomPassword(size_t length) {
  const char charPool[] = "abcdefghijkmnopqrstuvwxyzABCDEFGHIJKLMNPQRSTUVWXYZ23456789!@#$%^*()-_=+";
  size_t poolSize = sizeof(charPool) - 1;

  uint8_t *randomBytes = (uint8_t *)malloc(length);
  if (!randomBytes) return "";

  esp_fill_random(randomBytes, length);

  String password = "";
  password.reserve(length);
  
  for (size_t i = 0; i < length; i++) {
    password += charPool[randomBytes[i] % poolSize];
  }

  free(randomBytes);
  return password;
}

// ==================================================
// STORAGE ENCRYPTION
// ==================================================

String encryptStoragePayload(const String &plainText, const byte *key256) {
  byte iv[12];
  esp_fill_random(iv, sizeof(iv));

  size_t len = plainText.length();
  byte *cipher = (byte *)malloc(len);
  byte tag[16];

  if (!cipher) return "";

  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);
  
  mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key256, 256);

  mbedtls_gcm_crypt_and_tag(
      &gcm, MBEDTLS_GCM_ENCRYPT, len,
      iv, sizeof(iv), NULL, 0,
      (const byte *)plainText.c_str(), cipher, sizeof(tag), tag);

  mbedtls_gcm_free(&gcm);

  String result = toHex(iv, 12) + ":" + toHex(cipher, len) + ":" + toHex(tag, 16);
  free(cipher);
  return result;
}

String decryptStoragePayload(const String &payload, const byte *key256) {
  int c1 = payload.indexOf(':');
  int c2 = payload.indexOf(':', c1 + 1);
  if (c1 == -1 || c2 == -1) return "";

  String ivHex = payload.substring(0, c1);
  String cipherHex = payload.substring(c1 + 1, c2);
  String tagHex = payload.substring(c2 + 1);

  if (ivHex.length() != 24 || tagHex.length() != 32) return "";

  size_t cipherLen = cipherHex.length() / 2;
  if (cipherLen == 0) return "";

  byte iv[12];
  byte tag[16];
  fromHex(ivHex, iv, sizeof(iv));
  fromHex(tagHex, tag, sizeof(tag));

  byte *cipher = (byte *)malloc(cipherLen);
  byte *plain = (byte *)malloc(cipherLen + 1);
  
  if (!cipher || !plain) {
    if (cipher) free(cipher);
    if (plain) free(plain);
    return "";
  }

  fromHex(cipherHex, cipher, cipherLen);

  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);
  mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key256, 256);

  int ret = mbedtls_gcm_auth_decrypt(
      &gcm, cipherLen, iv, sizeof(iv),
      NULL, 0, tag, 16, cipher, plain);

  mbedtls_gcm_free(&gcm);
  free(cipher);

  if (ret != 0) {
    free(plain);
    return "";
  }

  plain[cipherLen] = '\0';
  String out = String((char *)plain);
  free(plain);
  return out;
}

// ==================================================
// BIOMETRIC SECURITY UTILITIES
// ==================================================

String hashSHA256(const String &input) {
  uint8_t outputHash[32];
  
  mbedtls_md(
    mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 
    (const uint8_t*)input.c_str(), 
    input.length(), 
    outputHash
  );
  
  return toHex(outputHash, 32);
}

// =========================================================================
// ECDSA P-256 KEYPAIR GENERATION & CANONICAL SIGNING
// =========================================================================

/**
 * Generates an ephemeral or resident P-256 Credential Keypair.
 * privateKeyOut: Must be pre-allocated to 32 bytes
 * publicKeyOut65: Must be pre-allocated to 65 bytes (0x04 || X || Y)
 */
#include <mbedtls/version.h>
#include <mbedtls/ecdsa.h>

// Handle mbedTLS 3.x private struct encapsulation
#if MBEDTLS_VERSION_NUMBER >= 0x03000000
    #define M_GRP MBEDTLS_PRIVATE(grp)
    #define M_D   MBEDTLS_PRIVATE(d)
    #define M_Q   MBEDTLS_PRIVATE(Q)
#else
    #define M_GRP grp
    #define M_D   d
    #define M_Q   Q
#endif

bool generateKeypairP256(uint8_t *privateKeyOut, uint8_t *publicKeyOut65) {
    if (privateKeyOut == nullptr || publicKeyOut65 == nullptr) {
        return false;
    }

    mbedtls_ecdsa_context ctx;
    mbedtls_ecdsa_init(&ctx);

    // 1. Generate the core keypair on NIST P-256 curve
    int ret = mbedtls_ecdsa_genkey(&ctx, MBEDTLS_ECP_DP_SECP256R1, hw_rng_callback, NULL);
    if (ret != 0) {
        mbedtls_ecdsa_free(&ctx);
        return false;
    }

    // 2. Export private scalar 'd' using the safe macro wrapper
    ret = mbedtls_mpi_write_binary(&ctx.M_D, privateKeyOut, 32);
    if (ret != 0) {
        mbedtls_ecdsa_free(&ctx);
        return false;
    }

    // 3. Export uncompressed public point mapping (65 bytes total)
    size_t writtenLen = 0;
    ret = mbedtls_ecp_point_write_binary(&ctx.M_GRP, &ctx.M_Q, 
                                         MBEDTLS_ECP_PF_UNCOMPRESSED, 
                                         &writtenLen, publicKeyOut65, 65);

    mbedtls_ecdsa_free(&ctx);
    return (ret == 0 && writtenLen == 65);
}

/**
 * Signs a 32-byte SHA-256 digest and emits a standard ASN.1 DER formatted signature
 * required by FIDO2 WebAuthn validating relying parties.
 */
#include <mbedtls/version.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/error.h>
#include <mbedtls/asn1write.h>

#if MBEDTLS_VERSION_NUMBER >= 0x03000000
    #define M_GRP MBEDTLS_PRIVATE(grp)
    #define M_D   MBEDTLS_PRIVATE(d)
#else
    #define M_GRP grp
    #define M_D   d
#endif

bool signECDSA_P256(const uint8_t *privateKey32, const uint8_t *digest32, size_t digestLen,
                    uint8_t *sigDerOut, size_t *sigDerLenOut) {
    if (!privateKey32 || !digest32 || digestLen != 32 || !sigDerOut || !sigDerLenOut) {
        return false;
    }

    size_t maxSigCapacity = *sigDerLenOut;
    mbedtls_ecdsa_context ctx;
    mbedtls_ecdsa_init(&ctx);

    // 1. Initialize curve and load private key
    if (mbedtls_ecp_group_load(&ctx.M_GRP, MBEDTLS_ECP_DP_SECP256R1) != 0 ||
        mbedtls_mpi_read_binary(&ctx.M_D, privateKey32, 32) != 0) {
        mbedtls_ecdsa_free(&ctx);
        return false;
    }

    mbedtls_mpi r, s;
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    // FIX: Declare variables here, BEFORE any 'goto' can jump over them
    unsigned char buf[128];
    unsigned char *p = buf + sizeof(buf);
    int len = 0;

    // 2. Core math signing (bypasses buggy ESP32 wrapper completely)
    int ret = mbedtls_ecdsa_sign(&ctx.M_GRP, &r, &s, &ctx.M_D, digest32, digestLen, hw_rng_callback, NULL);
    if (ret != 0) {
        Serial.println("[ERR] Core ECDSA math failed");
        goto cleanup;
    }

    // 3. Write strict ASN.1 DER (mbedTLS writes backwards into the buffer)
    ret = mbedtls_asn1_write_mpi(&p, buf, &s);
    if (ret <= 0) goto cleanup;
    len += ret;

    ret = mbedtls_asn1_write_mpi(&p, buf, &r);
    if (ret <= 0) goto cleanup;
    len += ret;

    ret = mbedtls_asn1_write_len(&p, buf, len);
    if (ret <= 0) goto cleanup;
    len += ret;

    ret = mbedtls_asn1_write_tag(&p, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    if (ret <= 0) goto cleanup;
    len += ret;

    if ((size_t)len > maxSigCapacity) {
        Serial.println("[ERR] Provided sigDerOut too small");
        goto cleanup;
    }

    // Copy forward into the destination buffer
    memcpy(sigDerOut, p, len);
    *sigDerLenOut = len;

    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    mbedtls_ecdsa_free(&ctx);
    return true;

cleanup:
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    mbedtls_ecdsa_free(&ctx);
    return false;
}

// Add to CryptoManager.cpp
// Safely generates the ECDSA signature for FIDO2 Login and writes it to a persistent buffer
bool generateFido2Signature(const String& privateKeyHex, const uint8_t* clientDataHash, size_t hashLen, uint8_t* sigOutBuffer, size_t* sigOutLen) {
    if (privateKeyHex.length() == 0 || hashLen != 32) {
        return false;
    }

    // 1. Convert hex private key to binary
    size_t pkLen = privateKeyHex.length() / 2;
    uint8_t pkBin[32]; 
    fromHex(privateKeyHex, pkBin, pkLen);

    // 2. sigOutBuffer MUST be allocated by the caller (at least 72 bytes)
    // This safely calls your existing signECDSA_P256 which copies the ASN.1 DER to sigOutBuffer
    bool success = signECDSA_P256(pkBin, clientDataHash, hashLen, sigOutBuffer, sigOutLen);
    
    // 3. Clear private key from RAM immediately
    memset(pkBin, 0, sizeof(pkBin));
    
    return success;
}

static int mbedtls_fido2_rng(void *p_rng, unsigned char *output, size_t output_len) {
    (void)p_rng;
    esp_fill_random(output, output_len);
    return 0;
}

// Generates an Ed25519 keypair and outputs the private key as hex and the public key as raw bytes
bool generateEd25519KeyPair(String& privateKeyHexOut, uint8_t* pubKeyXOut) {
    uint8_t priv[32];
    uint8_t pub[32];
    
    // Utilize ESP32 hardware RNG for secure key generation
    esp_fill_random(priv, 32);
    
    // Derive public key via Crypto library
    Ed25519::derivePublicKey(pub, priv);
    
    // Format outputs using your existing hex helper
    privateKeyHexOut = toHex(priv, 32);
    memcpy(pubKeyXOut, pub, 32);
    
    return true;
}

// Generates a 2048-bit RSA key pair
bool generateRsa2048KeyPair(String& privateKeyHexOut, uint8_t* nOut, size_t* nLen, uint8_t* eOut, size_t* eLen) {
    mbedtls_pk_context ctx;
    mbedtls_pk_init(&ctx);

    if (mbedtls_pk_setup(&ctx, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA)) != 0) {
        mbedtls_pk_free(&ctx);
        return false;
    }

    // Fixed RNG parameter mismatch using our custom wrapper function
    if (mbedtls_rsa_gen_key(mbedtls_pk_rsa(ctx), mbedtls_fido2_rng, NULL, 2048, 65537) != 0) {
        mbedtls_pk_free(&ctx);
        return false;
    }

    mbedtls_rsa_context *rsa = mbedtls_pk_rsa(ctx);
    
    unsigned char privDer[1500];
    int len = mbedtls_pk_write_key_der(&ctx, privDer, sizeof(privDer));
    if (len < 0) {
        mbedtls_pk_free(&ctx);
        return false;
    }
    
    unsigned char* p = privDer + sizeof(privDer) - len;
    privateKeyHexOut = "";
    for(int i = 0; i < len; i++) {
        if(p[i] < 0x10) privateKeyHexOut += "0";
        privateKeyHexOut += String(p[i], HEX);
    }

    mbedtls_mpi_write_binary(&rsa->N, nOut, 256);
    *nLen = 256;
    mbedtls_mpi_write_binary(&rsa->E, eOut, 3);
    *eLen = 3;

    mbedtls_pk_free(&ctx);
    return true;
}

// Algorithm-multiplexed signature routine
bool generateAlgSignature(int algId, const String& privateKeyHex, const uint8_t* hash, size_t hashLen, uint8_t* sigOut, size_t* sigLen) {
    if (algId == -7) { // ES256
        return generateFido2Signature(privateKeyHex, hash, hashLen, sigOut, sigLen);
    } 
    else if (algId == -8) { // EdDSA
        uint8_t privBin[32];
        uint8_t pubBin[32];
        
        // Convert hex back to binary
        fromHex(privateKeyHex, privBin, 32);
        Ed25519::derivePublicKey(pubBin, privBin);
        
        // Sign the hash
        Ed25519::sign(sigOut, privBin, pubBin, hash, hashLen);
        *sigLen = 64; // Ed25519 signatures are exactly 64 bytes
        
        // Securely clear private key from stack memory
        memset(privBin, 0, sizeof(privBin));
        
        return true;
    }
    else if (algId == -257) { // RS256
        size_t derLen = privateKeyHex.length() / 2;
        uint8_t* derBuf = (uint8_t*)malloc(derLen);
        for (size_t i = 0; i < derLen; i++) {
            derBuf[i] = strtol(privateKeyHex.substring(i*2, i*2+2).c_str(), NULL, 16);
        }

        mbedtls_pk_context ctx;
        mbedtls_pk_init(&ctx);
        int ret = mbedtls_pk_parse_key(&ctx, derBuf, derLen, NULL, 0);
        free(derBuf);
        if (ret != 0) {
            mbedtls_pk_free(&ctx);
            return false;
        }

        size_t slen = 0;
        ret = mbedtls_pk_sign(&ctx, MBEDTLS_MD_SHA256, hash, hashLen, sigOut, &slen, mbedtls_fido2_rng, NULL);
        *sigLen = slen;
        mbedtls_pk_free(&ctx);
        return (ret == 0);
    }
    return false;
}

int decodeBase32(const char* b32, uint8_t* out) {
    int len = strlen(b32);
    int buffer = 0;
    int bitsLeft = 0;
    int count = 0;
    
    for (int i = 0; i < len; i++) {
        uint8_t val = 0;
        char c = b32[i];
        
        if (c >= 'A' && c <= 'Z') val = c - 'A';
        else if (c >= 'a' && c <= 'z') val = c - 'a';
        else if (c >= '2' && c <= '7') val = c - '2' + 26;
        else continue;
        
        buffer = (buffer << 5) | val;
        bitsLeft += 5;
        
        if (bitsLeft >= 8) {
            out[count++] = (buffer >> (bitsLeft - 8)) & 0xFF;
            bitsLeft -= 8;
        }
    }
    return count;
}

String generateTOTP(const String& base32Secret, uint32_t unixTime) {
    uint8_t key[64];
    int keyLen = decodeBase32(base32Secret.c_str(), key);
    
    uint64_t timeStep = unixTime / 30;
    uint8_t timeBytes[8];
    
    for (int i = 7; i >= 0; i--) {
        timeBytes[i] = timeStep & 0xFF;
        timeStep >>= 8;
    }
    
    uint8_t hash[20];
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA1), 1);
    mbedtls_md_hmac_starts(&ctx, key, keyLen);
    mbedtls_md_hmac_update(&ctx, timeBytes, 8);
    mbedtls_md_hmac_finish(&ctx, hash);
    mbedtls_md_free(&ctx);
    
    int offset = hash[19] & 0x0F;
    uint32_t binary = ((hash[offset] & 0x7F) << 24) |
                      ((hash[offset + 1] & 0xFF) << 16) |
                      ((hash[offset + 2] & 0xFF) << 8) |
                      (hash[offset + 3] & 0xFF);
                      
    uint32_t otp = binary % 1000000;
    char code[7];
    sprintf(code, "%06u", otp);
    
    return String(code);
}

void getFidoHardwareKey(byte* outKey256) {
    uint8_t mac[6];
    // Grab the factory-fused MAC address (guaranteed unique per ESP32-S3 chip)
    if (esp_efuse_mac_get_default(mac) != ESP_OK) {
        memset(mac, 0xAA, 6);
    }

    // Stretch the MAC into a secure 32-byte AES key
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 0);
    mbedtls_md_starts(&ctx);
    mbedtls_md_update(&ctx, mac, 6);
    mbedtls_md_update(&ctx, (const unsigned char*)"VAULT_APP_FIDO2_ISOLATION_SECRET", 32);
    mbedtls_md_finish(&ctx, outKey256);
    mbedtls_md_free(&ctx);
}