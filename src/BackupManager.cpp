#include "BackupManager.h"
#include "CryptoManager.h"
#include "CommsManager.h"
#include "Globals.h"
#include <ArduinoJson.h>
#include "mbedtls/gcm.h"
#include "mbedtls/md.h"
#include "mbedtls/pkcs5.h"

bool exportVaultPlaintext(JsonDocument &out);
bool importVaultPlaintext(JsonDocument &in, bool overwrite, uint32_t &importedCount, uint32_t &skippedCount);

#define BACKUP_PBKDF2_ITERATIONS 200000
#define BACKUP_SALT_LEN 16
#define BACKUP_NONCE_LEN 12
#define BACKUP_TAG_LEN 16
#define BACKUP_MAGIC "VBK1"
#define BACKUP_VERSION 1
#define BACKUP_HEADER_LEN (4 + 1 + BACKUP_SALT_LEN + 4 + BACKUP_NONCE_LEN + BACKUP_TAG_LEN + 4)
#define BACKUP_EXPORT_CHUNK_SIZE 256
#define MAX_BACKUP_HEX_LEN (512UL * 1024UL)

static bool deriveBackupKey(const String &passphrase, const uint8_t *salt, uint32_t iterations, uint8_t keyOut[32]) {
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    if (mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1) != 0) {
        mbedtls_md_free(&ctx);
        return false;
    }
    int rc = mbedtls_pkcs5_pbkdf2_hmac(
        &ctx,
        (const unsigned char *)passphrase.c_str(), passphrase.length(),
        salt, BACKUP_SALT_LEN,
        iterations,
        32, keyOut
    );
    mbedtls_md_free(&ctx);
    return rc == 0;
}

static void putU32(uint8_t *dst, uint32_t v) {
    dst[0] = (v >> 24) & 0xFF;
    dst[1] = (v >> 16) & 0xFF;
    dst[2] = (v >> 8) & 0xFF;
    dst[3] = v & 0xFF;
}

static uint32_t getU32(const uint8_t *src) {
    return ((uint32_t)src[0] << 24) | ((uint32_t)src[1] << 16) | ((uint32_t)src[2] << 8) | src[3];
}

static bool backupEncryptBlob(const String &plaintext, const String &passphrase, String &hexOut, String &errorOut) {
    uint8_t salt[BACKUP_SALT_LEN];
    esp_fill_random(salt, sizeof(salt));

    uint8_t key[32];
    if (!deriveBackupKey(passphrase, salt, BACKUP_PBKDF2_ITERATIONS, key)) {
        errorOut = "KDF_FAILED";
        return false;
    }

    uint8_t nonce[BACKUP_NONCE_LEN];
    esp_fill_random(nonce, sizeof(nonce));

    size_t ptLen = plaintext.length();
    uint8_t *cipher = (uint8_t *)malloc(ptLen > 0 ? ptLen : 1);
    if (!cipher) {
        memset(key, 0, sizeof(key));
        errorOut = "OOM";
        return false;
    }
    uint8_t tag[BACKUP_TAG_LEN];

    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    int rc = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256);
    if (rc == 0) {
        rc = mbedtls_gcm_crypt_and_tag(
            &gcm, MBEDTLS_GCM_ENCRYPT, ptLen,
            nonce, sizeof(nonce), NULL, 0,
            (const uint8_t *)plaintext.c_str(), cipher,
            sizeof(tag), tag
        );
    }
    mbedtls_gcm_free(&gcm);
    memset(key, 0, sizeof(key));

    if (rc != 0) {
        free(cipher);
        errorOut = "GCM_ENCRYPT_FAILED";
        return false;
    }

    size_t totalLen = BACKUP_HEADER_LEN + ptLen;
    uint8_t *blob = (uint8_t *)malloc(totalLen);
    if (!blob) {
        free(cipher);
        errorOut = "OOM";
        return false;
    }

    size_t o = 0;
    memcpy(blob + o, BACKUP_MAGIC, 4); o += 4;
    blob[o++] = BACKUP_VERSION;
    memcpy(blob + o, salt, BACKUP_SALT_LEN); o += BACKUP_SALT_LEN;
    putU32(blob + o, BACKUP_PBKDF2_ITERATIONS); o += 4;
    memcpy(blob + o, nonce, BACKUP_NONCE_LEN); o += BACKUP_NONCE_LEN;
    memcpy(blob + o, tag, BACKUP_TAG_LEN); o += BACKUP_TAG_LEN;
    putU32(blob + o, (uint32_t)ptLen); o += 4;
    memcpy(blob + o, cipher, ptLen); o += ptLen;
    free(cipher);

    hexOut = toHex(blob, totalLen);
    memset(blob, 0, totalLen);
    free(blob);
    return true;
}

static bool backupDecryptBlob(const String &hexIn, const String &passphrase, String &plaintextOut, String &errorOut) {
    size_t totalLen = hexIn.length() / 2;
    if (hexIn.length() % 2 != 0 || totalLen < BACKUP_HEADER_LEN) {
        errorOut = "MALFORMED_BLOB";
        return false;
    }

    uint8_t *blob = (uint8_t *)malloc(totalLen);
    if (!blob) { errorOut = "OOM"; return false; }
    if (fromHex(hexIn, blob, totalLen) != totalLen) {
        free(blob);
        errorOut = "BAD_HEX";
        return false;
    }

    size_t o = 0;
    if (memcmp(blob + o, BACKUP_MAGIC, 4) != 0) { free(blob); errorOut = "BAD_MAGIC"; return false; }
    o += 4;
    uint8_t version = blob[o++];
    if (version != BACKUP_VERSION) { free(blob); errorOut = "UNSUPPORTED_VERSION"; return false; }

    uint8_t salt[BACKUP_SALT_LEN];
    memcpy(salt, blob + o, BACKUP_SALT_LEN); o += BACKUP_SALT_LEN;
    uint32_t iterations = getU32(blob + o); o += 4;
    uint8_t nonce[BACKUP_NONCE_LEN];
    memcpy(nonce, blob + o, BACKUP_NONCE_LEN); o += BACKUP_NONCE_LEN;
    uint8_t tag[BACKUP_TAG_LEN];
    memcpy(tag, blob + o, BACKUP_TAG_LEN); o += BACKUP_TAG_LEN;
    uint32_t ctLen = getU32(blob + o); o += 4;

    if (iterations == 0 || iterations > 2000000UL) { free(blob); errorOut = "BAD_ITERATIONS"; return false; }
    if (o + ctLen != totalLen) { free(blob); errorOut = "LENGTH_MISMATCH"; return false; }

    uint8_t key[32];
    if (!deriveBackupKey(passphrase, salt, iterations, key)) {
        free(blob);
        errorOut = "KDF_FAILED";
        return false;
    }

    uint8_t *plain = (uint8_t *)malloc(ctLen > 0 ? ctLen : 1);
    if (!plain) { free(blob); memset(key, 0, sizeof(key)); errorOut = "OOM"; return false; }

    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    int rc = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256);
    if (rc == 0) {
        rc = mbedtls_gcm_auth_decrypt(
            &gcm, ctLen,
            nonce, sizeof(nonce), NULL, 0,
            tag, sizeof(tag),
            blob + o, plain
        );
    }
    mbedtls_gcm_free(&gcm);
    memset(key, 0, sizeof(key));
    memset(blob, 0, totalLen);
    free(blob);

    if (rc != 0) {
        memset(plain, 0, ctLen);
        free(plain);
        errorOut = "DECRYPT_FAILED_OR_WRONG_PASSPHRASE";
        return false;
    }

    plaintextOut = String((const char *)plain, ctLen);
    memset(plain, 0, ctLen);
    free(plain);
    return true;
}

bool backupExport(const String &passphrase, String &errorOut) {
    if (passphrase.length() < 8) {
        errorOut = "PASSPHRASE_TOO_SHORT";
        return false;
    }

    JsonDocument vault;
    if (!exportVaultPlaintext(vault)) {
        errorOut = "KEY_LOCKED";
        return false;
    }

    String plaintext;
    serializeJson(vault, plaintext);

    String hexBlob;
    bool ok = backupEncryptBlob(plaintext, passphrase, hexBlob, errorOut);
    if (plaintext.length() > 0) memset(const_cast<char *>(plaintext.c_str()), 0, plaintext.length());
    if (!ok) return false;

    String checksum = hashSHA256(hexBlob);
    size_t totalLen = hexBlob.length();
    size_t totalChunks = (totalLen + BACKUP_EXPORT_CHUNK_SIZE - 1) / BACKUP_EXPORT_CHUNK_SIZE;
    if (totalChunks == 0) totalChunks = 1;

    JsonDocument startData;
    startData["total_len"] = (uint32_t)totalLen;
    startData["total_chunks"] = (uint32_t)totalChunks;
    startData["sha256"] = checksum;
    CommsManager::sendEvent("BACKUP", "EXPORT_START", &startData);

    for (size_t i = 0; i < totalChunks; i++) {
        size_t start = i * BACKUP_EXPORT_CHUNK_SIZE;
        size_t len = min((size_t)BACKUP_EXPORT_CHUNK_SIZE, totalLen - start);
        JsonDocument chunkData;
        chunkData["seq"] = (uint32_t)i;
        chunkData["data"] = hexBlob.substring(start, start + len);
        CommsManager::sendEvent("BACKUP", "EXPORT_CHUNK", &chunkData);
        vTaskDelay(5 / portTICK_PERIOD_MS);
    }

    JsonDocument doneData;
    doneData["total_chunks"] = (uint32_t)totalChunks;
    CommsManager::sendEvent("BACKUP", "EXPORT_DONE", &doneData);

    if (hexBlob.length() > 0) memset(const_cast<char *>(hexBlob.c_str()), 0, hexBlob.length());
    return true;
}

static String importAccumHex = "";
static uint32_t importTotalLen = 0;
static String importExpectedSha256 = "";
static bool importInProgress = false;

bool backupImportBegin(uint32_t totalHexLen, const String &expectedSha256Hex, String &errorOut) {
    backupImportAbort();
    if (totalHexLen == 0 || totalHexLen > MAX_BACKUP_HEX_LEN) {
        errorOut = "BAD_LENGTH";
        return false;
    }
    if (expectedSha256Hex.length() != 64) {
        errorOut = "BAD_CHECKSUM_FORMAT";
        return false;
    }
    importAccumHex.reserve(totalHexLen);
    importTotalLen = totalHexLen;
    importExpectedSha256 = expectedSha256Hex;
    importInProgress = true;
    return true;
}

bool backupImportChunk(const String &hexData, String &errorOut) {
    if (!importInProgress) { errorOut = "NOT_STARTED"; return false; }
    if (importAccumHex.length() + hexData.length() > importTotalLen) {
        errorOut = "OVERFLOW";
        backupImportAbort();
        return false;
    }
    importAccumHex += hexData;
    return true;
}

void backupImportAbort() {
    if (importAccumHex.length() > 0) {
        memset(const_cast<char *>(importAccumHex.c_str()), 0, importAccumHex.length());
    }
    importAccumHex = "";
    importTotalLen = 0;
    importExpectedSha256 = "";
    importInProgress = false;
}

bool backupImportCommit(const String &passphrase, bool overwrite, String &errorOut) {
    if (!importInProgress) { errorOut = "NOT_STARTED"; return false; }
    if (importAccumHex.length() != importTotalLen) { errorOut = "INCOMPLETE"; return false; }

    if (hashSHA256(importAccumHex) != importExpectedSha256) {
        errorOut = "CHECKSUM_MISMATCH";
        backupImportAbort();
        return false;
    }

    String plaintext;
    bool ok = backupDecryptBlob(importAccumHex, passphrase, plaintext, errorOut);
    backupImportAbort();

    if (!ok) return false;

    JsonDocument doc;
    DeserializationError err = deserializeJson(doc, plaintext);
    if (plaintext.length() > 0) memset(const_cast<char *>(plaintext.c_str()), 0, plaintext.length());
    if (err) {
        errorOut = "BAD_ARCHIVE_JSON";
        return false;
    }

    uint32_t imported = 0, skipped = 0;
    if (!importVaultPlaintext(doc, overwrite, imported, skipped)) {
        errorOut = "IMPORT_FAILED";
        return false;
    }

    JsonDocument resultData;
    resultData["imported"] = imported;
    resultData["skipped"] = skipped;
    CommsManager::sendEvent("BACKUP", "IMPORT_DONE", &resultData);
    return true;
}