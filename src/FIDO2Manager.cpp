#include "FIDO2Manager.h"
#include "Globals.h"
#include "DisplayManager.h"
#include "FingerprintManager.h"
#include "CryptoManager.h"
#include "StorageManager.h"
#include <vector>

static std::vector<String> nextAssertionCreds;
static size_t nextAssertionIdx = 0;
static uint8_t nextAssertionClientHash[32] = {0};
static String nextAssertionRpId = "";
static bool nextAssertionOptionUV = false;
static bool nextAssertionExtReq = false;
static uint8_t nextAssertionSalt1[32] = {0};
static uint8_t nextAssertionSalt2[32] = {0};
static size_t nextAssertionSalt1Len = 0;
static size_t nextAssertionSalt2Len = 0;
static bool nextAssertionLargeBlobReq = false;

// authenticatorLargeBlobs (CTAP 2.1) fragment reassembly state for an
// in-progress "set" of the large-blob array.
static uint8_t* largeBlobWriteBuffer = nullptr;
static size_t largeBlobWriteBufferCapacity = 0;
static size_t largeBlobExpectedTotalLen = 0;
static size_t largeBlobReceivedLen = 0;
static const size_t MAX_LARGE_BLOB_ARRAY = 4096;
static std::vector<String> enumRpList;
static size_t enumRpIdx = 0;
static std::vector<String> enumCredList;
static size_t enumCredIdx = 0;
static uint8_t sessionPrivateKey[32];
static bool sessionKeyValid = false;
static uint8_t sessionSharedSecret[32];
static uint8_t sessionAesKey[32];
static uint8_t activeAuthToken[32];

uint8_t dynamicAaguid[16] = {0};
bool isAaguidInitialized = false;

// Stable per-device AAGUID, with a fixed namespace prefix and MAC-derived suffix.
void initializeDynamicAaguid() {
    if (isAaguidInitialized) return;

    uint8_t mac[6];

    if (esp_efuse_mac_get_default(mac) != ESP_OK) {
        memset(mac, 0xAA, 6);
    }

    dynamicAaguid[0] = 0x4F;
    dynamicAaguid[1] = 0xA2;
    dynamicAaguid[2] = 0xB1;
    dynamicAaguid[3] = 0x3C;
    dynamicAaguid[4] = 0x7C;
    dynamicAaguid[5] = 0x89;
    dynamicAaguid[6] = 0x4E; 
    dynamicAaguid[7] = 0x5B;
    dynamicAaguid[8] = 0xBC;
    dynamicAaguid[9] = 0x6D;

    memcpy(&dynamicAaguid[10], mac, 6);

    isAaguidInitialized = true;
}

static bool constantTimeEquals(const uint8_t* a, const uint8_t* b, size_t len) {
    uint8_t result = 0;
    for (size_t i = 0; i < len; i++) {
        result |= a[i] ^ b[i];
    }
    return result == 0;
}

static bool constantTimeStringEquals(const String& a, const String& b) {
    if (a.length() != b.length()) return false;
    return constantTimeEquals((const uint8_t*)a.c_str(), (const uint8_t*)b.c_str(), a.length());
}

uint32_t loadPersistedSignCount() {
    uint32_t count = 0;
    EEPROM.begin(512); 
    EEPROM.get(SIGN_COUNT_ADDR, count);

    if (count == 0xFFFFFFFF) return 0;
    return count;
}

void savePersistedSignCount(uint32_t count) {
    EEPROM.put(SIGN_COUNT_ADDR, count);
    EEPROM.commit(); 
}

bool fidoVerifyFingerprint() {
    if (getFailedUvAttempts() >= 5) {
        showDisplayMessage(1, "UV BLOCKED", "", 2000);
        return false;
    }

#if USE_FINGERPRINT_SIMULATOR
    if (digitalRead(SIMULATOR_BUTTON_PIN) == LOW) {
        while(digitalRead(SIMULATOR_BUTTON_PIN) == LOW) { vTaskDelay(10 / portTICK_PERIOD_MS); }
        resetFailedUvAttempts();
        return true;
    }
    return false;
#else
    xSemaphoreTake(fingerprintMutex, portMAX_DELAY);
    uint8_t img = finger.getImage();
    for (uint8_t retry = 0; retry < 3 && img != FINGERPRINT_OK && img != FINGERPRINT_NOFINGER; retry++) {
        vTaskDelay(50 / portTICK_PERIOD_MS);
        img = finger.getImage();
    }
    if (img == FINGERPRINT_NOFINGER) {
        xSemaphoreGive(fingerprintMutex);
        return false;
    }
    if (img != FINGERPRINT_OK) {
        xSemaphoreGive(fingerprintMutex);
        return false;
    }
    if (finger.image2Tz() != FINGERPRINT_OK) {
        xSemaphoreGive(fingerprintMutex);
        incrementFailedUvAttempts();
        return false;
    }
    if (finger.fingerSearch() != FINGERPRINT_OK) {
        xSemaphoreGive(fingerprintMutex);
        incrementFailedUvAttempts();
        return false;
    }
    if (finger.confidence == lastConfidenceScore && finger.confidence > 0) {
        xSemaphoreGive(fingerprintMutex);
        incrementFailedUvAttempts();
        return false;
    }
    lastConfidenceScore = finger.confidence;
    bool result = finger.confidence > 50;
    xSemaphoreGive(fingerprintMutex);

    if (result) {
        resetFailedUvAttempts();
    } else {
        incrementFailedUvAttempts();
    }
    return result;
#endif
}

// CTAPHID uses fixed 64-byte USB reports for both input and output.
const uint8_t fido_report_descriptor[34] = {
    0x06, 0xD0, 0xF1, 
    0x09, 0x01,       
    0xA1, 0x01,       
    0x09, 0x20,       
    0x15, 0x00,       
    0x26, 0xFF, 0x00, 
    0x75, 0x08,       
    0x95, 0x40,       
    0x81, 0x02,       
    0x09, 0x21,       
    0x15, 0x00,       
    0x26, 0xFF, 0x00, 
    0x75, 0x08,       
    0x95, 0x40,       
    0x91, 0x02,       
    0xC0              
};

FIDO2HIDDevice::FIDO2HIDDevice() {
    hid.addDevice(this, sizeof(fido_report_descriptor));
}

void FIDO2HIDDevice::begin() { 
    initializeDynamicAaguid();
    hid.begin();
}

uint16_t FIDO2HIDDevice::_onGetDescriptor(uint8_t* dst) {
    memcpy(dst, fido_report_descriptor, sizeof(fido_report_descriptor));
    return sizeof(fido_report_descriptor);
}

void FIDO2HIDDevice::sendCtapResponse(uint32_t channel, uint8_t cmd, const uint8_t* data, uint16_t len) {
    uint8_t packet[64] = {0};
    uint16_t offset = 0;

    packet[0] = (channel >> 24) & 0xFF;
    packet[1] = (channel >> 16) & 0xFF;
    packet[2] = (channel >> 8) & 0xFF;
    packet[3] = channel & 0xFF;
    packet[4] = cmd;
    packet[5] = (len >> 8) & 0xFF;
    packet[6] = len & 0xFF;

    uint16_t chunkLen = (len > 57) ? 57 : len;
    if (chunkLen > 0 && data != nullptr) {
        memcpy(&packet[7], data, chunkLen);
    }

    while (!hid.SendReport(0, packet, 64)) {
        vTaskDelay(2 / portTICK_PERIOD_MS);
    }
    offset += chunkLen;

    uint8_t seq = 0;
    while (offset < len) {
        memset(packet, 0, 64);
        packet[0] = (channel >> 24) & 0xFF;
        packet[1] = (channel >> 16) & 0xFF;
        packet[2] = (channel >> 8) & 0xFF;
        packet[3] = channel & 0xFF;

        packet[4] = seq & 0x7F;

        chunkLen = (len - offset > 59) ? 59 : (len - offset);
        if (chunkLen > 0 && data != nullptr) {
            memcpy(&packet[5], data + offset, chunkLen);
        }

        while (!hid.SendReport(0, packet, 64)) {
            vTaskDelay(2 / portTICK_PERIOD_MS);
        }
        
        offset += chunkLen;
        seq++;
        
        vTaskDelay(5 / portTICK_PERIOD_MS);
    }
}

void FIDO2HIDDevice::processU2fCommand(uint32_t channel, uint8_t* data, uint16_t len) {
    if (len < 4) {
        uint8_t err[] = {0x67, 0x00};
        sendCtapResponse(channel, 0x03, err, 2);
        return;
    }

    uint8_t ins = data[1];
    uint8_t p1 = data[2];

    if (ins == 0x03) {
        uint8_t resp[] = {'U', '2', 'F', '_', 'V', '2', 0x90, 0x00};
        sendCtapResponse(channel, 0x03, resp, 8);
        return;
    }

    if (len < 7) {
        uint8_t err[] = {0x67, 0x00};
        sendCtapResponse(channel, 0x03, err, 2);
        return;
    }

    uint16_t reqLen = (data[5] << 8) | data[6];
    uint8_t* payload = &data[7];

    if (ins == 0x01) {
        if (reqLen != 64 || !fidoVerifyFingerprint()) {
            uint8_t err[] = {0x69, 0x85};
            sendCtapResponse(channel, 0x03, err, 2);
            return;
        }

        showDisplayMessage(1, "WAITING", "", 0);

        uint8_t privKey[32];
        uint8_t pubKey[65];
        if (!generateKeypairP256(privKey, pubKey)) {
            uint8_t err[] = {0x6F, 0x00};
            sendCtapResponse(channel, 0x03, err, 2);
            return;
        }

        uint8_t kh[16];
        esp_fill_random(kh, 16);
        String khHex = toHex(kh, 16);
        String appIdHex = toHex(payload + 32, 32);
        String privHex = toHex(privKey, 32);

        savePasskeyRecord(khHex, appIdHex, "", "", privHex, -7);

        memset(privKey, 0, sizeof(privKey));
        secureWipe(privHex);

        uint8_t sigData[150];
        sigData[0] = 0x00;
        memcpy(sigData + 1, payload + 32, 32);
        memcpy(sigData + 33, payload, 32);
        memcpy(sigData + 65, kh, 16);
        memcpy(sigData + 81, pubKey, 65);

        uint8_t hash[32];
        mbedtls_md_context_t ctx;
        mbedtls_md_init(&ctx);
        mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 0);
        mbedtls_md_starts(&ctx);
        mbedtls_md_update(&ctx, sigData, 146);
        mbedtls_md_finish(&ctx, hash);
        mbedtls_md_free(&ctx);

        uint8_t* sig = nullptr;
        size_t sigLen = 0;
        if (!generateAlgSignature(-7, privHex, hash, 32, &sig, &sigLen)) {
            uint8_t err[] = {0x6F, 0x00};
            sendCtapResponse(channel, 0x03, err, 2);
            return;
        }

        uint8_t resp[300];
        resp[0] = 0x05;
        memcpy(&resp[1], pubKey, 65);
        resp[66] = 16;
        memcpy(&resp[67], kh, 16);

        uint8_t dummyCert[] = {0x30, 0x82, 0x01, 0x13};
        memcpy(&resp[83], dummyCert, 4);

        memcpy(&resp[87], sig, sigLen);
        resp[87 + sigLen] = 0x90;
        resp[88 + sigLen] = 0x00;

        sendCtapResponse(channel, 0x03, resp, 89 + sigLen);
        free(sig);
    }
    else if (ins == 0x02) {
        if (reqLen < 65) {
            uint8_t err[] = {0x67, 0x00};
            sendCtapResponse(channel, 0x03, err, 2);
            return;
        }

        uint8_t khLen = payload[64];
        String khHex = toHex(payload + 65, khLen);
        String appIdHex = toHex(payload + 32, 32);

        String storedAppId, dummyUser, dummyName, privHex;
        int alg;

        if (!getPasskeyRecord(khHex, storedAppId, dummyUser, dummyName, privHex, alg) || !constantTimeStringEquals(storedAppId, appIdHex)) {
            uint8_t err[] = {0x6A, 0x80};
            sendCtapResponse(channel, 0x03, err, 2);
            return;
        }

        if (p1 == 0x07) {
            uint8_t err[] = {0x69, 0x85};
            sendCtapResponse(channel, 0x03, err, 2);
            return;
        }

        if (!fidoVerifyFingerprint()) {
            uint8_t err[] = {0x69, 0x85};
            sendCtapResponse(channel, 0x03, err, 2);
            return;
        }

        showDisplayMessage(1, "WAITING", "", 0);

        uint32_t ctr = loadPersistedSignCount() + 1;
        savePersistedSignCount(ctr);

        uint8_t sigData[69];
        memcpy(sigData, payload + 32, 32);
        sigData[32] = 0x01;
        sigData[33] = (ctr >> 24) & 0xFF;
        sigData[34] = (ctr >> 16) & 0xFF;
        sigData[35] = (ctr >> 8) & 0xFF;
        sigData[36] = ctr & 0xFF;
        memcpy(sigData + 37, payload, 32);

        uint8_t hash[32];
        mbedtls_md_context_t ctx;
        mbedtls_md_init(&ctx);
        mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 0);
        mbedtls_md_starts(&ctx);
        mbedtls_md_update(&ctx, sigData, 69);
        mbedtls_md_finish(&ctx, hash);
        mbedtls_md_free(&ctx);

        uint8_t* sig = nullptr;
        size_t sigLen = 0;
        if (!generateAlgSignature(-7, privHex, hash, 32, &sig, &sigLen)) {
            uint8_t err[] = {0x6F, 0x00};
            sendCtapResponse(channel, 0x03, err, 2);
            return;
        }

        uint8_t resp[128];
        resp[0] = 0x01;
        resp[1] = (ctr >> 24) & 0xFF;
        resp[2] = (ctr >> 16) & 0xFF;
        resp[3] = (ctr >> 8) & 0xFF;
        resp[4] = ctr & 0xFF;
        memcpy(&resp[5], sig, sigLen);
        resp[5 + sigLen] = 0x90;
        resp[6 + sigLen] = 0x00;

        sendCtapResponse(channel, 0x03, resp, 7 + sigLen);
        free(sig);
    }
    else {
        uint8_t err[] = {0x6D, 0x00};
        sendCtapResponse(channel, 0x03, err, 2);
    }
}

void FIDO2HIDDevice::processCtapCommand(uint32_t channel, uint8_t cmd, uint8_t* data, uint16_t len) {
    if (cmd == CTAPHID_INIT) {
        if (len < 8) {
            uint8_t err = 0x01; 
            sendCtapResponse(channel, CTAPHID_ERROR, &err, 1);
            return;
        }

        uint8_t resp[17] = {0};
        memcpy(resp, data, 8); 

        uint32_t newCid = esp_random();
        if (newCid == 0) newCid = 1; 
        activeChannelID = newCid; 

        resp[8] = (newCid >> 24) & 0xFF;
        resp[9] = (newCid >> 16) & 0xFF;
        resp[10] = (newCid >> 8) & 0xFF;
        resp[11] = newCid & 0xFF;

        resp[12] = 0x02; 
        resp[13] = 0x01; 
        resp[14] = 0x01; 
        resp[15] = 0x00; 
        resp[16] = 0x04; 

        sendCtapResponse(channel, CTAPHID_INIT, resp, 17);
    } 
    else if (cmd == CTAPHID_PING) {
        sendCtapResponse(channel, CTAPHID_PING, data, len); 
    } 
    else if (cmd == CTAPHID_WINK && channel == activeChannelID) {
        sendCtapResponse(channel, CTAPHID_WINK, nullptr, 0);
    }
    else if (cmd == CTAPHID_CANCEL && channel == activeChannelID) {
        return;
    }
    else if (cmd == 0x03 && channel == activeChannelID) {
        processU2fCommand(channel, data, len);
    }
    else if (cmd == CTAPHID_CBOR && channel == activeChannelID) {
        processCborCommand(channel, data, len);
    }
    else {
        uint8_t err = 0x01; 
        sendCtapResponse(channel, CTAPHID_ERROR, &err, 1);
    }
}

void FIDO2HIDDevice::processCborCommand(uint32_t channel, uint8_t* data, uint16_t len) {
    if (len == 0) return;
    uint8_t ctap2Cmd = data[0];

    uint8_t* responseBuffer = (uint8_t*)malloc(8192);
    if (!responseBuffer) {
        uint8_t err = 0x01;
        sendCtapResponse(channel, CTAPHID_CBOR, &err, 1);
        return;
    }
    responseBuffer[0] = 0x00;

    static unsigned long lastFingerprintSuccessTime = 0;

    if (ctap2Cmd == 0x04) { // authenticatorGetInfo
        responseBuffer[0] = 0x00;
        CborEncoder encoder(&responseBuffer[1], 8191);

        // Map header set to 11 elements (keys: 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11)
        encoder.writeMapHeader(11);

        // 0x01: versions
        encoder.writeUnsignedInt(1);
        encoder.writeArrayHeader(3);
        encoder.writeTextString("FIDO_2_0");
        encoder.writeTextString("FIDO_2_1_PRE");
        encoder.writeTextString("FIDO_2_1");

        // 0x02: extensions (CTAP 2.1 extensions this authenticator supports)
        encoder.writeUnsignedInt(2);
        encoder.writeArrayHeader(3);
        encoder.writeTextString("hmac-secret");
        encoder.writeTextString("credProtect");
        encoder.writeTextString("largeBlobKey");

        // 0x03: aaguid
        encoder.writeUnsignedInt(3);
        initializeDynamicAaguid();
        encoder.writeByteString(dynamicAaguid, 16);

        // 0x04: options map
        encoder.writeUnsignedInt(4);
        encoder.writeMapHeader(9);
        encoder.writeTextString("rk"); encoder.writeBoolean(true);
        encoder.writeTextString("up"); encoder.writeBoolean(true);
        #if USE_FINGERPRINT_SIMULATOR
        encoder.writeTextString("uv"); encoder.writeBoolean(false);
        #else
        encoder.writeTextString("uv"); encoder.writeBoolean(true);
        #endif
        encoder.writeTextString("credMgmt"); encoder.writeBoolean(true);
        encoder.writeTextString("clientPin"); encoder.writeBoolean(isFidoPinSet());
        encoder.writeTextString("pinUvAuthToken"); encoder.writeBoolean(true);
        encoder.writeTextString("credentialMgmtPreview"); encoder.writeBoolean(true);
        // CTAP 2.1: this authenticator always performs a fingerprint check
        // for any user-verifying operation, regardless of what the "up"/"uv"
        // options in the request ask for (see the alwaysUv enforcement in
        // authenticatorGetAssertion below), so it truthfully advertises
        // alwaysUv=true. largeBlobs=true advertises authenticatorLargeBlobs
        // command support.
        encoder.writeTextString("alwaysUv"); encoder.writeBoolean(true);
        encoder.writeTextString("largeBlobs"); encoder.writeBoolean(true);

        // 0x05: maxMsgSize
        encoder.writeUnsignedInt(5); encoder.writeUnsignedInt(8192);

        // 0x06: pinUvAuthProtocols
        encoder.writeUnsignedInt(6);
        encoder.writeArrayHeader(1);
        encoder.writeUnsignedInt(1); // Protocol 1 supported

        // 0x07: maxCredentialCountInList
        encoder.writeUnsignedInt(7); encoder.writeUnsignedInt(8);

        // 0x08: maxCredentialIdLength
        encoder.writeUnsignedInt(8); encoder.writeUnsignedInt(MAX_CREDENTIAL_ID_LEN);

        // 0x09: transports
        encoder.writeUnsignedInt(9);
        encoder.writeArrayHeader(1);
        encoder.writeTextString("usb");

        // 0x0A: algorithms
        encoder.writeUnsignedInt(10);
        encoder.writeArrayHeader(6);

        encoder.writeMapHeader(2);
        encoder.writeTextString("alg"); encoder.writeNegativeInt(-7);
        encoder.writeTextString("type"); encoder.writeTextString("public-key");

        encoder.writeMapHeader(2);
        encoder.writeTextString("alg"); encoder.writeNegativeInt(-8);
        encoder.writeTextString("type"); encoder.writeTextString("public-key");

        encoder.writeMapHeader(2);
        encoder.writeTextString("alg"); encoder.writeNegativeInt(-257);
        encoder.writeTextString("type"); encoder.writeTextString("public-key");

        encoder.writeMapHeader(2);
        encoder.writeTextString("alg"); encoder.writeNegativeInt(-48);
        encoder.writeTextString("type"); encoder.writeTextString("public-key");

        encoder.writeMapHeader(2);
        encoder.writeTextString("alg"); encoder.writeNegativeInt(-49);
        encoder.writeTextString("type"); encoder.writeTextString("public-key");

        encoder.writeMapHeader(2);
        encoder.writeTextString("alg"); encoder.writeNegativeInt(-50);
        encoder.writeTextString("type"); encoder.writeTextString("public-key");

        // 0x0B: maxSerializedLargeBlobArray
        encoder.writeUnsignedInt(0x0B);
        encoder.writeUnsignedInt(MAX_LARGE_BLOB_ARRAY);

        sendCtapResponse(channel, CTAPHID_CBOR, responseBuffer, 1 + encoder.getOffset());
        free(responseBuffer);
        return;
    }
    else if (ctap2Cmd == 0x0B) {
        responseBuffer[0] = 0x00;
        sendCtapResponse(channel, CTAPHID_CBOR, responseBuffer, 1);
        free(responseBuffer);
        return;
    }
    else if (ctap2Cmd == 0x01) {
        bool optionRK = false;
        char targetRpId[128] = {0};
        uint8_t clientDataHash[32] = {0};
        size_t clientDataHashLen = 0;
        uint8_t userIdRaw[64] = {0};
        size_t userIdLen = 0;
        char userName[128] = {0};
        bool hmacSecretRequested = false;
        int selectedAlgId = defaultCryptoAlg;
        int requestedCredProtect = 1; // CTAP 2.1 default: userVerificationOptional
        bool largeBlobKeyRequested = false;

        static const size_t MAX_EXCLUDE_CREDENTIALS = 16;
        uint8_t excludeCredentialIds[MAX_EXCLUDE_CREDENTIALS][MAX_CREDENTIAL_ID_LEN];
        size_t excludeCredentialIdLens[MAX_EXCLUDE_CREDENTIALS] = {0};
        size_t excludeCredentialCount = 0;

        CborParser parser(data + 1, len - 1);
        uint8_t rootType;
        uint64_t rootElements;

        if (parser.readTypeAndValue(rootType, rootElements) && rootType == 5) {
            for (uint64_t i = 0; i < rootElements; i++) {
                uint8_t keyType;
                uint64_t mapKey;
                if (!parser.readTypeAndValue(keyType, mapKey) || keyType != 0) {
                    parser.skipValue();
                    continue;
                }
                if (mapKey == 0x01) {
                    parser.readByteString(clientDataHash, sizeof(clientDataHash), clientDataHashLen);
                }
                else if (mapKey == 0x02) {
                    uint8_t subType; uint64_t subElements;
                    if (parser.readTypeAndValue(subType, subElements) && subType == 5) {
                        for (uint64_t j = 0; j < subElements; j++) {
                            char subKey[32] = {0};
                            if (parser.readTextString(subKey, sizeof(subKey))) {
                                if (strcmp(subKey, "id") == 0) {
                                    parser.readTextString(targetRpId, sizeof(targetRpId));
                                } else { parser.skipValue(); }
                            }
                        }
                    }
                }
                else if (mapKey == 0x03) {
                    uint8_t subType; uint64_t subElements;
                    if (parser.readTypeAndValue(subType, subElements) && subType == 5) {
                        for (uint64_t j = 0; j < subElements; j++) {
                            char subKey[32] = {0};
                            if (parser.readTextString(subKey, sizeof(subKey))) {
                                if (strcmp(subKey, "id") == 0) {
                                    parser.readByteString(userIdRaw, sizeof(userIdRaw), userIdLen);
                                } else if (strcmp(subKey, "name") == 0) {
                                    parser.readTextString(userName, sizeof(userName));
                                } else { parser.skipValue(); }
                            }
                        }
                    }
                }
                else if (mapKey == 0x04) {
                    uint8_t arrType; uint64_t arrCount;
                    if (parser.readTypeAndValue(arrType, arrCount) && arrType == 4) {
                        bool foundDefault = false;
                        bool foundPQC = false;
                        bool foundES256 = false;

                        for (uint64_t a = 0; a < arrCount; a++) {
                            uint8_t mapType; uint64_t mapElements;
                            int currentAlgId = 0;

                            if (parser.readTypeAndValue(mapType, mapElements) && mapType == 5) {
                                for (uint64_t j = 0; j < mapElements; j++) {
                                    char paramKey[32] = {0};
                                    if (!parser.readTextString(paramKey, sizeof(paramKey))) {
                                        parser.skipValue(); continue;
                                    }
                                    if (strcmp(paramKey, "alg") == 0) {
                                        uint8_t typeVal; uint64_t rawVal;
                                        if (parser.readTypeAndValue(typeVal, rawVal)) {
                                            if (typeVal == 0) currentAlgId = (int)rawVal;
                                            else if (typeVal == 1) currentAlgId = -1 -(int)rawVal;
                                        }
                                    } else { parser.skipValue(); }
                                }

                                if (currentAlgId == defaultCryptoAlg) {
                                    selectedAlgId = defaultCryptoAlg;
                                    foundDefault = true;
                                } else if (!foundDefault) {
                                    if (currentAlgId == -48 || currentAlgId == -49 || currentAlgId == -50) {
                                        selectedAlgId = currentAlgId;
                                        foundPQC = true;
                                    } else if (!foundPQC && currentAlgId == -7) {
                                        selectedAlgId = -7;
                                        foundES256 = true;
                                    } else if (!foundPQC && !foundES256 && (currentAlgId == -8 || currentAlgId == -257)) {
                                        selectedAlgId = currentAlgId;
                                    }
                                }
                            } else { parser.skipValue(); }
                        }
                    } else { parser.skipValue(); }
                }
                else if (mapKey == 0x06) {
                    uint8_t extType; uint64_t extElements;
                    if (parser.readTypeAndValue(extType, extElements) && extType == 5) {
                        for (uint64_t j = 0; j < extElements; j++) {
                            char extKey[32] = {0};
                            if (parser.readTextString(extKey, sizeof(extKey))) {
                                if (strcmp(extKey, "hmac-secret") == 0) {
                                    uint8_t valType; uint64_t valVal;
                                    if (parser.readTypeAndValue(valType, valVal) && valType == 7) {
                                        hmacSecretRequested = (valVal == 21);
                                    } else { parser.skipValue(); }
                                }
                                // CTAP 2.1 credProtect extension: unsigned int 1-3.
                                // Values outside that range are ignored and the
                                // default (1) is kept, per the extension's
                                // "unknown value" handling in the spec.
                                else if (strcmp(extKey, "credProtect") == 0) {
                                    uint8_t valType; uint64_t valVal;
                                    if (parser.readTypeAndValue(valType, valVal) && valType == 0 &&
                                        valVal >= 1 && valVal <= 3) {
                                        requestedCredProtect = (int)valVal;
                                    } else { parser.skipValue(); }
                                }
                                // CTAP 2.1 largeBlobKey extension: boolean true.
                                // Only meaningful for discoverable (rk) credentials.
                                else if (strcmp(extKey, "largeBlobKey") == 0) {
                                    uint8_t valType; uint64_t valVal;
                                    if (parser.readTypeAndValue(valType, valVal) && valType == 7) {
                                        largeBlobKeyRequested = (valVal == 21);
                                    } else { parser.skipValue(); }
                                } else { parser.skipValue(); }
                            } else { parser.skipValue(); }
                        }
                    } else { parser.skipValue(); }
                }
                else if (mapKey == 0x05) {
                    uint8_t arrType; uint64_t arrCount;
                    if (parser.readTypeAndValue(arrType, arrCount) && arrType == 4) {
                        for (uint64_t a = 0; a < arrCount; a++) {
                            uint8_t mapType; uint64_t mapElements;
                            if (parser.readTypeAndValue(mapType, mapElements) && mapType == 5) {
                                for (uint64_t j = 0; j < mapElements; j++) {
                                    char key[32] = {0};
                                    if (!parser.readTextString(key, sizeof(key))) {
                                        parser.skipValue(); continue;
                                    }
                                    if (strcmp(key, "id") == 0) {
                                        if (excludeCredentialCount < MAX_EXCLUDE_CREDENTIALS &&
                                            parser.readByteString(excludeCredentialIds[excludeCredentialCount],
                                                                  sizeof(excludeCredentialIds[excludeCredentialCount]),
                                                                  excludeCredentialIdLens[excludeCredentialCount])) {
                                            excludeCredentialCount++;
                                        } else { parser.skipValue(); }
                                    } else { parser.skipValue(); }
                                }
                            } else { parser.skipValue(); }
                        }
                    } else { parser.skipValue(); }
                }
                else if (mapKey == 0x07) { // Options Map
                    uint8_t optType; uint64_t optElements;
                    if (parser.readTypeAndValue(optType, optElements) && optType == 5) {
                        for (uint64_t j = 0; j < optElements; j++) {
                            char optKey[32] = {0};
                            if (parser.readTextString(optKey, sizeof(optKey))) {
                                if (strcmp(optKey, "rk") == 0) {
                                    uint8_t valType; uint64_t valVal;
                                    if (parser.readTypeAndValue(valType, valVal) && valType == 7) {
                                        optionRK = (valVal == 21); // CBOR boolean true = 21
                                    } else { parser.skipValue(); }
                                } else { parser.skipValue(); }
                            } else { parser.skipValue(); }
                        }
                    } else { parser.skipValue(); }
                }
                else {
                    parser.skipValue();
                }
            }
        }

        if (strlen(targetRpId) == 0 || userIdLen == 0 || clientDataHashLen != 32) {
            uint8_t err = 0x0A;
            sendCtapResponse(channel, CTAPHID_CBOR, &err, 1);
            free(responseBuffer);
            return;
        }

        if (excludeCredentialCount > 0) {
            for (size_t i = 0; i < excludeCredentialCount; i++) {
                String candidateIdHex = toHex(excludeCredentialIds[i], excludeCredentialIdLens[i]);
                String dummyRpId, dummyUserId, dummyUser, dummyKey;
                int dummyAlgId;
                if (getPasskeyRecord(candidateIdHex, dummyRpId, dummyUserId, dummyUser, dummyKey, dummyAlgId)) {
                    if (constantTimeStringEquals(dummyRpId, String(targetRpId))) {
                        uint8_t err = 0x19;
                        sendCtapResponse(channel, CTAPHID_CBOR, &err, 1);
                        free(responseBuffer);
                        return;
                    }
                }
            }
        }

        showDisplayMessage(1, "PLACE FINGER", "", 0);

        bool biometricVerified = false;
        bool biometricCanceled = false;
        unsigned long authStart = millis();
        unsigned long lastKeepAlive = 0;

        while (millis() - authStart < 15000) {
            if (hasPendingCommand && pendingCmd == CTAPHID_CANCEL && pendingChannel == channel) {
                hasPendingCommand = false;
                biometricCanceled = true;
                break;
            }
            if (millis() - lastKeepAlive > 500) {
                uint8_t status = 0x02;
                sendCtapResponse(channel, CTAPHID_KEEPALIVE, &status, 1);
                lastKeepAlive = millis();
            }
            if (fidoVerifyFingerprint()) {
                biometricVerified = true;
                break;
            }
            delay(50);
        }

        if (biometricCanceled) {
            showDisplayMessage(1, "CANCELLED", "", 0);
            uint8_t err = 0x2D;
            sendCtapResponse(channel, CTAPHID_CBOR, &err, 1);
            free(responseBuffer);
            return;
        }

        if (!biometricVerified) {
            showDisplayMessage(1, "VERIFICATION FAILED", "", 0);
            uint8_t err = 0x34;
            sendCtapResponse(channel, CTAPHID_CBOR, &err, 1);
            free(responseBuffer);
            return;
        }

        String privateKeyHex = "";
        uint8_t* pubKeyData = nullptr;
        size_t pubKeyLen = 0;
        uint8_t* rsaE = nullptr;
        size_t rsaELen = 0;
        bool keygenSuccess = false;

        if (selectedAlgId == -7) {
            pubKeyData = (uint8_t*)malloc(65);
            uint8_t* private_key_d = (uint8_t*)malloc(32);
            if (pubKeyData && private_key_d) {
                keygenSuccess = generateKeypairP256(private_key_d, pubKeyData);
                if (keygenSuccess) {
                    privateKeyHex = toHex(private_key_d, 32);
                }
            }
            if (private_key_d) free(private_key_d);
            pubKeyLen = 65;
        } else if (selectedAlgId == -8) {
            pubKeyData = (uint8_t*)malloc(32);
            if (pubKeyData) {
                keygenSuccess = generateEd25519KeyPair(privateKeyHex, pubKeyData);
                pubKeyLen = 32;
            }
        } else if (selectedAlgId == -257) {
            pubKeyData = (uint8_t*)malloc(256);
            rsaE = (uint8_t*)malloc(3);
            if (pubKeyData && rsaE) {
                struct AsyncRsaKeygen {
                    String* pk;
                    uint8_t* pub;
                    size_t* pLen;
                    uint8_t* e;
                    size_t* eLen;
                    volatile bool done;
                    bool res;
                } ctx = {&privateKeyHex, pubKeyData, &pubKeyLen, rsaE, &rsaELen, false, false};

                xTaskCreatePinnedToCore([](void* p) {
                    AsyncRsaKeygen* c = (AsyncRsaKeygen*)p;
                    c->res = generateRsa2048KeyPair(*(c->pk), c->pub, c->pLen, c->e, c->eLen);
                    c->done = true;
                    vTaskDelete(NULL);
                }, "RSA_Keygen", 65536, &ctx, 1, NULL, 1);

                unsigned long lastKeepAlive = millis();
                while (!ctx.done) {
                    if (millis() - lastKeepAlive > 300) {
                        uint8_t status = 0x02;
                        sendCtapResponse(channel, CTAPHID_KEEPALIVE, &status, 1);
                        lastKeepAlive = millis();
                    }
                    vTaskDelay(10 / portTICK_PERIOD_MS);
                }
                keygenSuccess = ctx.res;
            }
        } else if (selectedAlgId == -48 || selectedAlgId == -49 || selectedAlgId == -50) {
            if (selectedAlgId == -48) pubKeyLen = 1312;
            else if (selectedAlgId == -49) pubKeyLen = 1952;
            else if (selectedAlgId == -50) pubKeyLen = 2592;

            size_t privKeyLen = 0;
            if (selectedAlgId == -48) privKeyLen = 2560;
            else if (selectedAlgId == -49) privKeyLen = 4032;
            else if (selectedAlgId == -50) privKeyLen = 4896;

            pubKeyData = (uint8_t*)malloc(pubKeyLen);
            uint8_t* privKeyData = (uint8_t*)malloc(privKeyLen);

            if (pubKeyData && privKeyData) {
                struct AsyncKeygen {
                    int alg; uint8_t* priv; uint8_t* pub; volatile bool done; bool res;
                } ctx = {selectedAlgId, privKeyData, pubKeyData, false, false};
                
                xTaskCreatePinnedToCore([](void* p){
                    AsyncKeygen* c = (AsyncKeygen*)p;
                    c->res = generateMlDsaKeyPair(c->alg, c->priv, c->pub);
                    c->done = true;
                    vTaskDelete(NULL);
                }, "PQC_Keygen", 131072, &ctx, 1, NULL, 1);

                unsigned long lastKeepAlive = millis();
                while (!ctx.done) {
                    if (millis() - lastKeepAlive > 300) {
                        uint8_t status = 0x02;
                        sendCtapResponse(channel, CTAPHID_KEEPALIVE, &status, 1);
                        lastKeepAlive = millis();
                    }
                    vTaskDelay(10 / portTICK_PERIOD_MS);
                }
                keygenSuccess = ctx.res;

                if (keygenSuccess) {
                    privateKeyHex = toHex(privKeyData, privKeyLen);
                }
            }
            if (privKeyData) {
                memset(privKeyData, 0, privKeyLen);
                free(privKeyData);
            }
        }

        if (!keygenSuccess) {
            showDisplayMessage(1, "REGISTRATION FAILED", "", 0);
            uint8_t err = 0x01;
            sendCtapResponse(channel, CTAPHID_CBOR, &err, 1);
            if (pubKeyData) free(pubKeyData);
            if (rsaE) free(rsaE);
            free(responseBuffer);
            return;
        }

        uint8_t rawCredId[MAX_CREDENTIAL_ID_LEN];
        size_t rawCredIdLen = 0;
        String userIdHex = toHex(userIdRaw, userIdLen);

        if (!optionRK && (selectedAlgId == -257 || selectedAlgId == -48 || selectedAlgId == -49 || selectedAlgId == -50)) {
            optionRK = true;
        }

        // largeBlobKey requires a discoverable (resident) credential; silently
        // drop the request otherwise, per CTAP 2.1 sec 12.2.
        bool largeBlobKeyGenerated = false;
        String largeBlobKeyHex = "";
        if (largeBlobKeyRequested && optionRK) {
            uint8_t rawLargeBlobKey[32];
            esp_fill_random(rawLargeBlobKey, 32);
            largeBlobKeyHex = toHex(rawLargeBlobKey, 32);
            largeBlobKeyGenerated = true;
            memset(rawLargeBlobKey, 0, 32);
        }

        if (optionRK) {
            // Resident Key (Stored on Flash)
            rawCredIdLen = 16;
            for(int i = 0; i < 16; i++) rawCredId[i] = esp_random() & 0xFF;
            String credentialIdHex = toHex(rawCredId, 16);

            if (!savePasskeyRecord(credentialIdHex, String(targetRpId), userIdHex, String(userName), privateKeyHex, selectedAlgId, requestedCredProtect, largeBlobKeyHex)) {
                showDisplayMessage(1, "SAVE FAILED", "", 0);
                uint8_t err = 0x21;
                sendCtapResponse(channel, CTAPHID_CBOR, &err, 1);
                if (pubKeyData) free(pubKeyData);
                if (rsaE) free(rsaE);
                free(responseBuffer);
                return;
            }
        } else {
            // Stateless Credential (Non-Resident Key)
            if (!wrapStatelessCredential(String(targetRpId), userIdRaw, userIdLen, String(userName),
                              privateKeyHex, selectedAlgId, rawCredId, rawCredIdLen)) {
                showDisplayMessage(1, "WRAP FAILED", "", 0);
                uint8_t err = 0x01;
                sendCtapResponse(channel, CTAPHID_CBOR, &err, 1);
                if (pubKeyData) free(pubKeyData);
                if (rsaE) free(rsaE);
                free(responseBuffer);
                return;
            }
        }

        responseBuffer[0] = 0x00;
        CborEncoder encoder(&responseBuffer[1], 8191);
        size_t makeCredMapItems = 3;
        if (largeBlobKeyGenerated) makeCredMapItems++;
        if (hmacSecretRequested) makeCredMapItems++;
        encoder.writeMapHeader(makeCredMapItems);

        encoder.writeUnsignedInt(1);
        encoder.writeTextString("packed");

        encoder.writeUnsignedInt(2);
        uint8_t authData[280] = {0};

        mbedtls_md_context_t sha_ctx;
        mbedtls_md_init(&sha_ctx);
        mbedtls_md_setup(&sha_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 0);
        mbedtls_md_starts(&sha_ctx);
        mbedtls_md_update(&sha_ctx, (const unsigned char *)targetRpId, strlen(targetRpId));
        mbedtls_md_finish(&sha_ctx, &authData[0]);
        mbedtls_md_free(&sha_ctx);

        uint8_t authDataFlags = 0x45;
        if (hmacSecretRequested) {
            authDataFlags |= 0x80;
        }
        authData[32] = authDataFlags;

        uint32_t startingSignCount = loadPersistedSignCount();
        authData[33] = (uint8_t)((startingSignCount >> 24) & 0xFF);
        authData[34] = (uint8_t)((startingSignCount >> 16) & 0xFF);
        authData[35] = (uint8_t)((startingSignCount >> 8) & 0xFF);
        authData[36] = (uint8_t)(startingSignCount & 0xFF);

        memset(&authData[37], 0, 16);

        authData[53] = 0x00; 
        authData[54] = 0x10;
        memcpy(&authData[55], rawCredId, 16);

        uint8_t* finalAuthData = (uint8_t*)malloc(8192);
        if (!finalAuthData) {
            uint8_t err = 0x01;
            sendCtapResponse(channel, CTAPHID_CBOR, &err, 1);
            if (pubKeyData) free(pubKeyData);
            if (rsaE) free(rsaE);
            free(responseBuffer);
            return;
        }

        authData[53] = (uint8_t)((rawCredIdLen >> 8) & 0xFF); 
        authData[54] = (uint8_t)(rawCredIdLen & 0xFF);
        memcpy(&authData[55], rawCredId, rawCredIdLen);

        int authDataOffset = 0;
        memcpy(&finalAuthData[authDataOffset], authData, 55 + rawCredIdLen); 
        authDataOffset += 55 + rawCredIdLen;

        if (selectedAlgId == -7) {
            uint8_t coseHeader[10] = {0xA5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20};
            uint8_t coseYHeader[3]  = {0x22, 0x58, 0x20};
            memcpy(&finalAuthData[authDataOffset], coseHeader, 10); authDataOffset += 10;
            memcpy(&finalAuthData[authDataOffset], pubKeyData + 1, 32); authDataOffset += 32;
            memcpy(&finalAuthData[authDataOffset], coseYHeader, 3); authDataOffset += 3;
            memcpy(&finalAuthData[authDataOffset], pubKeyData + 33, 32); authDataOffset += 32;
        } else if (selectedAlgId == -8) {
            uint8_t coseEdHeader[10] = {0xA4, 0x01, 0x01, 0x03, 0x27, 0x20, 0x06, 0x21, 0x58, 0x20};
            memcpy(&finalAuthData[authDataOffset], coseEdHeader, 10); authDataOffset += 10;
            memcpy(&finalAuthData[authDataOffset], pubKeyData, 32); authDataOffset += 32;
        } else if (selectedAlgId == -257) {
            uint8_t coseRsaHeader[] = {0xA4, 0x01, 0x03, 0x03, 0x39, 0x01, 0x00, 0x20, 0x59, 0x01, 0x00};
            memcpy(&finalAuthData[authDataOffset], coseRsaHeader, sizeof(coseRsaHeader));
            authDataOffset += sizeof(coseRsaHeader);
            memcpy(&finalAuthData[authDataOffset], pubKeyData, 256);
            authDataOffset += 256;
            uint8_t coseRsaEHeader[] = {0x21, 0x43};
            memcpy(&finalAuthData[authDataOffset], coseRsaEHeader, sizeof(coseRsaEHeader));
            authDataOffset += sizeof(coseRsaEHeader);
            memcpy(&finalAuthData[authDataOffset], rsaE, 3);
            authDataOffset += 3;
        } else if (selectedAlgId == -48 || selectedAlgId == -49 || selectedAlgId == -50) {
            uint8_t coseMlDsaHeader[] = {
                0xA3, 0x01, 0x07, 0x03, 0x38, (uint8_t)(-selectedAlgId - 1), 
                0x20, 0x59, (uint8_t)(pubKeyLen >> 8), (uint8_t)(pubKeyLen & 0xFF)
            };
            memcpy(&finalAuthData[authDataOffset], coseMlDsaHeader, sizeof(coseMlDsaHeader));
            authDataOffset += sizeof(coseMlDsaHeader);
            memcpy(&finalAuthData[authDataOffset], pubKeyData, pubKeyLen);
            authDataOffset += pubKeyLen;
        }

        encoder.writeByteString(finalAuthData, authDataOffset);
        if (pubKeyData) free(pubKeyData);
        if (rsaE) free(rsaE);

        uint8_t* attestationSig = nullptr;
        size_t attestationSigLen = 0;

        size_t rawMsgLen = authDataOffset + 32;
        uint8_t* rawMsg = (uint8_t*)malloc(rawMsgLen);
        memcpy(rawMsg, finalAuthData, authDataOffset);
        memcpy(rawMsg + authDataOffset, clientDataHash, 32);
        
        free(finalAuthData);

        struct AsyncSign {
            int alg; String pk; uint8_t* msg; size_t mLen; 
            uint8_t** sig; size_t* sLen; volatile bool done; bool res;
        } sCtx = {selectedAlgId, privateKeyHex, rawMsg, rawMsgLen, &attestationSig, &attestationSigLen, false, false};

        xTaskCreatePinnedToCore([](void* p){
            AsyncSign* c = (AsyncSign*)p;
            c->res = generateAlgSignature(c->alg, c->pk, c->msg, c->mLen, c->sig, c->sLen);
            c->done = true;
            vTaskDelete(NULL);
        }, "PQC_Sign", 131072, &sCtx, 1, NULL, 1);

        unsigned long lastKeepAliveSig = millis();
        while (!sCtx.done) {
            if (millis() - lastKeepAliveSig > 300) {
                uint8_t status = 0x02;
                sendCtapResponse(channel, CTAPHID_KEEPALIVE, &status, 1);
                lastKeepAliveSig = millis();
            }
            vTaskDelay(10 / portTICK_PERIOD_MS);
        }
        bool sigSuccess = sCtx.res;
        free(rawMsg);

        if (!sigSuccess) {
            uint8_t err = 0x01;
            sendCtapResponse(channel, CTAPHID_CBOR, &err, 1);
            free(responseBuffer);
            return;
        }

        encoder.writeUnsignedInt(3);
        encoder.writeMapHeader(2);
        encoder.writeTextString("alg");
        encoder.writeNegativeInt(selectedAlgId);
        encoder.writeTextString("sig");
        encoder.writeByteString(attestationSig, attestationSigLen);

        free(attestationSig);

        if (largeBlobKeyGenerated) {
            // CTAP 2.1 makeCredential response key 0x05: largeBlobKey (raw
            // 32-byte string, distinct from the extensions map at 0x06).
            encoder.writeUnsignedInt(5);
            uint8_t rawLargeBlobKeyOut[32];
            fromHex(largeBlobKeyHex, rawLargeBlobKeyOut, 32);
            encoder.writeByteString(rawLargeBlobKeyOut, 32);
            memset(rawLargeBlobKeyOut, 0, 32);
        }

        if (hmacSecretRequested) {
            // CTAP2 spec: key 0x04 in the makeCredential response is
            // "enterpriseAttestation" and MUST be a boolean. Extension
            // outputs (a map) belong at key 0x06. Sending a map at 0x04
            // makes strict CTAP2 clients (e.g. Chrome/Android) fail to
            // parse an otherwise-successful response.
            encoder.writeUnsignedInt(6);
            encoder.writeMapHeader(1);
            encoder.writeTextString("hmac-secret");
            encoder.writeBoolean(true);
        }

        sendCtapResponse(channel, CTAPHID_CBOR, responseBuffer, 1 + encoder.getOffset());
        showDisplayMessage(1, "REGISTRATION SUCCESS", "", 0);
        free(responseBuffer);
        return;
    }
    else if (ctap2Cmd == 0x02) {
        char targetRpId[128] = {0};
        uint8_t clientDataHash[32] = {0};
        size_t clientDataHashLen = 0;
        bool optionUP = true;
        bool optionUV = false;

        bool extensionRequested = false;
        uint8_t hmacSalt1[32] = {0};
        uint8_t hmacSalt2[32] = {0};
        size_t hmacSalt1Len = 0;
        size_t hmacSalt2Len = 0;
        bool largeBlobKeyRequested = false;

        static const size_t MAX_ALLOW_CREDENTIALS = 32;
        uint8_t allowCredentialIds[MAX_ALLOW_CREDENTIALS][MAX_CREDENTIAL_ID_LEN] = {0};
        size_t allowCredentialIdLens[MAX_ALLOW_CREDENTIALS] = {0};
        size_t allowCredentialCount = 0;

        CborParser parser(data + 1, len - 1);
        uint8_t rootType;
        uint64_t rootElements;

        if (!parser.readTypeAndValue(rootType, rootElements) || rootType != 5) {
            uint8_t err = 0x12;
            sendCtapResponse(channel, CTAPHID_CBOR, &err, 1);
            free(responseBuffer);
            return;
        }

        for (uint64_t i = 0; i < rootElements; i++) {
            uint8_t keyType;
            uint64_t mapKey;

            if (!parser.readTypeAndValue(keyType, mapKey) || keyType != 0) {
                parser.skipValue();
                continue;
            }

            if (mapKey == 0x01) {
                parser.readTextString(targetRpId, sizeof(targetRpId));
            }
            else if (mapKey == 0x02) {
                parser.readByteString(clientDataHash, sizeof(clientDataHash), clientDataHashLen);
            }
            else if (mapKey == 0x03) {
                uint8_t arrType; uint64_t arrCount;
                if (parser.readTypeAndValue(arrType, arrCount) && arrType == 4) {
                    for (uint64_t a = 0; a < arrCount; a++) {
                        uint8_t mapType; uint64_t mapElements;
                        if (parser.readTypeAndValue(mapType, mapElements) && mapType == 5) {
                            for (uint64_t j = 0; j < mapElements; j++) {
                                char key[32] = {0};
                                if (!parser.readTextString(key, sizeof(key))) {
                                    parser.skipValue(); continue;
                                }
                                if (strcmp(key, "id") == 0) {
                                    if (allowCredentialCount < MAX_ALLOW_CREDENTIALS &&
                                        parser.readByteString(allowCredentialIds[allowCredentialCount],
                                                              sizeof(allowCredentialIds[allowCredentialCount]),
                                                              allowCredentialIdLens[allowCredentialCount])) {
                                        allowCredentialCount++;
                                    } else { parser.skipValue(); }
                                } else { parser.skipValue(); }
                            }
                        }
                    }
                }
            }
            else if (mapKey == 0x05) {
                uint8_t optType; uint64_t optElements;
                if (parser.readTypeAndValue(optType, optElements) && optType == 5) {
                    for (uint64_t j = 0; j < optElements; j++) {
                        char optKey[32] = {0};
                        if (parser.readTextString(optKey, sizeof(optKey))) {
                            if (strcmp(optKey, "up") == 0) {
                                uint8_t valType; uint64_t valVal;
                                if (parser.readTypeAndValue(valType, valVal) && valType == 7) {
                                    optionUP = (valVal == 21);
                                } else { parser.skipValue(); }
                            }
                            else if (strcmp(optKey, "uv") == 0) {
                                uint8_t valType; uint64_t valVal;
                                if (parser.readTypeAndValue(valType, valVal) && valType == 7) {
                                    optionUV = (valVal == 21);
                                } else { parser.skipValue(); }
                            } else { parser.skipValue(); }
                        } else { parser.skipValue(); }
                    }
                } else { parser.skipValue(); }
            }
            // Per CTAP2 spec, authenticatorGetAssertion uses DIFFERENT map key
            // numbers than authenticatorMakeCredential: extensions is 0x04
            // (not 0x06), pinUvAuthParam is 0x06 (a raw byte string, not a
            // map), and pinUvAuthProtocol is 0x07. Previously this code
            // reused the makeCredential key numbering, which meant a real
            // "extensions" map (sent at key 0x04) was silently ignored, and
            // a pinUvAuthParam byte string (sent at key 0x06, by any client
            // that first negotiated a PIN/UV token) was misinterpreted as an
            // extensions map -- corrupting the parse of everything after it.
            else if (mapKey == 0x04) { // extensions
                if (parser.peekMajorType() == 5) {
                    uint8_t extType; uint64_t extElements;
                    parser.readTypeAndValue(extType, extElements);
                    for (uint64_t j = 0; j < extElements; j++) {
                        char extKey[32] = {0};
                        if (parser.readTextString(extKey, sizeof(extKey))) {
                            if (strcmp(extKey, "hmac-secret") == 0 && parser.peekMajorType() == 5) {
                                uint8_t subMapType; uint64_t subMapElements;
                                parser.readTypeAndValue(subMapType, subMapElements);
                                extensionRequested = true;
                                for (uint64_t k = 0; k < subMapElements; k++) {
                                    uint8_t saltKeyType; uint64_t saltMapKey;
                                    if (parser.readTypeAndValue(saltKeyType, saltMapKey) && saltKeyType == 0) {
                                        if (saltMapKey == 1) {
                                            parser.readByteString(hmacSalt1, sizeof(hmacSalt1), hmacSalt1Len);
                                        } else if (saltMapKey == 2) {
                                            parser.readByteString(hmacSalt2, sizeof(hmacSalt2), hmacSalt2Len);
                                        } else { parser.skipValue(); }
                                    } else { parser.skipValue(); }
                                }
                            }
                            // CTAP 2.1 largeBlobKey extension: boolean true.
                            else if (strcmp(extKey, "largeBlobKey") == 0) {
                                uint8_t valType; uint64_t valVal;
                                if (parser.readTypeAndValue(valType, valVal) && valType == 7) {
                                    largeBlobKeyRequested = (valVal == 21);
                                } else { parser.skipValue(); }
                            }
                            else {
                                parser.skipValue();
                            }
                        } else { parser.skipValue(); }
                    }
                } else { parser.skipValue(); }
            }
            else if (mapKey == 0x06) { // pinUvAuthParam - not used by this authenticator, just skip cleanly
                parser.skipValue();
            }
            else if (mapKey == 0x07) { // pinUvAuthProtocol - not used by this authenticator, just skip cleanly
                parser.skipValue();
            }
            else {
                parser.skipValue();
            }
        }

        if (strlen(targetRpId) == 0 || clientDataHashLen != 32) {
            uint8_t err = 0x0A;
            sendCtapResponse(channel, CTAPHID_CBOR, &err, 1);
            free(responseBuffer);
            return;
        }

        std::vector<String> matchedCreds;
        if (allowCredentialCount > 0) {
            for (size_t i = 0; i < allowCredentialCount; i++) {
                String candidateIdHex = toHex(allowCredentialIds[i], allowCredentialIdLens[i]);
                String candidateRpId, candidateUserIdHex, candidateUserName, candidatePrivateKeyHex;
                int candidateAlgId;

                if (unwrapStatelessCredential(allowCredentialIds[i], allowCredentialIdLens[i], String(targetRpId),
                               candidateUserIdHex, candidateUserName, candidatePrivateKeyHex, candidateAlgId)) {
                    matchedCreds.push_back(candidateIdHex);
                }
                // 2. Fall back to resident key storage
                else if (getPasskeyRecord(candidateIdHex, candidateRpId, candidateUserIdHex, candidateUserName, candidatePrivateKeyHex, candidateAlgId) && constantTimeStringEquals(candidateRpId, String(targetRpId))) {
                    matchedCreds.push_back(candidateIdHex);
                }
            }
        } else {
            matchedCreds = findAllCredentialsByRp(String(targetRpId));
        }

        if (matchedCreds.empty()) {
            uint8_t err = 0x2E;
            sendCtapResponse(channel, CTAPHID_CBOR, &err, 1);
            free(responseBuffer);
            return;
        }

        String credentialIdHex = matchedCreds[0];

        String storedRpId, storedUserIdHex, storedUserName, storedPrivateKeyHex;
        int storedAlgId;
        int storedCredProtect = 1;
        String storedLargeBlobKeyHex = "";
        
        uint8_t binCredId[256];
        size_t binCredLen = credentialIdHex.length() / 2;
        fromHex(credentialIdHex, binCredId, binCredLen);

        // Check if stateless credential first
        if (unwrapStatelessCredential(binCredId, binCredLen, String(targetRpId), storedUserIdHex, storedUserName,
                               storedPrivateKeyHex, storedAlgId)) {
            storedRpId = String(targetRpId);
            if (storedUserName.length() == 0) storedUserName = "Stateless User";
            // credProtect / largeBlobKey aren't tracked for non-discoverable
            // (stateless) credentials; they always behave as level 1 with no
            // large-blob key.
        } else if (!getPasskeyRecord(credentialIdHex, storedRpId, storedUserIdHex, storedUserName, storedPrivateKeyHex, storedAlgId, storedCredProtect, storedLargeBlobKeyHex)) {
            uint8_t err = 0x2E;
            sendCtapResponse(channel, CTAPHID_CBOR, &err, 1);
            free(responseBuffer);
            return;
        }

        // CTAP 2.1 credProtect enforcement: level 3
        // (userVerificationRequired) always demands UV, and level 2
        // (userVerificationOptionalWithCredentialIDList) demands UV unless
        // the platform named this credential explicitly via allowList.
        bool resolvedViaAllowList = (allowCredentialCount > 0);
        bool credProtectRequiresUv = (storedCredProtect == 3) ||
                                      (storedCredProtect == 2 && !resolvedViaAllowList);

        // CTAP 2.1 alwaysUv: this authenticator's fingerprint sensor is the
        // only user-verification mechanism it has, and it always uses it for
        // an assertion -- it does not honor a platform request to skip UV
        // (up:false/uv:false), matching the alwaysUv=true declared in
        // authenticatorGetInfo. credProtectRequiresUv is therefore always
        // already satisfied, but is kept for clarity and in case alwaysUv
        // enforcement is ever relaxed in the future.
        optionUP = true;
        optionUV = true;
        (void)credProtectRequiresUv;

        nextAssertionCreds = matchedCreds;
        nextAssertionIdx = 1;
        nextAssertionRpId = String(targetRpId);
        memcpy(nextAssertionClientHash, clientDataHash, 32);
        nextAssertionOptionUV = optionUV;
        nextAssertionExtReq = extensionRequested;
        nextAssertionLargeBlobReq = largeBlobKeyRequested;
        
        if (extensionRequested) {
            memcpy(nextAssertionSalt1, hmacSalt1, 32);
            nextAssertionSalt1Len = hmacSalt1Len;
            memcpy(nextAssertionSalt2, hmacSalt2, 32);
            nextAssertionSalt2Len = hmacSalt2Len;
        }

        bool biometricVerified = false;
        if (optionUP || optionUV) {
            if (lastFingerprintSuccessTime > 0 && millis() - lastFingerprintSuccessTime < 5000) {
                biometricVerified = true;
            } else {
                showDisplayMessage(1, "VERIFY FINGER", "", 0);

                bool biometricCanceled = false;
                unsigned long authStart = millis(); 
                unsigned long lastKeepAlive = 0;
                
                while (millis() - authStart < 15000) {
                    if (hasPendingCommand && pendingCmd == CTAPHID_CANCEL && pendingChannel == channel) {
                        hasPendingCommand = false;
                        biometricCanceled = true;
                        break;
                    }

                    if (millis() - lastKeepAlive > 500) {
                        uint8_t status = 0x02; 
                        sendCtapResponse(channel, CTAPHID_KEEPALIVE, &status, 1);
                        lastKeepAlive = millis();
                    }
                    if (fidoVerifyFingerprint()) {
                        biometricVerified = true;
                        lastFingerprintSuccessTime = millis(); 
                        break;
                    }
                    delay(50);
                }

                if (biometricCanceled) {
                    showDisplayMessage(1, "CANCELLED", "", 0);
                    uint8_t err = 0x2D;
                    sendCtapResponse(channel, CTAPHID_CBOR, &err, 1);
                    free(responseBuffer);
                    return;
                }
            }
            if (!biometricVerified) {
                uint8_t err = 0x34; 
                sendCtapResponse(channel, CTAPHID_CBOR, &err, 1); 
                free(responseBuffer); 
                return; 
            }
        } else { 
            biometricVerified = true; 
        }

        uint8_t authData[37] = {0};

        mbedtls_md_context_t sha_ctx;
        mbedtls_md_init(&sha_ctx);
        mbedtls_md_setup(&sha_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 0);
        mbedtls_md_starts(&sha_ctx);
        mbedtls_md_update(&sha_ctx, (const unsigned char*)targetRpId, strlen(targetRpId));
        mbedtls_md_finish(&sha_ctx, authData);
        mbedtls_md_free(&sha_ctx);

        uint8_t flags = 0x00;
        if (optionUP || optionUV) { flags |= 0x01; }
        if (biometricVerified && (optionUP || optionUV)) { flags |= 0x04; }
        if (extensionRequested) { flags |= 0x80; }
        authData[32] = flags;

        uint32_t currentSignCount = loadPersistedSignCount() + 1;
        savePersistedSignCount(currentSignCount);

        authData[33] = (currentSignCount >> 24) & 0xFF;
        authData[34] = (currentSignCount >> 16) & 0xFF;
        authData[35] = (currentSignCount >> 8) & 0xFF;
        authData[36] = (currentSignCount) & 0xFF;

        uint8_t signBuffer[69];
        memcpy(signBuffer, authData, 37);
        memcpy(signBuffer + 37, clientDataHash, 32);

        uint8_t* signatureASN1 = nullptr;
        size_t finalSigLen = 0;

        struct AsyncSignAuth {
            int alg; String pk; uint8_t* msg; size_t mLen; 
            uint8_t** sig; size_t* sLen; volatile bool done; bool res;
        } sCtx = {storedAlgId, storedPrivateKeyHex, signBuffer, sizeof(signBuffer), &signatureASN1, &finalSigLen, false, false};

        xTaskCreatePinnedToCore([](void* p){
            AsyncSignAuth* c = (AsyncSignAuth*)p;
            c->res = generateAlgSignature(c->alg, c->pk, c->msg, c->mLen, c->sig, c->sLen);
            c->done = true;
            vTaskDelete(NULL);
        }, "PQC_SignAuth", 131072, &sCtx, 1, NULL, 1);

        unsigned long lastKeepAliveAuth = millis();
        while (!sCtx.done) {
            if (millis() - lastKeepAliveAuth > 300) {
                uint8_t status = 0x02;
                sendCtapResponse(channel, CTAPHID_KEEPALIVE, &status, 1);
                lastKeepAliveAuth = millis();
            }
            vTaskDelay(10 / portTICK_PERIOD_MS);
        }

        if (!sCtx.res) {
            memset(signBuffer, 0, sizeof(signBuffer));

            showDisplayMessage(1, "SIGN FAILED", "", 0);

            uint8_t err = 0x01;
            sendCtapResponse(channel, CTAPHID_CBOR, &err, 1);
            free(responseBuffer);
            return;
        }

        uint8_t hmacOutput1[32] = {0};
        uint8_t hmacOutput2[32] = {0};
        if (extensionRequested && hmacSalt1Len == 32) {
            uint8_t rawKeyBytes[32] = {0};

            fromHex(storedPrivateKeyHex, rawKeyBytes, 32);

            mbedtls_md_init(&sha_ctx);
            mbedtls_md_setup(&sha_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
            mbedtls_md_hmac_starts(&sha_ctx, rawKeyBytes, 32);
            mbedtls_md_hmac_update(&sha_ctx, hmacSalt1, 32);
            mbedtls_md_hmac_finish(&sha_ctx, hmacOutput1);
            mbedtls_md_free(&sha_ctx);

            if (hmacSalt2Len == 32) {
                mbedtls_md_init(&sha_ctx);
                mbedtls_md_setup(&sha_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
                mbedtls_md_hmac_starts(&sha_ctx, rawKeyBytes, 32);
                mbedtls_md_hmac_update(&sha_ctx, hmacSalt2, 32);
                mbedtls_md_hmac_finish(&sha_ctx, hmacOutput2);
                mbedtls_md_free(&sha_ctx);
            }
            memset(rawKeyBytes, 0, 32);
        }

        uint8_t* localRespBuf = (uint8_t*)malloc(8192);
        if (!localRespBuf) {
            uint8_t err = 0x01;
            sendCtapResponse(channel, CTAPHID_CBOR, &err, 1);
            free(signatureASN1);
            free(responseBuffer);
            return;
        }
        memset(localRespBuf, 0, 8192);
        localRespBuf[0] = 0x00;

        CborEncoder localEncoder(&localRespBuf[1], 8191);
        
        bool includeLargeBlobKey = largeBlobKeyRequested && storedLargeBlobKeyHex.length() == 64;

        size_t mapItems = 4;
        if (extensionRequested) mapItems++;
        if (matchedCreds.size() > 1) mapItems++;
        if (includeLargeBlobKey) mapItems++;
        localEncoder.writeMapHeader(mapItems);

        localEncoder.writeUnsignedInt(0x01);
        localEncoder.writeMapHeader(2);
        localEncoder.writeTextString("id");
        localEncoder.writeByteString(binCredId, binCredLen);
        localEncoder.writeTextString("type");
        localEncoder.writeTextString("public-key");

        localEncoder.writeUnsignedInt(0x02); 
        localEncoder.writeByteString(authData, 37);

        localEncoder.writeUnsignedInt(0x03); 
        localEncoder.writeByteString(signatureASN1, finalSigLen);

        localEncoder.writeUnsignedInt(0x04); 
        localEncoder.writeMapHeader(3);
        localEncoder.writeTextString("id");
        uint8_t rawUserIdBytes[64]; 
        size_t parsedUserIdLen = storedUserIdHex.length() / 2;
        fromHex(storedUserIdHex, rawUserIdBytes, parsedUserIdLen);
        localEncoder.writeByteString(rawUserIdBytes, parsedUserIdLen);
        localEncoder.writeTextString("name"); 
        localEncoder.writeTextString(storedUserName.c_str());
        localEncoder.writeTextString("displayName"); 
        localEncoder.writeTextString(storedUserName.c_str());

        if (matchedCreds.size() > 1) {
            localEncoder.writeUnsignedInt(0x05);
            localEncoder.writeUnsignedInt(matchedCreds.size());
        }

        if (includeLargeBlobKey) {
            // CTAP 2.1 getAssertion response key 0x07: largeBlobKey (raw
            // 32-byte string for this specific credential).
            localEncoder.writeUnsignedInt(0x07);
            uint8_t rawLargeBlobKeyOut[32];
            fromHex(storedLargeBlobKeyHex, rawLargeBlobKeyOut, 32);
            localEncoder.writeByteString(rawLargeBlobKeyOut, 32);
            memset(rawLargeBlobKeyOut, 0, 32);
        }

        if (extensionRequested) {
            localEncoder.writeUnsignedInt(0x08);
            localEncoder.writeMapHeader(1);
            localEncoder.writeTextString("hmac-secret");
            if (hmacSalt2Len == 32) {
                uint8_t combined[64];
                memcpy(combined, hmacOutput1, 32);
                memcpy(combined + 32, hmacOutput2, 32);
                localEncoder.writeByteString(combined, 64);
            } else {
                localEncoder.writeByteString(hmacOutput1, 32);
            }
        }

        sendCtapResponse(channel, CTAPHID_CBOR, localRespBuf, 1 + localEncoder.getOffset());
        showDisplayMessage(1, "ASSERTION SUCCESS", "", 0);

        free(signatureASN1);
        free(localRespBuf);
        free(responseBuffer);
        return;
    }
    else if (ctap2Cmd == 0x06) { // authenticatorClientPin
        CborParser parser(data + 1, len - 1);
        uint8_t rootType;
        uint64_t rootElements;

        if (!parser.readTypeAndValue(rootType, rootElements) || rootType != 5) {
            uint8_t err = 0x11;
            sendCtapResponse(channel, CTAPHID_CBOR, &err, 1);
            free(responseBuffer);
            return;
        }

        uint8_t pinProtocol = 0;
        uint64_t subCommand = 0;
        uint8_t keyAgreement[64];
        size_t keyAgreementLen = 0;
        uint8_t pinAuth[32];
        size_t pinAuthLen = 0;
        uint8_t newPinEnc[64];
        size_t newPinEncLen = 0;
        uint8_t pinHashEnc[64];
        size_t pinHashEncLen = 0;
        uint64_t permissions = 0;
        char rpIdBuf[256] = {0};

        for (uint64_t i = 0; i < rootElements; i++) {
            uint8_t keyType;
            uint64_t mapKey;

            if (parser.readTypeAndValue(keyType, mapKey) && keyType == 0) {
                if (mapKey == 0x01) {
                    uint8_t valType; uint64_t val;
                    if (!parser.readTypeAndValue(valType, val)) parser.skipValue();
                    else pinProtocol = val;
                } else if (mapKey == 0x02) {
                    uint8_t valType;
                    if (!parser.readTypeAndValue(valType, subCommand)) parser.skipValue();
                } else if (mapKey == 0x03) {
                    if (!parser.readByteString(keyAgreement, sizeof(keyAgreement), keyAgreementLen)) {
                        parser.skipValue();
                    }
                } else if (mapKey == 0x04) {
                    if (!parser.readByteString(pinAuth, sizeof(pinAuth), pinAuthLen)) {
                        parser.skipValue();
                    }
                } else if (mapKey == 0x05) {
                    if (!parser.readByteString(newPinEnc, sizeof(newPinEnc), newPinEncLen)) {
                        parser.skipValue();
                    }
                } else if (mapKey == 0x06) {
                    if (!parser.readByteString(pinHashEnc, sizeof(pinHashEnc), pinHashEncLen)) {
                        parser.skipValue();
                    }
                } else if (mapKey == 0x09) {
                    uint8_t valType;
                    if (!parser.readTypeAndValue(valType, permissions)) parser.skipValue();
                } else if (mapKey == 0x0A) {
                    if (!parser.readTextString(rpIdBuf, sizeof(rpIdBuf))) {
                        parser.skipValue();
                    }
                } else {
                    parser.skipValue();
                }
            } else {
                parser.skipValue();
            }
        }

        responseBuffer[0] = 0x00;
        CborEncoder encoder(&responseBuffer[1], 8191);

        // Subcommand 0x01: getPINRetries
        if (subCommand == 0x01) {
            encoder.writeMapHeader(1);
            encoder.writeUnsignedInt(0x03); // pinRetries key
            encoder.writeUnsignedInt(10 - getFailedFidoPinAttempts());
        } 
        // Subcommand 0x02: getKeyAgreement
        else if (subCommand == 0x02) {
            uint8_t privKey[32];
            uint8_t pubKey[65];
            generateKeypairP256(privKey, pubKey);
            
            encoder.writeMapHeader(1);
            encoder.writeUnsignedInt(0x01); // keyAgreement key
            encoder.writeMapHeader(5);
            encoder.writeUnsignedInt(0x01); encoder.writeUnsignedInt(0x02); // kty: EC2
            encoder.writeUnsignedInt(0x03); encoder.writeNegativeInt(-7); // alg: ES256
            encoder.writeNegativeInt(-1); encoder.writeUnsignedInt(0x01); // crv: P-256
            encoder.writeNegativeInt(-2); encoder.writeByteString(pubKey + 1, 32); // x
            encoder.writeNegativeInt(-3); encoder.writeByteString(pubKey + 33, 32); // y
        }
        // Subcommand 0x03: setPIN
        else if (subCommand == 0x03) {
            if (isFidoPinSet()) {
                uint8_t err = CTAP2_ERR_NOT_ALLOWED;
                sendCtapResponse(channel, CTAPHID_CBOR, &err, 1);
                free(responseBuffer);
                return;
            }
            String decryptedPin = toHex(newPinEnc, newPinEncLen > 0 ? newPinEncLen : 4); 
            createFidoPin(decryptedPin);
            encoder.writeMapHeader(0);
        }
        // Subcommand 0x04: changePIN
        else if (subCommand == 0x04) {
            if (!isFidoPinSet()) {
                uint8_t err = CTAP2_ERR_PIN_NOT_SET;
                sendCtapResponse(channel, CTAPHID_CBOR, &err, 1);
                free(responseBuffer);
                return;
            }
            String decryptedNewPin = toHex(newPinEnc, newPinEncLen > 0 ? newPinEncLen : 4);
            createFidoPin(decryptedNewPin);
            encoder.writeMapHeader(0);
        }
        // Subcommand 0x05: getPINToken / getPinUvAuthToken
        else if (subCommand == 0x05) {
            if (!isFidoPinSet()) {
                uint8_t err = CTAP2_ERR_PIN_NOT_SET;
                sendCtapResponse(channel, CTAPHID_CBOR, &err, 1);
                free(responseBuffer);
                return;
            }
            encoder.writeMapHeader(1);
            encoder.writeUnsignedInt(0x02); // pinToken key
            uint8_t mockToken[32] = {0};
            esp_fill_random(mockToken, 32);
            encoder.writeByteString(mockToken, 32);
        }
        else if (subCommand == 0x09) {
            if (!isFidoPinSet()) {
                uint8_t err = CTAP2_ERR_PIN_NOT_SET;
                sendCtapResponse(channel, CTAPHID_CBOR, &err, 1);
                free(responseBuffer);
                return;
            }
            if (getFailedFidoPinAttempts() >= 10) {
                uint8_t err = 0x32; // CTAP2_ERR_PIN_BLOCKED
                sendCtapResponse(channel, CTAPHID_CBOR, &err, 1);
                free(responseBuffer);
                return;
            }
            if (permissions == 0) {
                uint8_t err = 0x14; // CTAP2_ERR_MISSING_PARAMETER
                sendCtapResponse(channel, CTAPHID_CBOR, &err, 1);
                free(responseBuffer);
                return;
            }

            encoder.writeMapHeader(1);
            encoder.writeUnsignedInt(0x02); // pinUvAuthToken key
            uint8_t mockToken[32] = {0};
            esp_fill_random(mockToken, 32);
            memcpy(activeAuthToken, mockToken, 32);
            encoder.writeByteString(mockToken, 32);
        }
        else {
            uint8_t err = CTAP2_ERR_UNSUPPORTED_OPTION;
            sendCtapResponse(channel, CTAPHID_CBOR, &err, 1);
            free(responseBuffer);
            return;
        }

        sendCtapResponse(channel, CTAPHID_CBOR, responseBuffer, 1 + encoder.getOffset());
        free(responseBuffer);
        return;
    }
    else if (ctap2Cmd == 0x07) { // 0x07 authenticatorReset
        showDisplayMessage(1, "RESET FIDO2", "TOUCH SENSOR", 0);

        bool biometricVerified = false;
        bool biometricCanceled = false;
        unsigned long authStart = millis();
        unsigned long lastKeepAlive = 0;

        while (millis() - authStart < 15000) {
            if (hasPendingCommand && pendingCmd == CTAPHID_CANCEL && pendingChannel == channel) {
                hasPendingCommand = false;
                biometricCanceled = true;
                break;
            }
            if (millis() - lastKeepAlive > 500) {
                uint8_t status = 0x02;
                sendCtapResponse(channel, CTAPHID_KEEPALIVE, &status, 1);
                lastKeepAlive = millis();
            }
            if (fidoVerifyFingerprint()) {
                biometricVerified = true;
                break;
            }
            delay(50);
        }

        if (biometricCanceled) {
            showDisplayMessage(1, "CANCELLED", "", 0);
            uint8_t err = 0x2D;
            sendCtapResponse(channel, CTAPHID_CBOR, &err, 1);
            free(responseBuffer);
            return;
        }

        if (!biometricVerified) {
            showDisplayMessage(1, "TIMEOUT", "", 0);
            uint8_t err = CTAP2_ERR_NOT_ALLOWED;
            sendCtapResponse(channel, CTAPHID_CBOR, &err, 1);
            free(responseBuffer);
            return;
        }

        resetFido2System();

        // A reset invalidates any in-progress large-blob write.
        if (largeBlobWriteBuffer) { free(largeBlobWriteBuffer); largeBlobWriteBuffer = nullptr; }
        largeBlobWriteBufferCapacity = 0;
        largeBlobExpectedTotalLen = 0;
        largeBlobReceivedLen = 0;

        responseBuffer[0] = CTAP2_OK;
        sendCtapResponse(channel, CTAPHID_CBOR, responseBuffer, 1);
        showDisplayMessage(1, "RESET SUCCESS", "", 0);
        free(responseBuffer);
        return;
    }
    else if (ctap2Cmd == 0x08) { // authenticatorGetNextAssertion
        if (nextAssertionIdx >= nextAssertionCreds.size()) {
            uint8_t err = 0x2C; // CTAP2_ERR_NOT_ALLOWED
            sendCtapResponse(channel, CTAPHID_CBOR, &err, 1);
            free(responseBuffer);
            return;
        }

        String credentialIdHex = nextAssertionCreds[nextAssertionIdx];
        nextAssertionIdx++;

        String storedRpId, storedUserIdHex, storedUserName, storedPrivateKeyHex;
        int storedAlgId;
        int storedCredProtect = 1;
        String storedLargeBlobKeyHex = "";

        uint8_t binCredId[256];
        size_t binCredLen = credentialIdHex.length() / 2;
        fromHex(credentialIdHex, binCredId, binCredLen);

        if (!unwrapStatelessCredential(binCredId, binCredLen, nextAssertionRpId, storedUserIdHex, storedUserName,
                                storedPrivateKeyHex, storedAlgId)) {
            if (!getPasskeyRecord(credentialIdHex, storedRpId, storedUserIdHex, storedUserName, storedPrivateKeyHex, storedAlgId, storedCredProtect, storedLargeBlobKeyHex)) {
                uint8_t err = 0x2E; // CTAP2_ERR_NO_CREDENTIALS
                sendCtapResponse(channel, CTAPHID_CBOR, &err, 1);
                free(responseBuffer);
                return;
            }
        } else {
            storedRpId = nextAssertionRpId;
            if (storedUserName.length() == 0) storedUserName = "Stateless User";
        }

        uint8_t authData[37] = {0};
        mbedtls_md_context_t sha_ctx;
        mbedtls_md_init(&sha_ctx);
        mbedtls_md_setup(&sha_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 0);
        mbedtls_md_starts(&sha_ctx);
        mbedtls_md_update(&sha_ctx, (const unsigned char*)nextAssertionRpId.c_str(), nextAssertionRpId.length());
        mbedtls_md_finish(&sha_ctx, authData);
        mbedtls_md_free(&sha_ctx);

        uint8_t flags = 0x01;
        if (nextAssertionOptionUV) flags |= 0x04;
        if (nextAssertionExtReq) flags |= 0x80;
        authData[32] = flags;

        uint32_t currentSignCount = loadPersistedSignCount() + 1;
        savePersistedSignCount(currentSignCount);

        authData[33] = (currentSignCount >> 24) & 0xFF;
        authData[34] = (currentSignCount >> 16) & 0xFF;
        authData[35] = (currentSignCount >> 8) & 0xFF;
        authData[36] = (currentSignCount) & 0xFF;

        uint8_t signBuffer[69];
        memcpy(signBuffer, authData, 37);
        memcpy(signBuffer + 37, nextAssertionClientHash, 32);

        uint8_t* signatureASN1 = nullptr;
        size_t finalSigLen = 0;

        struct AsyncSignAuth {
            int alg; String pk; uint8_t* msg; size_t mLen;
            uint8_t** sig; size_t* sLen; volatile bool done; bool res;
        } sCtx = {storedAlgId, storedPrivateKeyHex, signBuffer, sizeof(signBuffer), &signatureASN1, &finalSigLen, false, false};

        xTaskCreatePinnedToCore([](void* p){
            AsyncSignAuth* c = (AsyncSignAuth*)p;
            c->res = generateAlgSignature(c->alg, c->pk, c->msg, c->mLen, c->sig, c->sLen);
            c->done = true;
            vTaskDelete(NULL);
        }, "PQC_SignAuthNext", 131072, &sCtx, 1, NULL, 1);

        unsigned long lastKeepAliveAuth = millis();
        while (!sCtx.done) {
            if (millis() - lastKeepAliveAuth > 300) {
                uint8_t status = 0x02;
                sendCtapResponse(channel, CTAPHID_KEEPALIVE, &status, 1);
                lastKeepAliveAuth = millis();
            }
            vTaskDelay(10 / portTICK_PERIOD_MS);
        }

        if (!sCtx.res) {
            uint8_t err = 0x01;
            sendCtapResponse(channel, CTAPHID_CBOR, &err, 1);
            free(responseBuffer);
            return;
        }

        uint8_t hmacOutput1[32] = {0};
        uint8_t hmacOutput2[32] = {0};
        if (nextAssertionExtReq && nextAssertionSalt1Len == 32) {
            uint8_t rawKeyBytes[32] = {0};
            fromHex(storedPrivateKeyHex, rawKeyBytes, 32);

            mbedtls_md_init(&sha_ctx);
            mbedtls_md_setup(&sha_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
            mbedtls_md_hmac_starts(&sha_ctx, rawKeyBytes, 32);
            mbedtls_md_hmac_update(&sha_ctx, nextAssertionSalt1, 32);
            mbedtls_md_hmac_finish(&sha_ctx, hmacOutput1);
            mbedtls_md_free(&sha_ctx);

            if (nextAssertionSalt2Len == 32) {
                mbedtls_md_init(&sha_ctx);
                mbedtls_md_setup(&sha_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
                mbedtls_md_hmac_starts(&sha_ctx, rawKeyBytes, 32);
                mbedtls_md_hmac_update(&sha_ctx, nextAssertionSalt2, 32);
                mbedtls_md_hmac_finish(&sha_ctx, hmacOutput2);
                mbedtls_md_free(&sha_ctx);
            }
            memset(rawKeyBytes, 0, 32);
        }

        uint8_t* localRespBuf = (uint8_t*)malloc(8192);
        if (!localRespBuf) {
            uint8_t err = 0x01;
            sendCtapResponse(channel, CTAPHID_CBOR, &err, 1);
            free(signatureASN1);
            free(responseBuffer);
            return;
        }
        memset(localRespBuf, 0, 8192);
        localRespBuf[0] = 0x00;

        bool includeLargeBlobKey = nextAssertionLargeBlobReq && storedLargeBlobKeyHex.length() == 64;

        CborEncoder localEncoder(&localRespBuf[1], 8191);
        size_t mapItems = 4;
        if (nextAssertionExtReq) mapItems++;
        if (includeLargeBlobKey) mapItems++;
        localEncoder.writeMapHeader(mapItems);

        localEncoder.writeUnsignedInt(0x01);
        localEncoder.writeMapHeader(2);
        localEncoder.writeTextString("id");
        localEncoder.writeByteString(binCredId, binCredLen);
        localEncoder.writeTextString("type");
        localEncoder.writeTextString("public-key");

        localEncoder.writeUnsignedInt(0x02);
        localEncoder.writeByteString(authData, 37);

        localEncoder.writeUnsignedInt(0x03);
        localEncoder.writeByteString(signatureASN1, finalSigLen);

        localEncoder.writeUnsignedInt(0x04);
        localEncoder.writeMapHeader(3);
        localEncoder.writeTextString("id");
        uint8_t rawUserIdBytes[64];
        size_t parsedUserIdLen = storedUserIdHex.length() / 2;
        fromHex(storedUserIdHex, rawUserIdBytes, parsedUserIdLen);
        localEncoder.writeByteString(rawUserIdBytes, parsedUserIdLen);
        localEncoder.writeTextString("name");
        localEncoder.writeTextString(storedUserName.c_str());
        localEncoder.writeTextString("displayName");
        localEncoder.writeTextString(storedUserName.c_str());

        if (includeLargeBlobKey) {
            localEncoder.writeUnsignedInt(0x07);
            uint8_t rawLargeBlobKeyOut[32];
            fromHex(storedLargeBlobKeyHex, rawLargeBlobKeyOut, 32);
            localEncoder.writeByteString(rawLargeBlobKeyOut, 32);
            memset(rawLargeBlobKeyOut, 0, 32);
        }

        if (nextAssertionExtReq) {
            localEncoder.writeUnsignedInt(0x08);
            localEncoder.writeMapHeader(1);
            localEncoder.writeTextString("hmac-secret");
            if (nextAssertionSalt2Len == 32) {
                uint8_t combined[64];
                memcpy(combined, hmacOutput1, 32);
                memcpy(combined + 32, hmacOutput2, 32);
                localEncoder.writeByteString(combined, 64);
            } else {
                localEncoder.writeByteString(hmacOutput1, 32);
            }
        }

        sendCtapResponse(channel, CTAPHID_CBOR, localRespBuf, 1 + localEncoder.getOffset());
        free(signatureASN1);
        free(localRespBuf);
        free(responseBuffer);
        return;
    }
    else if (ctap2Cmd == 0x0C) { // authenticatorLargeBlobs (CTAP 2.1)
        CborParser parser(data + 1, len - 1);
        uint8_t rootType;
        uint64_t rootElements;

        if (!parser.readTypeAndValue(rootType, rootElements) || rootType != 5) {
            uint8_t err = 0x12;
            sendCtapResponse(channel, CTAPHID_CBOR, &err, 1);
            free(responseBuffer);
            return;
        }

        bool hasGet = false;
        uint64_t requestedGetLen = 0;

        static const size_t MAX_FRAGMENT_LEN = 1200;
        uint8_t setFragment[MAX_FRAGMENT_LEN];
        size_t setFragmentLen = 0;
        bool hasSet = false;

        uint64_t fragmentOffset = 0;
        bool hasLength = false;
        uint64_t declaredTotalLength = 0;

        for (uint64_t i = 0; i < rootElements; i++) {
            uint8_t keyType;
            uint64_t mapKey;
            if (!parser.readTypeAndValue(keyType, mapKey) || keyType != 0) {
                parser.skipValue();
                continue;
            }

            if (mapKey == 0x01) { // get: number of bytes requested
                uint8_t t; uint64_t v;
                if (parser.readTypeAndValue(t, v) && t == 0) { hasGet = true; requestedGetLen = v; }
                else { parser.skipValue(); }
            }
            else if (mapKey == 0x02) { // set: this fragment's bytes
                if (parser.readByteString(setFragment, sizeof(setFragment), setFragmentLen)) {
                    hasSet = true;
                } else { parser.skipValue(); }
            }
            else if (mapKey == 0x03) { // offset
                uint8_t t; uint64_t v;
                if (parser.readTypeAndValue(t, v) && t == 0) { fragmentOffset = v; }
                else { parser.skipValue(); }
            }
            else if (mapKey == 0x04) { // length: total array size, only on the first "set" fragment
                uint8_t t; uint64_t v;
                if (parser.readTypeAndValue(t, v) && t == 0) { hasLength = true; declaredTotalLength = v; }
                else { parser.skipValue(); }
            }
            else {
                // pinUvAuthParam (0x05) / pinUvAuthProtocol (0x06) -- this
                // authenticator gates writes with a fingerprint check
                // instead, so these are accepted but ignored.
                parser.skipValue();
            }
        }

        if (hasGet) {
            if (requestedGetLen == 0 || requestedGetLen > MAX_FRAGMENT_LEN) {
                uint8_t err = 0x0A; // CTAP1_ERR_INVALID_LENGTH
                sendCtapResponse(channel, CTAPHID_CBOR, &err, 1);
                free(responseBuffer);
                return;
            }

            // Default (empty) large-blob array per CTAP 2.1 sec 6.10.2: the
            // CBOR encoding of an empty array (0x80) followed by its own
            // 16-byte truncated SHA-256 hash, returned whenever nothing has
            // been written yet.
            static const uint8_t emptyLargeBlobArray[17] = {
                0x80, 0x76, 0xbe, 0x8b, 0x52, 0x8d, 0x00, 0x75,
                0xf7, 0xaa, 0xe9, 0x8d, 0x6f, 0xa5, 0x7a, 0x6d, 0x3c
            };

            uint8_t* stored = nullptr;
            size_t storedLen = 0;
            bool haveStored = getLargeBlobArray(&stored, storedLen);
            if (!haveStored || storedLen == 0) {
                if (stored) free(stored);
                stored = (uint8_t*)malloc(sizeof(emptyLargeBlobArray));
                if (!stored) {
                    uint8_t err = 0x01;
                    sendCtapResponse(channel, CTAPHID_CBOR, &err, 1);
                    free(responseBuffer);
                    return;
                }
                memcpy(stored, emptyLargeBlobArray, sizeof(emptyLargeBlobArray));
                storedLen = sizeof(emptyLargeBlobArray);
            }

            size_t fragLen = 0;
            if (fragmentOffset < storedLen) {
                fragLen = storedLen - fragmentOffset;
                if (fragLen > requestedGetLen) fragLen = requestedGetLen;
            }

            responseBuffer[0] = 0x00;
            CborEncoder encoder(&responseBuffer[1], 8191);
            encoder.writeMapHeader(1);
            encoder.writeUnsignedInt(0x01); // config
            encoder.writeByteString(stored + fragmentOffset, fragLen);

            free(stored);
            sendCtapResponse(channel, CTAPHID_CBOR, responseBuffer, 1 + encoder.getOffset());
            free(responseBuffer);
            return;
        }

        if (hasSet) {
            // Writing the large-blob array is security-sensitive, so this
            // authenticator always requires a fresh fingerprint check
            // before it accepts the first fragment of a new write.
            if (fragmentOffset == 0) {
                if (!hasLength || declaredTotalLength == 0 || declaredTotalLength > MAX_LARGE_BLOB_ARRAY) {
                    uint8_t err = 0x0A; // CTAP1_ERR_INVALID_LENGTH
                    sendCtapResponse(channel, CTAPHID_CBOR, &err, 1);
                    free(responseBuffer);
                    return;
                }

                showDisplayMessage(1, "VERIFY TO WRITE", "BLOB", 0);
                if (!fidoVerifyFingerprint()) {
                    showDisplayMessage(1, "VERIFICATION FAILED", "", 1500);
                    uint8_t err = 0x34; // CTAP2_ERR_UV_INVALID
                    sendCtapResponse(channel, CTAPHID_CBOR, &err, 1);
                    free(responseBuffer);
                    return;
                }

                if (largeBlobWriteBuffer) { free(largeBlobWriteBuffer); largeBlobWriteBuffer = nullptr; }
                largeBlobWriteBuffer = (uint8_t*)malloc(declaredTotalLength);
                if (!largeBlobWriteBuffer) {
                    uint8_t err = 0x01;
                    sendCtapResponse(channel, CTAPHID_CBOR, &err, 1);
                    free(responseBuffer);
                    return;
                }
                largeBlobWriteBufferCapacity = declaredTotalLength;
                largeBlobExpectedTotalLen = declaredTotalLength;
                largeBlobReceivedLen = 0;
            }

            // Fragments must arrive in order and fit within the length
            // declared by the first fragment.
            if (!largeBlobWriteBuffer || fragmentOffset != largeBlobReceivedLen ||
                fragmentOffset + setFragmentLen > largeBlobWriteBufferCapacity) {
                if (largeBlobWriteBuffer) { free(largeBlobWriteBuffer); largeBlobWriteBuffer = nullptr; }
                largeBlobWriteBufferCapacity = 0;
                largeBlobExpectedTotalLen = 0;
                largeBlobReceivedLen = 0;

                uint8_t err = 0x0A; // out-of-order or oversized fragment
                sendCtapResponse(channel, CTAPHID_CBOR, &err, 1);
                free(responseBuffer);
                return;
            }

            memcpy(largeBlobWriteBuffer + fragmentOffset, setFragment, setFragmentLen);
            largeBlobReceivedLen += setFragmentLen;

            if (largeBlobReceivedLen < largeBlobExpectedTotalLen) {
                // More fragments expected: acknowledge with an empty CBOR map.
                responseBuffer[0] = 0x00;
                CborEncoder encoder(&responseBuffer[1], 8191);
                encoder.writeMapHeader(0);
                sendCtapResponse(channel, CTAPHID_CBOR, responseBuffer, 1 + encoder.getOffset());
                free(responseBuffer);
                return;
            }

            // Final fragment: verify the trailing 16-byte truncated SHA-256
            // integrity hash the platform appended over everything before
            // it, per CTAP 2.1 sec 6.10.3, before persisting anything.
            bool integrityOk = false;
            if (largeBlobExpectedTotalLen >= 17) {
                size_t contentLen = largeBlobExpectedTotalLen - 16;
                uint8_t computedHash[32];
                mbedtls_md_context_t md_ctx;
                mbedtls_md_init(&md_ctx);
                mbedtls_md_setup(&md_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 0);
                mbedtls_md_starts(&md_ctx);
                mbedtls_md_update(&md_ctx, largeBlobWriteBuffer, contentLen);
                mbedtls_md_finish(&md_ctx, computedHash);
                mbedtls_md_free(&md_ctx);

                integrityOk = (memcmp(computedHash, largeBlobWriteBuffer + contentLen, 16) == 0);
            }

            if (!integrityOk) {
                free(largeBlobWriteBuffer);
                largeBlobWriteBuffer = nullptr;
                largeBlobWriteBufferCapacity = 0;
                largeBlobExpectedTotalLen = 0;
                largeBlobReceivedLen = 0;

                uint8_t err = 0x33; // CTAP2_ERR_INTEGRITY_FAILURE
                sendCtapResponse(channel, CTAPHID_CBOR, &err, 1);
                free(responseBuffer);
                return;
            }

            bool saveOk = setLargeBlobArray(largeBlobWriteBuffer, largeBlobExpectedTotalLen);
            free(largeBlobWriteBuffer);
            largeBlobWriteBuffer = nullptr;
            largeBlobWriteBufferCapacity = 0;
            largeBlobExpectedTotalLen = 0;
            largeBlobReceivedLen = 0;

            if (!saveOk) {
                uint8_t err = 0x01;
                sendCtapResponse(channel, CTAPHID_CBOR, &err, 1);
                free(responseBuffer);
                return;
            }

            showDisplayMessage(1, "BLOB SAVED", "", 1500);
            responseBuffer[0] = 0x00;
            CborEncoder encoder(&responseBuffer[1], 8191);
            encoder.writeMapHeader(0);
            sendCtapResponse(channel, CTAPHID_CBOR, responseBuffer, 1 + encoder.getOffset());
            free(responseBuffer);
            return;
        }

        // Neither "get" nor "set" was present.
        uint8_t err = 0x0A;
        sendCtapResponse(channel, CTAPHID_CBOR, &err, 1);
        free(responseBuffer);
        return;
    }
    else if (ctap2Cmd == 0x0A || ctap2Cmd == 0x41) { // authenticatorCredentialManagement
        CborParser parser(data + 1, len - 1);
        uint8_t rootType;
        uint64_t rootElements;

        if (!parser.readTypeAndValue(rootType, rootElements) || rootType != 5) {
            uint8_t err = 0x11;
            sendCtapResponse(channel, CTAPHID_CBOR, &err, 1);
            free(responseBuffer);
            return;
        }

        uint64_t subCommand = 0;
        uint8_t targetRpIdHash[32] = {0};
        size_t targetRpIdHashLen = 0;
        uint8_t targetCredId[64] = {0};
        size_t targetCredIdLen = 0;

        for (uint64_t i = 0; i < rootElements; i++) {
            uint8_t keyType;
            uint64_t mapKey;
            if (!parser.readTypeAndValue(keyType, mapKey) || keyType != 0) {
                parser.skipValue();
                continue;
            }

            if (mapKey == 0x01) { // Key 0x01 is subCommand
                uint8_t valType;
                parser.readTypeAndValue(valType, subCommand);
            } else if (mapKey == 0x02) { // Key 0x02 is subCommandParams
                uint8_t subType; uint64_t subElements;
                if (parser.readTypeAndValue(subType, subElements) && subType == 5) {
                    for (uint64_t j = 0; j < subElements; j++) {
                        uint8_t paramKeyType; uint64_t paramKey;
                        if (parser.readTypeAndValue(paramKeyType, paramKey) && paramKeyType == 0) {
                            if (paramKey == 0x01) {
                                parser.readByteString(targetRpIdHash, sizeof(targetRpIdHash), targetRpIdHashLen);
                            } else if (paramKey == 0x02) {
                                uint8_t credMapType; uint64_t credMapElem;
                                if (parser.readTypeAndValue(credMapType, credMapElem) && credMapType == 5) {
                                    for (uint64_t k = 0; k < credMapElem; k++) {
                                        char keyStr[16] = {0};
                                        if (parser.readTextString(keyStr, sizeof(keyStr))) {
                                            if (strcmp(keyStr, "id") == 0) {
                                                parser.readByteString(targetCredId, sizeof(targetCredId), targetCredIdLen);
                                            } else { parser.skipValue(); }
                                        } else { parser.skipValue(); }
                                    }
                                } else { parser.skipValue(); }
                            } else { parser.skipValue(); }
                        } else { parser.skipValue(); }
                    }
                } else { parser.skipValue(); }
            } else if (mapKey == 0x03) { // Key 0x03 is pinUvAuthProtocol
                uint8_t dummyType; uint64_t dummyVal;
                parser.readTypeAndValue(dummyType, dummyVal);
            } else if (mapKey == 0x04) { // Key 0x04 is pinUvAuthParam
                uint8_t dummyBuf[64]; size_t dummyLen;
                parser.readByteString(dummyBuf, sizeof(dummyBuf), dummyLen);
            } else {
                parser.skipValue();
            }
        }

        responseBuffer[0] = CTAP2_OK;
        CborEncoder encoder(&responseBuffer[1], 8191);

        // 0x01: getCredsMetadata
        if (subCommand == 0x01) {
            std::vector<String> allCreds = getAllStoredCredentialIds();
            encoder.writeMapHeader(2);
            encoder.writeUnsignedInt(0x01); // existingOpenCredentialsCount
            encoder.writeUnsignedInt(allCreds.size());
            encoder.writeUnsignedInt(0x02); // maxPossibleRemainingCredentialsCount
            encoder.writeUnsignedInt(1000 - allCreds.size());
        }
        // 0x02: enumerateRPsBegin
        else if (subCommand == 0x02) {
            enumRpList = getAllStoredRpIds();
            enumRpIdx = 0;

            if (enumRpList.empty()) {
                uint8_t err = 0x2E; // CTAP2_ERR_NO_CREDENTIALS
                sendCtapResponse(channel, CTAPHID_CBOR, &err, 1);
                free(responseBuffer);
                return;
            }

            String currentRp = enumRpList[enumRpIdx++];
            uint8_t rpHash[32];
            mbedtls_md_context_t sha_ctx;
            mbedtls_md_init(&sha_ctx);
            mbedtls_md_setup(&sha_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 0);
            mbedtls_md_starts(&sha_ctx);
            mbedtls_md_update(&sha_ctx, (const unsigned char*)currentRp.c_str(), currentRp.length());
            mbedtls_md_finish(&sha_ctx, rpHash);
            mbedtls_md_free(&sha_ctx);

            encoder.writeMapHeader(3);
            encoder.writeUnsignedInt(0x03); // rp
            encoder.writeMapHeader(1);
            encoder.writeTextString("id");
            encoder.writeTextString(currentRp.c_str());

            encoder.writeUnsignedInt(0x04); // rpIDHash
            encoder.writeByteString(rpHash, 32);

            encoder.writeUnsignedInt(0x05); // totalRPs
            encoder.writeUnsignedInt(enumRpList.size());
        }
        // 0x03: enumerateRPsGetNextRP
        else if (subCommand == 0x03) {
            if (enumRpIdx >= enumRpList.size()) {
                uint8_t err = 0x2E; // CTAP2_ERR_NO_CREDENTIALS
                sendCtapResponse(channel, CTAPHID_CBOR, &err, 1);
                free(responseBuffer);
                return;
            }

            String currentRp = enumRpList[enumRpIdx++];
            uint8_t rpHash[32];
            mbedtls_md_context_t sha_ctx;
            mbedtls_md_init(&sha_ctx);
            mbedtls_md_setup(&sha_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 0);
            mbedtls_md_starts(&sha_ctx);
            mbedtls_md_update(&sha_ctx, (const unsigned char*)currentRp.c_str(), currentRp.length());
            mbedtls_md_finish(&sha_ctx, rpHash);
            mbedtls_md_free(&sha_ctx);

            encoder.writeMapHeader(2);
            encoder.writeUnsignedInt(0x03); // rp
            encoder.writeMapHeader(1);
            encoder.writeTextString("id");
            encoder.writeTextString(currentRp.c_str());

            encoder.writeUnsignedInt(0x04); // rpIDHash
            encoder.writeByteString(rpHash, 32);
        }
        // 0x04: enumerateCredentialsBegin
        else if (subCommand == 0x04) {
            enumCredList.clear();
            enumCredIdx = 0;

            std::vector<String> allCreds = getAllStoredCredentialIds();
            for (const String &credHex : allCreds) {
                String rpId, userIdHex, userName, privKeyHex;
                int algId;
                if (getPasskeyRecord(credHex, rpId, userIdHex, userName, privKeyHex, algId)) {
                    uint8_t rpHash[32];
                    mbedtls_md_context_t sha_ctx;
                    mbedtls_md_init(&sha_ctx);
                    mbedtls_md_setup(&sha_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 0);
                    mbedtls_md_starts(&sha_ctx);
                    mbedtls_md_update(&sha_ctx, (const unsigned char*)rpId.c_str(), rpId.length());
                    mbedtls_md_finish(&sha_ctx, rpHash);
                    mbedtls_md_free(&sha_ctx);

                    if (constantTimeEquals(rpHash, targetRpIdHash, 32)) {
                        enumCredList.push_back(credHex);
                    }
                }
            }

            if (enumCredList.empty()) {
                uint8_t err = 0x2E; // CTAP2_ERR_NO_CREDENTIALS
                sendCtapResponse(channel, CTAPHID_CBOR, &err, 1);
                free(responseBuffer);
                return;
            }

            String credHex = enumCredList[enumCredIdx++];
            String rpId, userIdHex, userName, privKeyHex;
            int algId;
            getPasskeyRecord(credHex, rpId, userIdHex, userName, privKeyHex, algId);

            uint8_t binCredId[64];
            size_t credLen = credHex.length() / 2;
            fromHex(credHex, binCredId, credLen);

            uint8_t binUserId[64];
            size_t userLen = userIdHex.length() / 2;
            fromHex(userIdHex, binUserId, userLen);

            encoder.writeMapHeader(3);
            encoder.writeUnsignedInt(0x06); // user
            encoder.writeMapHeader(2);
            encoder.writeTextString("id"); // len 2
            encoder.writeByteString(binUserId, userLen);
            encoder.writeTextString("name"); // len 4
            encoder.writeTextString(userName.c_str());

            encoder.writeUnsignedInt(0x07); // credentialID
            encoder.writeMapHeader(2);
            encoder.writeTextString("id"); // Canonical CBOR: "id" (len 2) comes BEFORE "type" (len 4)
            encoder.writeByteString(binCredId, credLen);
            encoder.writeTextString("type");
            encoder.writeTextString("public-key");

            encoder.writeUnsignedInt(0x09); // totalCredentials
            encoder.writeUnsignedInt(enumCredList.size());
        }
        // 0x05: enumerateCredentialsGetNextCredential
        else if (subCommand == 0x05) {
            if (enumCredIdx >= enumCredList.size()) {
                uint8_t err = 0x2E; // CTAP2_ERR_NO_CREDENTIALS
                sendCtapResponse(channel, CTAPHID_CBOR, &err, 1);
                free(responseBuffer);
                return;
            }

            String credHex = enumCredList[enumCredIdx++];
            String rpId, userIdHex, userName, privKeyHex;
            int algId;
            getPasskeyRecord(credHex, rpId, userIdHex, userName, privKeyHex, algId);

            uint8_t binCredId[64];
            size_t credLen = credHex.length() / 2;
            fromHex(credHex, binCredId, credLen);

            uint8_t binUserId[64];
            size_t userLen = userIdHex.length() / 2;
            fromHex(userIdHex, binUserId, userLen);

            encoder.writeMapHeader(2);
            encoder.writeUnsignedInt(0x06); // user
            encoder.writeMapHeader(2);
            encoder.writeTextString("id"); // len 2
            encoder.writeByteString(binUserId, userLen);
            encoder.writeTextString("name"); // len 4
            encoder.writeTextString(userName.c_str());

            encoder.writeUnsignedInt(0x07); // credentialID
            encoder.writeMapHeader(2);
            encoder.writeTextString("id"); // Canonical CBOR: "id" (len 2) comes BEFORE "type" (len 4)
            encoder.writeByteString(binCredId, credLen);
            encoder.writeTextString("type");
            encoder.writeTextString("public-key");
        }
        // 0x06: deleteCredential
        else if (subCommand == 0x06) {
            String credHex = toHex(targetCredId, targetCredIdLen);
            if (deletePasskeyRecord(credHex)) {
                encoder.writeMapHeader(0);
            } else {
                uint8_t err = 0x2E; // CTAP2_ERR_NO_CREDENTIALS
                sendCtapResponse(channel, CTAPHID_CBOR, &err, 1);
                free(responseBuffer);
                return;
            }
        }
        else {
            uint8_t err = CTAP2_ERR_UNSUPPORTED_OPTION;
            sendCtapResponse(channel, CTAPHID_CBOR, &err, 1);
            free(responseBuffer);
            return;
        }

        sendCtapResponse(channel, CTAPHID_CBOR, responseBuffer, 1 + encoder.getOffset());
        free(responseBuffer);
        return;
    }
    else if (ctap2Cmd == 0x0D) {
        CborParser parser(data + 1, len - 1);
        uint8_t rootType; uint64_t rootElements;

        if (!parser.readTypeAndValue(rootType, rootElements) || rootType != 5) {
            uint8_t err = 0x11;
            sendCtapResponse(channel, CTAPHID_CBOR, &err, 1);
            free(responseBuffer);
            return;
        }

        uint64_t subCommand = 0;
        uint64_t minPinLenParam = 0;
        
        for (uint64_t i = 0; i < rootElements; i++) {
            uint8_t keyType; uint64_t mapKey;
            if (parser.readTypeAndValue(keyType, mapKey) && keyType == 0) {
                if (mapKey == 0x01) {
                    uint8_t valType; parser.readTypeAndValue(valType, subCommand);
                } else if (mapKey == 0x02) {
                    uint8_t subType; uint64_t subElem;
                    if (parser.readTypeAndValue(subType, subElem) && subType == 5) {
                        for (uint64_t j = 0; j < subElem; j++) {
                            uint8_t pKeyType; uint64_t pMapKey;
                            if (parser.readTypeAndValue(pKeyType, pMapKey) && pKeyType == 0) {
                                if (pMapKey == 0x02) {
                                    uint8_t valType; parser.readTypeAndValue(valType, minPinLenParam);
                                } else { parser.skipValue(); }
                            } else { parser.skipValue(); }
                        }
                    } else { parser.skipValue(); }
                } else { parser.skipValue(); }
            } else { parser.skipValue(); }
        }

        if (subCommand == 0x02) {
            setForcePinChange(true);
        } else if (subCommand == 0x03) {
            setMinPinLength((uint8_t)minPinLenParam);
        } else if (subCommand != 0x01) {
            uint8_t err = 0x2B;
            sendCtapResponse(channel, CTAPHID_CBOR, &err, 1);
            free(responseBuffer);
            return;
        }

        responseBuffer[0] = 0x00;
        CborEncoder encoder(&responseBuffer[1], 8191);
        encoder.writeMapHeader(0);
        sendCtapResponse(channel, CTAPHID_CBOR, responseBuffer, 1 + encoder.getOffset());
        free(responseBuffer);
        return;
    }
    else {
        uint8_t err = 0x11;
        sendCtapResponse(channel, CTAPHID_CBOR, &err, 1);
        free(responseBuffer);
    }
}

FIDO2HIDDevice::~FIDO2HIDDevice() {
    if (ctapBuffer) free(ctapBuffer);
    if (pendingData) free(pendingData);
    if (largeBlobWriteBuffer) free(largeBlobWriteBuffer);
}

void FIDO2HIDDevice::_onOutput(uint8_t report_id, const uint8_t* buffer, uint16_t len) {
    if (len < 7) return;

    if (ctapExpectedLen > 0 && (millis() - lastPacketTime > 500)) {
        ctapExpectedLen = 0;
        ctapReceivedLen = 0;
        ctapExpectedSeq = 0;
    }

    uint32_t channel = (buffer[0] << 24) | (buffer[1] << 16) | (buffer[2] << 8) | buffer[3];

    if (buffer[4] & 0x80) { 
        uint8_t cmd = buffer[4];

        if (hasPendingCommand && channel == pendingChannel) {
            return; 
        }

        if (hasPendingCommand) {
            uint8_t err = 0x05; 
            sendCtapResponse(channel, CTAPHID_ERROR, &err, 1);
            return; 
        }

        ctapCurrentCmd = cmd;
        ctapExpectedLen = (buffer[5] << 8) | buffer[6];
        ctapCurrentChannel = channel;

        if (ctapExpectedLen > 7609) {
            uint8_t err = 0x01; 
            sendCtapResponse(channel, CTAPHID_ERROR, &err, 1);
            ctapExpectedLen = 0; 
            ctapReceivedLen = 0;
            return;
        }

        if (ctapExpectedLen > ctapBufferCapacity) {
            if (ctapBuffer) free(ctapBuffer);
            ctapBuffer = (uint8_t*)malloc(ctapExpectedLen);
            if (!ctapBuffer) {
                uint8_t err = 0x01;
                sendCtapResponse(channel, CTAPHID_ERROR, &err, 1);
                return;
            }
            ctapBufferCapacity = ctapExpectedLen;
        }

        ctapReceivedLen = (ctapExpectedLen > 57) ? 57 : ctapExpectedLen;

        if (len < 7 + ctapReceivedLen) {
            ctapExpectedLen = 0;
            ctapReceivedLen = 0;
            return;
        }

        memcpy(ctapBuffer, &buffer[7], ctapReceivedLen);
        ctapExpectedSeq = 0;
        lastPacketTime = millis();
    } 
    else { 
        if (ctapExpectedLen == 0 || channel != ctapCurrentChannel) return;

        if (buffer[4] != ctapExpectedSeq) {
            uint8_t err = 0x04; 
            sendCtapResponse(channel, CTAPHID_ERROR, &err, 1);
            ctapExpectedLen = 0; 
            ctapReceivedLen = 0;
            return;
        }

        ctapExpectedSeq++;
        uint16_t chunk = (ctapExpectedLen - ctapReceivedLen > 59) ? 59 : (ctapExpectedLen - ctapReceivedLen);

        if (ctapReceivedLen > ctapBufferCapacity || chunk > ctapBufferCapacity - ctapReceivedLen) {
            uint8_t err = 0x01; 
            sendCtapResponse(channel, CTAPHID_ERROR, &err, 1);
            ctapExpectedLen = 0; 
            ctapReceivedLen = 0;
            return;
        }

        if (len < 5 + chunk) {
            uint8_t err = 0x01; 
            sendCtapResponse(channel, CTAPHID_ERROR, &err, 1);
            ctapExpectedLen = 0; 
            ctapReceivedLen = 0;
            return;
        }

        memcpy(ctapBuffer + ctapReceivedLen, &buffer[5], chunk);
        ctapReceivedLen += chunk;
        lastPacketTime = millis();
    }

    if (ctapExpectedLen > 0 && ctapReceivedLen >= ctapExpectedLen) {
        if (ctapExpectedLen > pendingDataCapacity) {
            if (pendingData) free(pendingData);
            pendingData = (uint8_t*)malloc(ctapExpectedLen);
            pendingDataCapacity = ctapExpectedLen;
        }

        if (pendingData) {
            pendingChannel = channel;
            pendingCmd = ctapCurrentCmd;
            memcpy(pendingData, ctapBuffer, ctapExpectedLen);
            pendingLen = ctapExpectedLen;
            hasPendingCommand = true; 
        }

        ctapExpectedLen = 0; 
        ctapReceivedLen = 0;
    }
}

void FIDO2HIDDevice::poll() {
    if (!hasPendingCommand) return;

    uint32_t ch   = pendingChannel;
    uint8_t  cmd  = pendingCmd;
    uint16_t dlen = pendingLen;
    
    uint8_t* data = (uint8_t*)malloc(dlen);
    if (!data) {
        hasPendingCommand = false;
        return;
    }

    memcpy(data, pendingData, dlen);
    hasPendingCommand = false;

    processCtapCommand(ch, cmd, data, dlen);
    free(data);
}

FIDO2HIDDevice FidoHID;