#include "FIDO2Manager.h"
#include "Globals.h"
#include "DisplayManager.h"
#include "FingerprintManager.h"
#include "CryptoManager.h"
#include "StorageManager.h"

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
#if USE_FINGERPRINT_SIMULATOR
    if (digitalRead(SIMULATOR_BUTTON_PIN) == LOW) {
        while(digitalRead(SIMULATOR_BUTTON_PIN) == LOW) { vTaskDelay(10 / portTICK_PERIOD_MS); }
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
    if (img != FINGERPRINT_OK) {
        xSemaphoreGive(fingerprintMutex);
        return false;
    }
    if (finger.image2Tz() != FINGERPRINT_OK) {
        xSemaphoreGive(fingerprintMutex);
        return false;
    }
    if (finger.fingerSearch() != FINGERPRINT_OK) {
        xSemaphoreGive(fingerprintMutex);
        return false;
    }
    bool result = finger.confidence > 50;
    xSemaphoreGive(fingerprintMutex);
    return result;
#endif
}

// CTAPHID runs on fixed 64-byte USB reports for both input and output.
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

// Initial HID packets carry 57 data bytes; continuation packets carry 59.
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

        if (!getPasskeyRecord(khHex, storedAppId, dummyUser, dummyName, privHex, alg) || storedAppId != appIdHex) {
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

// INIT may allocate a channel; all stateful commands stay on the active channel.
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

    if (ctap2Cmd == 0x04) {
        responseBuffer[0] = 0x00;
        CborEncoder encoder(&responseBuffer[1], 8191);

        encoder.writeMapHeader(8);

        encoder.writeUnsignedInt(1);
        encoder.writeArrayHeader(1);
        encoder.writeTextString("FIDO_2_0");

        encoder.writeUnsignedInt(3);
        initializeDynamicAaguid();
        encoder.writeByteString(dynamicAaguid, 16);

        encoder.writeUnsignedInt(4);
        encoder.writeMapHeader(3);
        encoder.writeTextString("rk"); encoder.writeBoolean(true);
        encoder.writeTextString("up"); encoder.writeBoolean(true);
        encoder.writeTextString("uv"); encoder.writeBoolean(true);

        encoder.writeUnsignedInt(5); encoder.writeUnsignedInt(8192);
        encoder.writeUnsignedInt(7); encoder.writeUnsignedInt(8);
        encoder.writeUnsignedInt(8); encoder.writeUnsignedInt(64);

        encoder.writeUnsignedInt(9);
        encoder.writeArrayHeader(1);
        encoder.writeTextString("usb");

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
        char targetRpId[128] = {0};
        uint8_t clientDataHash[32] = {0};
        size_t clientDataHashLen = 0;
        uint8_t userIdRaw[64] = {0};
        size_t userIdLen = 0;
        char userName[128] = {0};
        bool hmacSecretRequested = false;
        int selectedAlgId = defaultCryptoAlg;

        static const size_t MAX_EXCLUDE_CREDENTIALS = 16;
        uint8_t excludeCredentialIds[MAX_EXCLUDE_CREDENTIALS][64];
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
                                    // Standard fallback priority if the website rejects the user's preferred default
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
                    if (dummyRpId == String(targetRpId)) {
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
            xSemaphoreGive(displayMutex);
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
                keygenSuccess = generateRsa2048KeyPair(privateKeyHex, pubKeyData, &pubKeyLen, rsaE, &rsaELen);
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
                        uint8_t status = 0x02; // 0x02 PROCESSING
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

        uint8_t rawCredId[16];
        for(int i = 0; i < 16; i++) rawCredId[i] = esp_random() & 0xFF;

        String credentialIdHex = toHex(rawCredId, 16);
        String userIdHex = toHex(userIdRaw, userIdLen);

        if (!savePasskeyRecord(credentialIdHex, String(targetRpId), userIdHex, String(userName), privateKeyHex, selectedAlgId)) {
            showDisplayMessage(1, "SAVE FAILED", "", 0);
            uint8_t err = 0x21;
            sendCtapResponse(channel, CTAPHID_CBOR, &err, 1);
            if (pubKeyData) free(pubKeyData);
            if (rsaE) free(rsaE);
            free(responseBuffer);
            return;
        }

        responseBuffer[0] = 0x00;
        CborEncoder encoder(&responseBuffer[1], 8191);
        encoder.writeMapHeader(hmacSecretRequested ? 4 : 3);

        encoder.writeUnsignedInt(1);
        encoder.writeTextString("packed");

        encoder.writeUnsignedInt(2);
        uint8_t authData[200] = {0};

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

        initializeDynamicAaguid();
        memcpy(&authData[37], dynamicAaguid, 16);

        authData[53] = 0x00; authData[54] = 0x10;
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

        int authDataOffset = 0;
        memcpy(&finalAuthData[authDataOffset], authData, 71); 
        authDataOffset += 71;

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
        free(finalAuthData);
        if (pubKeyData) free(pubKeyData);
        if (rsaE) free(rsaE);

        uint8_t attestationHash[32];
        mbedtls_md_init(&sha_ctx);
        mbedtls_md_setup(&sha_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 0);
        mbedtls_md_starts(&sha_ctx);
        mbedtls_md_update(&sha_ctx, &responseBuffer[2], encoder.getOffset() - 1);
        mbedtls_md_update(&sha_ctx, clientDataHash, 32);
        mbedtls_md_finish(&sha_ctx, attestationHash);
        mbedtls_md_free(&sha_ctx);

        uint8_t* attestationSig = nullptr;
        size_t attestationSigLen = 0;

        size_t authDataLen = encoder.getOffset() - 1;
        size_t rawMsgLen = authDataLen + 32;
        uint8_t* rawMsg = (uint8_t*)malloc(rawMsgLen);
        memcpy(rawMsg, &responseBuffer[2], authDataLen);
        memcpy(rawMsg + authDataLen, clientDataHash, 32);

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

        if (hmacSecretRequested) {
            encoder.writeUnsignedInt(4);
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

        static const size_t MAX_ALLOW_CREDENTIALS = 32;
        uint8_t allowCredentialIds[MAX_ALLOW_CREDENTIALS][64] = {0};
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
            else if (mapKey == 0x06) {
                uint8_t extType; uint64_t extElements;
                if (parser.readTypeAndValue(extType, extElements) && extType == 5) {
                    for (uint64_t j = 0; j < extElements; j++) {
                        char extKey[32] = {0};
                        if (parser.readTextString(extKey, sizeof(extKey))) {
                            if (strcmp(extKey, "hmac-secret") == 0) {
                                uint8_t subMapType; uint64_t subMapElements;
                                if (parser.readTypeAndValue(subMapType, subMapElements) && subMapType == 5) {
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

        if (strlen(targetRpId) == 0 || clientDataHashLen != 32) {
            uint8_t err = 0x0A;
            sendCtapResponse(channel, CTAPHID_CBOR, &err, 1);
            free(responseBuffer);
            return;
        }

        String credentialIdHex = "";
        if (allowCredentialCount > 0) {
            for (size_t i = 0; i < allowCredentialCount; i++) {
                String candidateIdHex = toHex(allowCredentialIds[i], allowCredentialIdLens[i]);
                String candidateRpId, candidateUserIdHex, candidateUserName, candidatePrivateKeyHex;
                int candidateAlgId;
                if (getPasskeyRecord(candidateIdHex, candidateRpId, candidateUserIdHex,
                                     candidateUserName, candidatePrivateKeyHex, candidateAlgId) &&
                    candidateRpId == String(targetRpId)) {
                    credentialIdHex = candidateIdHex;
                    break;
                }
            }

            if (credentialIdHex == "") {
                uint8_t err = 0x2E;
                sendCtapResponse(channel, CTAPHID_CBOR, &err, 1);
                free(responseBuffer);
                return;
            }
        } else {
            credentialIdHex = findCredentialIdByRpAndUser(String(targetRpId), "");
            if (credentialIdHex == "") {
                uint8_t err = 0x2E;
                sendCtapResponse(channel, CTAPHID_CBOR, &err, 1);
                free(responseBuffer);
                return;
            }
        }

        String storedRpId, storedUserIdHex, storedUserName, storedPrivateKeyHex;
        int storedAlgId;
        if (!getPasskeyRecord(credentialIdHex, storedRpId, storedUserIdHex, storedUserName, storedPrivateKeyHex, storedAlgId)) {
            uint8_t err = 0x2E;
            sendCtapResponse(channel, CTAPHID_CBOR, &err, 1);
            free(responseBuffer);
            return;
        }

        bool biometricVerified = false;
        if (optionUP || optionUV) {
            if (millis() - lastFingerprintSuccessTime < 5000) {
                biometricVerified = true;
            } else {
                showDisplayMessage(1, "VERIFY FINGER", "", 0);

                bool biometricCanceled = false;
                unsigned long authStart = millis(); unsigned long lastKeepAlive = 0;
                while (millis() - authStart < 15000) {
                    if (hasPendingCommand && pendingCmd == CTAPHID_CANCEL && pendingChannel == channel) {
                        hasPendingCommand = false;
                        biometricCanceled = true;
                        break;
                    }

                    if (millis() - lastKeepAlive > 500) {
                        uint8_t status = 0x02; sendCtapResponse(channel, CTAPHID_KEEPALIVE, &status, 1);
                        lastKeepAlive = millis();
                    }
                    if (fidoVerifyFingerprint()) {
                        biometricVerified = true;
                        lastFingerprintSuccessTime = millis(); break;
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
                uint8_t err = 0x34; sendCtapResponse(channel, CTAPHID_CBOR, &err, 1); free(responseBuffer); return;
            }
        } else { biometricVerified = true; }

        uint8_t authData[37] = {0};

        mbedtls_md_context_t sha_ctx;
        mbedtls_md_init(&sha_ctx);
        mbedtls_md_setup(&sha_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 0);
        mbedtls_md_starts(&sha_ctx);
        mbedtls_md_update(&sha_ctx, (const unsigned char*)targetRpId, strlen(targetRpId));
        mbedtls_md_finish(&sha_ctx, authData);
        mbedtls_md_free(&sha_ctx);

        uint8_t flags = 0x01;
        if (optionUV && biometricVerified) { flags |= 0x04; }
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

        localEncoder.writeMapHeader(extensionRequested ? 5 : 4);

        localEncoder.writeUnsignedInt(0x01);
        localEncoder.writeMapHeader(2);
        localEncoder.writeTextString("id");
        uint8_t binCredId[64]; size_t binCredLen = credentialIdHex.length() / 2;
        fromHex(credentialIdHex, binCredId, binCredLen);
        localEncoder.writeByteString(binCredId, binCredLen);
        localEncoder.writeTextString("type"); localEncoder.writeTextString("public-key");

        localEncoder.writeUnsignedInt(0x02); localEncoder.writeByteString(authData, 37);

        localEncoder.writeUnsignedInt(0x03); localEncoder.writeByteString(signatureASN1, finalSigLen);

        localEncoder.writeUnsignedInt(0x04); localEncoder.writeMapHeader(3);
        localEncoder.writeTextString("id");
        uint8_t rawUserIdBytes[64]; size_t parsedUserIdLen = storedUserIdHex.length() / 2;
        fromHex(storedUserIdHex, rawUserIdBytes, parsedUserIdLen);
        localEncoder.writeByteString(rawUserIdBytes, parsedUserIdLen);
        localEncoder.writeTextString("name"); localEncoder.writeTextString(storedUserName.c_str());
        localEncoder.writeTextString("displayName"); localEncoder.writeTextString(storedUserName.c_str());

        if (extensionRequested) {
            localEncoder.writeUnsignedInt(0x05);
            localEncoder.writeMapHeader(1);
            localEncoder.writeTextString("hmac-secret");

            if (hmacSalt2Len == 32) {
                uint8_t dualHmac[64];
                memcpy(dualHmac, hmacOutput1, 32);
                memcpy(dualHmac + 32, hmacOutput2, 32);
                localEncoder.writeByteString(dualHmac, 64);
            } else {
                localEncoder.writeByteString(hmacOutput1, 32);
            }
        }

        size_t finalPayloadSize = localEncoder.getOffset() + 1;
        sendCtapResponse(channel, CTAPHID_CBOR, localRespBuf, finalPayloadSize);

        #if defined(ARDUINO_ARCH_ESP32)
            vTaskDelay(10 / portTICK_PERIOD_MS);
        #else
            delay(10);
        #endif

        showDisplayMessage(1, "VERIFIED", "", 0);
        free(signatureASN1);
        free(localRespBuf);
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

        if (ctapReceivedLen + chunk > ctapBufferCapacity) {
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