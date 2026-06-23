#include "FIDO2Manager.h"
#include "Globals.h"
#include "DisplayManager.h"
#include "FingerprintManager.h"
#include "CryptoManager.h"
#include "StorageManager.h"

uint8_t dynamicAaguid[16] = {0};
bool isAaguidInitialized = false;

// Function to derive a unique AAGUID from the device's factory MAC address
void initializeDynamicAaguid() {
    if (isAaguidInitialized) return;

    uint8_t mac[6];
    // Retrieve the factory-fused MAC address (guaranteed unique per chip)
    if (esp_efuse_mac_get_default(mac) != ESP_OK) {
        // Fallback placeholder if MAC reading fails
        memset(mac, 0xAA, 6);
    }

    // Standard UUIDv4 variant/version bits can be integrated into a fixed prefix
    // Prefix: Fixed 10-byte namespace identifier
    dynamicAaguid[0] = 0x4F;
    dynamicAaguid[1] = 0xA2;
    dynamicAaguid[2] = 0xB1;
    dynamicAaguid[3] = 0x3C;
    dynamicAaguid[4] = 0x7C;
    dynamicAaguid[5] = 0x89;
    dynamicAaguid[6] = 0x4E; // UUID version 4 indicators can go here if required
    dynamicAaguid[7] = 0x5B;
    dynamicAaguid[8] = 0xBC;
    dynamicAaguid[9] = 0x6D;

    // Suffix: Append the unique 6-byte hardware MAC address
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
    uint8_t img = finger.getImage();

    for (uint8_t retry = 0; retry < 3 && img != FINGERPRINT_OK && img != FINGERPRINT_NOFINGER; retry++) {
        delay(50);
        img = finger.getImage();
    }

    if (img != FINGERPRINT_OK) return false;              
    if (finger.image2Tz() != FINGERPRINT_OK) return false;
    if (finger.fingerSearch() != FINGERPRINT_OK) return false;
    return finger.confidence > 50;                        
}

const uint8_t fido_report_descriptor[34] = {
    0x06, 0xD0, 0xF1, // USAGE_PAGE (FIDO Alliance)
    0x09, 0x01,       // USAGE (U2F Authenticator Device)
    0xA1, 0x01,       // COLLECTION (Application)
    0x09, 0x20,       //   USAGE (Input Report Data)
    0x15, 0x00,       //   LOGICAL_MINIMUM (0)
    0x26, 0xFF, 0x00, //   LOGICAL_MAXIMUM (255)
    0x75, 0x08,       //   REPORT_SIZE (8)
    0x95, 0x40,       //   REPORT_COUNT (64)
    0x81, 0x02,       //   INPUT (Data,Var,Abs)
    0x09, 0x21,       //   USAGE (Output Report Data)
    0x15, 0x00,       //   LOGICAL_MINIMUM (0)
    0x26, 0xFF, 0x00, //   LOGICAL_MAXIMUM (255)
    0x75, 0x08,       //   REPORT_SIZE (8)
    0x95, 0x40,       //   REPORT_COUNT (64)
    0x91, 0x02,       //   OUTPUT (Data,Var,Abs)
    0xC0              // END_COLLECTION
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
        delay(1); 
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

        if (hid.SendReport(0, packet, 64)) {
            offset += chunkLen;
            seq++;
        } else {
            delay(2); 
        }
    }
}

void FIDO2HIDDevice::processCtapCommand(uint32_t channel, uint8_t cmd, uint8_t* data, uint16_t len) {
    if (cmd == CTAPHID_INIT) {
        if (len < 8) {
            uint8_t err = 0x01; // CTAPHID_ERR_INVALID_LEN
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

        resp[12] = 0x02; // Protocol V2
        resp[13] = 0x01; // Major Version
        resp[14] = 0x01; // Minor Version
        resp[15] = 0x00; // Build
        resp[16] = 0x04; // Capabilities: CBOR

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
    else if (cmd == CTAPHID_CBOR && channel == activeChannelID) {
        processCborCommand(channel, data, len);
    } 
    else {
        uint8_t err = 0x01; // CTAPHID_ERR_INVALID_CMD
        sendCtapResponse(channel, CTAPHID_ERROR, &err, 1);
    }
}

void FIDO2HIDDevice::processCborCommand(uint32_t channel, uint8_t* data, uint16_t len) {
    if (len == 0) return;
    uint8_t ctap2Cmd = data[0];

    // Increased buffer size to support large RSA records cleanly
    uint8_t responseBuffer[1024];
    responseBuffer[0] = 0x00; 

    // Global static tracking for biometric cache to avoid system double-clipping
    static unsigned long lastFingerprintSuccessTime = 0;

    if (ctap2Cmd == 0x04) {
        responseBuffer[0] = 0x00;
        CborEncoder encoder(&responseBuffer[1], 1023);

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

        encoder.writeUnsignedInt(5); encoder.writeUnsignedInt(1024);
        encoder.writeUnsignedInt(7); encoder.writeUnsignedInt(8);
        encoder.writeUnsignedInt(8); encoder.writeUnsignedInt(64);

        encoder.writeUnsignedInt(9);
        encoder.writeArrayHeader(1);
        encoder.writeTextString("usb");

        // Dynamic update: Advertise multiple supported algorithms (P-256, Ed25519, RS256)
        encoder.writeUnsignedInt(10);
        encoder.writeArrayHeader(3);
        
        // Algorithm 1: ES256 (P-256)
        encoder.writeMapHeader(2);
        encoder.writeTextString("alg"); encoder.writeNegativeInt(-7);
        encoder.writeTextString("type"); encoder.writeTextString("public-key");
        
        // Algorithm 2: EdDSA (Ed25519)
        encoder.writeMapHeader(2);
        encoder.writeTextString("alg"); encoder.writeNegativeInt(-8);
        encoder.writeTextString("type"); encoder.writeTextString("public-key");

        // Algorithm 3: RS256
        encoder.writeMapHeader(2);
        encoder.writeTextString("alg"); encoder.writeNegativeInt(-257);
        encoder.writeTextString("type"); encoder.writeTextString("public-key");

        sendCtapResponse(channel, CTAPHID_CBOR, responseBuffer, 1 + encoder.getOffset());
        return;
    }
    else if (ctap2Cmd == 0x0B) { 
        responseBuffer[0] = 0x00;
        sendCtapResponse(channel, CTAPHID_CBOR, responseBuffer, 1);
        return;
    }
    else if (ctap2Cmd == 0x01) { 
        if (!authenticated) {
            uint8_t err = 0x31; 
            sendCtapResponse(channel, CTAPHID_CBOR, &err, 1);
            return; 
        }

        char targetRpId[128] = {0};
        uint8_t clientDataHash[32] = {0};
        size_t clientDataHashLen = 0;
        uint8_t userIdRaw[64] = {0};
        size_t userIdLen = 0;
        char userName[128] = {0};
        bool hmacSecretRequested = false; 
        int selectedAlgId = -7; // Default fallback to P-256 (-7)

        // Track incoming excludeList items
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
                // Key 0x06: pubKeyCredParams array (Select the cryptographic algorithm requested by client)
                else if (mapKey == 0x06) {
                    uint8_t arrType; uint64_t arrCount;
                    if (parser.readTypeAndValue(arrType, arrCount) && arrType == 4) {
                        bool algorithmicMatchFound = false;
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
                                            else if (typeVal == 1) currentAlgId = -(int)rawVal;
                                        }
                                    } else { parser.skipValue(); }
                                }
                                // Pick Ed25519 (-8), P-256 (-7), or RS256 (-257) if supported
                                if (!algorithmicMatchFound && (currentAlgId == -7 || currentAlgId == -8 || currentAlgId == -257)) {
                                    selectedAlgId = currentAlgId;
                                    algorithmicMatchFound = true;
                                }
                            } else { parser.skipValue(); }
                        }
                    } else { parser.skipValue(); }
                }
                else if (mapKey == 0x04) { 
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
                        return;
                    }
                }
            }
        }

        tft.fillScreen(TFT_YELLOW);
        tft.setCursor(10, 20);
        tft.println("PLACE FINGER...");
        
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
            tft.fillScreen(TFT_BLACK);
            uint8_t err = 0x2D; 
            sendCtapResponse(channel, CTAPHID_CBOR, &err, 1);
            return;
        }

        if (!biometricVerified) {
            uint8_t err = 0x34; 
            sendCtapResponse(channel, CTAPHID_CBOR, &err, 1);
            return;
        }

        String privateKeyHex = "";
        uint8_t pubKeyP256[65] = {0};
        uint8_t pubKeyEd[32] = {0};
        uint8_t rsaN[256] = {0};
        uint8_t rsaE[3] = {0};
        size_t rsaNLen = 0, rsaELen = 0;
        bool keygenSuccess = false;

        // Condition generation based on dynamically selected algorithm parameter
        if (selectedAlgId == -7) {
            uint8_t private_key_d[32] = {0};
            keygenSuccess = generateKeypairP256(private_key_d, pubKeyP256);
            if(keygenSuccess) {
                privateKeyHex = toHex(private_key_d, 32);
                memset(private_key_d, 0, 32);
            }
        } else if (selectedAlgId == -8) {
            keygenSuccess = generateEd25519KeyPair(privateKeyHex, pubKeyEd);
        } else if (selectedAlgId == -257) {
            keygenSuccess = generateRsa2048KeyPair(privateKeyHex, rsaN, &rsaNLen, rsaE, &rsaELen);
        }

        if (!keygenSuccess) {
            tft.fillScreen(TFT_RED);
            tft.println("REGISTRATION FAILED");
            delay(2000);
            tft.fillScreen(TFT_BLACK);
            uint8_t err = 0x01; 
            sendCtapResponse(channel, CTAPHID_CBOR, &err, 1);
            return;
        }

        uint8_t rawCredId[16];
        for(int i = 0; i < 16; i++) rawCredId[i] = esp_random() & 0xFF;
        
        String credentialIdHex = toHex(rawCredId, 16);
        String userIdHex = toHex(userIdRaw, userIdLen);

        // Save credential directly via StorageManager mapped to appropriate generic alg identifier
        if (!savePasskeyRecord(credentialIdHex, String(targetRpId), userIdHex, String(userName), privateKeyHex, selectedAlgId)) {
            uint8_t err = 0x21; 
            sendCtapResponse(channel, CTAPHID_CBOR, &err, 1);
            return;
        }

        responseBuffer[0] = 0x00; 
        CborEncoder encoder(&responseBuffer[1], 1023);
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

        // Build dynamically sized structure payload based on current COSE Algorithm Format requirements
        uint8_t finalAuthData[512];
        int authDataOffset = 0;
        memcpy(&finalAuthData[authDataOffset], authData, 71); authDataOffset += 71;

        if (selectedAlgId == -7) {
            uint8_t coseHeader[10] = {0xA5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20};
            uint8_t coseYHeader[3]  = {0x22, 0x58, 0x20};
            memcpy(&finalAuthData[authDataOffset], coseHeader, 10); authDataOffset += 10;
            memcpy(&finalAuthData[authDataOffset], pubKeyP256 + 1, 32); authDataOffset += 32; // X Coords
            memcpy(&finalAuthData[authDataOffset], coseYHeader, 3); authDataOffset += 3;
            memcpy(&finalAuthData[authDataOffset], pubKeyP256 + 33, 32); authDataOffset += 32; // Y Coords
        } else if (selectedAlgId == -8) {
            // COSE encoding structure for Ed25519 public key parameters (-8)
            uint8_t coseEdHeader[10] = {0xA4, 0x01, 0x01, 0x03, 0x27, 0x20, 0x06, 0x21, 0x58, 0x20};
            memcpy(&finalAuthData[authDataOffset], coseEdHeader, 10); authDataOffset += 10;
            memcpy(&finalAuthData[authDataOffset], pubKeyEd, 32); authDataOffset += 32; // Direct public key raw bytes
        } else if (selectedAlgId == -257) {
            // COSE encoding structure for RS256 public key parameters (-257)
            uint8_t coseRsaHeader[] = {0xA4, 0x01, 0x03, 0x03, 0x39, 0x01, 0x00, 0x20, 0x59, 0x01, 0x00};
            memcpy(&finalAuthData[authDataOffset], coseRsaHeader, sizeof(coseRsaHeader));
            authDataOffset += sizeof(coseRsaHeader);
            
            memcpy(&finalAuthData[authDataOffset], rsaN, 256); // N value
            authDataOffset += 256;
            
            uint8_t coseRsaEHeader[] = {0x21, 0x43};
            memcpy(&finalAuthData[authDataOffset], coseRsaEHeader, sizeof(coseRsaEHeader));
            authDataOffset += sizeof(coseRsaEHeader);
            
            memcpy(&finalAuthData[authDataOffset], rsaE, 3); // E value
            authDataOffset += 3;
        }

        encoder.writeByteString(finalAuthData, authDataOffset);
        
        uint8_t attestationHash[32];
        mbedtls_md_init(&sha_ctx);
        mbedtls_md_setup(&sha_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 0);
        mbedtls_md_starts(&sha_ctx);
        mbedtls_md_update(&sha_ctx, finalAuthData, authDataOffset);
        mbedtls_md_update(&sha_ctx, clientDataHash, 32);
        mbedtls_md_finish(&sha_ctx, attestationHash);
        mbedtls_md_free(&sha_ctx);

        uint8_t attestationSig[300];
        size_t attestationSigLen = sizeof(attestationSig);
        
        // Use generic robust signature generation multiplexer from CryptoManager
        bool sigSuccess = generateAlgSignature(selectedAlgId, privateKeyHex, attestationHash, 32, attestationSig, &attestationSigLen);

        if (!sigSuccess) {
            uint8_t err = 0x01;
            sendCtapResponse(channel, CTAPHID_CBOR, &err, 1);
            return;
        }

        encoder.writeUnsignedInt(3);
        encoder.writeMapHeader(2); 
        encoder.writeTextString("alg");
        encoder.writeNegativeInt(selectedAlgId); 
        encoder.writeTextString("sig");
        encoder.writeByteString(attestationSig, attestationSigLen);

        if (hmacSecretRequested) {
            encoder.writeUnsignedInt(4);
            encoder.writeMapHeader(1);
            encoder.writeTextString("hmac-secret");
            encoder.writeBoolean(true);
        }

        sendCtapResponse(channel, CTAPHID_CBOR, responseBuffer, 1 + encoder.getOffset());
        tft.fillScreen(TFT_GREEN);
        tft.println("REGISTERED SUCCESS!");
        return;
    }
    else if (ctap2Cmd == 0x02) {
        static char targetRpId[128];
        static uint8_t clientDataHash[32];
        memset(targetRpId, 0, sizeof(targetRpId));
        memset(clientDataHash, 0, sizeof(clientDataHash));
        
        size_t clientDataHashLen = 0;
        bool optionUP = true; 
        bool optionUV = false;

        // Extension tracking parameters
        bool extensionRequested = false;
        static uint8_t hmacSalt1[32];
        static uint8_t hmacSalt2[32];
        size_t hmacSalt1Len = 0;
        size_t hmacSalt2Len = 0;
        memset(hmacSalt1, 0, sizeof(hmacSalt1));
        memset(hmacSalt2, 0, sizeof(hmacSalt2));

        static const size_t MAX_ALLOW_CREDENTIALS = 32;
        static uint8_t allowCredentialIds[MAX_ALLOW_CREDENTIALS][64];
        static size_t allowCredentialIdLens[MAX_ALLOW_CREDENTIALS];
        memset(allowCredentialIds, 0, sizeof(allowCredentialIds));
        memset(allowCredentialIdLens, 0, sizeof(allowCredentialIdLens));
        size_t allowCredentialCount = 0;

        CborParser parser(data + 1, len - 1);
        uint8_t rootType;
        uint64_t rootElements;

        if (!parser.readTypeAndValue(rootType, rootElements) || rootType != 5) {
            uint8_t err = 0x12; 
            sendCtapResponse(channel, CTAPHID_CBOR, &err, 1);
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
            // Parse Assertion Request Extensions (Key 0x06)
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
            return;
        }

        // 🌟 DYNAMIC ALLOWLIST PRE-FLIGHT RESTRICTIONS ENFORCEMENT:
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
                    break; // Match found!
                }
            }
            
            // If an allowList was specified by the host but none of those IDs exist locally,
            // reject IMMEDIATELY without prompting for biometric authorization.
            if (credentialIdHex == "") {
                uint8_t err = 0x2E; // CTAP2_ERR_NO_CREDENTIALS
                sendCtapResponse(channel, CTAPHID_CBOR, &err, 1);
                return;
            }
        } else {
            // Fallback: search default discoverable/resident credential mapping criteria
            credentialIdHex = findCredentialIdByRpAndUser(String(targetRpId), "");
            if (credentialIdHex == "") {
                uint8_t err = 0x2E; // CTAP2_ERR_NO_CREDENTIALS
                sendCtapResponse(channel, CTAPHID_CBOR, &err, 1);
                return;
            }
        }

        // Now pull full properties safely since credentialIdHex is guaranteed to exist
        String storedRpId, storedUserIdHex, storedUserName, storedPrivateKeyHex;
        int storedAlgId;
        if (!getPasskeyRecord(credentialIdHex, storedRpId, storedUserIdHex, storedUserName, storedPrivateKeyHex, storedAlgId)) {
            uint8_t err = 0x2E; 
            sendCtapResponse(channel, CTAPHID_CBOR, &err, 1); 
            return;
        }

        bool biometricVerified = false;
        if (optionUP || optionUV) {
            if (millis() - lastFingerprintSuccessTime < 5000) {
                biometricVerified = true;
            } else {
                tft.fillScreen(TFT_YELLOW);
                tft.setCursor(10, 20);
                tft.println("VERIFY FINGERPRINT");
                tft.println("TO SIGN IN...");

                bool biometricCanceled = false;
                unsigned long authStart = millis(); unsigned long lastKeepAlive = 0;
                while (millis() - authStart < 15000) {
                    if (hasPendingCommand && pendingCmd == CTAPHID_CANCEL && pendingChannel == channel) {
                        hasPendingCommand = false; // Consume the packet flag
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

                // Handle early abort due to browser cancellation
                if (biometricCanceled) {
                    tft.fillScreen(TFT_BLACK);
                    uint8_t err = 0x2D; // CTAP2_ERR_KEEPALIVE_CANCEL
                    sendCtapResponse(channel, CTAPHID_CBOR, &err, 1);
                    return;
                }
            }
            if (!biometricVerified) {
                uint8_t err = 0x34; sendCtapResponse(channel, CTAPHID_CBOR, &err, 1); return;
            }
        } else { biometricVerified = true; }

        static uint8_t authData[37];
        memset(authData, 0, sizeof(authData));

        mbedtls_md_context_t sha_ctx;
        mbedtls_md_init(&sha_ctx);
        mbedtls_md_setup(&sha_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 0);
        mbedtls_md_starts(&sha_ctx);
        mbedtls_md_update(&sha_ctx, (const unsigned char*)targetRpId, strlen(targetRpId));
        mbedtls_md_finish(&sha_ctx, authData);
        mbedtls_md_free(&sha_ctx);

        uint8_t flags = 0x01; 
        if (optionUV && biometricVerified) { flags |= 0x04; }
        if (extensionRequested) { flags |= 0x80; } // Turn on ED Flag bit indicating extension presence
        authData[32] = flags; 

        uint32_t currentSignCount = loadPersistedSignCount() + 1;
        savePersistedSignCount(currentSignCount);

        authData[33] = (currentSignCount >> 24) & 0xFF;
        authData[34] = (currentSignCount >> 16) & 0xFF;
        authData[35] = (currentSignCount >> 8) & 0xFF;
        authData[36] = (currentSignCount) & 0xFF;
        
        static uint8_t signBuffer[37 + 32];
        memcpy(signBuffer, authData, 37);
        memcpy(signBuffer + 37, clientDataHash, 32);

        static uint8_t hashedMessage[32];
        mbedtls_md_init(&sha_ctx);
        mbedtls_md_setup(&sha_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 0);
        mbedtls_md_starts(&sha_ctx);
        mbedtls_md_update(&sha_ctx, signBuffer, sizeof(signBuffer));
        mbedtls_md_finish(&sha_ctx, hashedMessage);
        mbedtls_md_free(&sha_ctx);

        static uint8_t signatureASN1[300]; // Increased bounds for handling large RSA 2048 keys
        size_t finalSigLen = sizeof(signatureASN1); 

        if (!generateAlgSignature(storedAlgId, storedPrivateKeyHex, hashedMessage, 32, signatureASN1, &finalSigLen)) {
            // SECURITY FIX: Zero out temporary signature calculations and the hashed transaction data
            memset(signatureASN1, 0, sizeof(signatureASN1));
            memset(hashedMessage, 0, sizeof(hashedMessage));
            memset(signBuffer, 0, sizeof(signBuffer));

            // FALLBACK STATE: Reset the screen UI to an idle/error state
            tft.fillScreen(TFT_RED);
            tft.setTextColor(TFT_WHITE, TFT_RED);
            tft.println("SIGNING FAILED");
            delay(2000);
            tft.fillScreen(TFT_BLACK);

            uint8_t err = 0x01; 
            sendCtapResponse(channel, CTAPHID_CBOR, &err, 1); 
            return;
        }

        // Compute HMAC Secret values if the extension is present
        static uint8_t hmacOutput1[32];
        static uint8_t hmacOutput2[32];
        if (extensionRequested && hmacSalt1Len == 32) {
            uint8_t rawKeyBytes[32] = {0};
            // Limit extraction to 32 bytes to support HMAC generic standard across varying lengths of keys
            fromHex(storedPrivateKeyHex, rawKeyBytes, 32);

            // Execute HMAC-SHA-256 (Key = private key portion, Data = salt)
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
            memset(rawKeyBytes, 0, 32); // Clear plain key from RAM safely
        }
        
        static uint8_t localRespBuf[1024]; // Safely handles oversized responses bound by large algorithms
        memset(localRespBuf, 0, sizeof(localRespBuf));
        localRespBuf[0] = 0x00; 

        CborEncoder localEncoder(&localRespBuf[1], 1023);
        
        // Map elements size: 4 standard parameters, 5 if serving extensions
        localEncoder.writeMapHeader(extensionRequested ? 5 : 4); 

        // Key 1: Credential info descriptor
        localEncoder.writeUnsignedInt(0x01); 
        localEncoder.writeMapHeader(2);
        localEncoder.writeTextString("id");
        static uint8_t binCredId[64]; size_t binCredLen = credentialIdHex.length() / 2;
        fromHex(credentialIdHex, binCredId, binCredLen);
        localEncoder.writeByteString(binCredId, binCredLen); 
        localEncoder.writeTextString("type"); localEncoder.writeTextString("public-key");

        // Key 2: Authenticator Data stream
        localEncoder.writeUnsignedInt(0x02); localEncoder.writeByteString(authData, 37);

        // Key 3: Computed Digital signature
        localEncoder.writeUnsignedInt(0x03); localEncoder.writeByteString(signatureASN1, finalSigLen);

        // Key 4: User account context descriptors
        localEncoder.writeUnsignedInt(0x04); localEncoder.writeMapHeader(3); 
        localEncoder.writeTextString("id");
        static uint8_t rawUserIdBytes[64]; size_t parsedUserIdLen = storedUserIdHex.length() / 2;
        fromHex(storedUserIdHex, rawUserIdBytes, parsedUserIdLen);
        localEncoder.writeByteString(rawUserIdBytes, parsedUserIdLen);
        localEncoder.writeTextString("name"); localEncoder.writeTextString(storedUserName.c_str());
        localEncoder.writeTextString("displayName"); localEncoder.writeTextString(storedUserName.c_str()); 

        // Key 5: Output extension map response data
        if (extensionRequested) {
            localEncoder.writeUnsignedInt(0x05);
            localEncoder.writeMapHeader(1);
            localEncoder.writeTextString("hmac-secret");
            localEncoder.writeByteString(hmacOutput1, 32); // Returns raw 32-byte salt output directly
            
            // Note: FIDO2 specification returns raw bytestring directly for single-salt configurations,
            // or concatenated 64 bytes if both salts were calculated.
            if (hmacSalt2Len == 32) {
                // Rewind the single byte write hook and write out full 64
                static uint8_t dualHmac[64];
                memcpy(dualHmac, hmacOutput1, 32);
                memcpy(dualHmac + 32, hmacOutput2, 32);
                
                localEncoder.getOffset(); // Rollback hook visualization logic
                localEncoder.writeMapHeader(1);
                localEncoder.writeTextString("hmac-secret");
                localEncoder.writeByteString(dualHmac, 64);
            }
        }

        size_t finalPayloadSize = localEncoder.getOffset() + 1;
        sendCtapResponse(channel, CTAPHID_CBOR, localRespBuf, finalPayloadSize);

        #if defined(ARDUINO_ARCH_ESP32)
            vTaskDelay(10 / portTICK_PERIOD_MS);
        #else
            delay(10);
        #endif

        tft.fillScreen(TFT_BLACK); tft.setTextColor(TFT_GREEN, TFT_BLACK);
        tft.println("VERIFICATION SUCCESS");
        return;
    }
    else {
        uint8_t err = 0x11; 
        sendCtapResponse(channel, CTAPHID_CBOR, &err, 1);
    }
}

void FIDO2HIDDevice::poll() {
    if (!hasPendingCommand) return;

    uint32_t ch   = pendingChannel;
    uint8_t  cmd  = pendingCmd;
    uint16_t dlen = pendingLen;
    static uint8_t data[sizeof(pendingData)];
    memcpy(data, pendingData, dlen);
    hasPendingCommand = false;

    processCtapCommand(ch, cmd, data, dlen);
}

void FIDO2HIDDevice::_onOutput(uint8_t report_id, const uint8_t* buffer, uint16_t len) {
    if (len < 7) return;

    if (ctapExpectedLen > 0 && (millis() - lastPacketTime > 500)) {
        ctapExpectedLen = 0;
        ctapReceivedLen = 0;
        ctapExpectedSeq = 0;
    }

    uint32_t channel = (buffer[0] << 24) | (buffer[1] << 16) | (buffer[2] << 8) | buffer[3];

    if (buffer[4] & 0x80) { // Initialization Packet
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
        
        if (ctapExpectedLen > sizeof(ctapBuffer)) {
            uint8_t err = 0x01; // CTAPHID_ERR_INVALID_LEN
            sendCtapResponse(channel, CTAPHID_ERROR, &err, 1);
            ctapExpectedLen = 0; 
            ctapReceivedLen = 0;
            return;
        }

        ctapReceivedLen = (ctapExpectedLen > 57) ? 57 : ctapExpectedLen;
        
        // Defensive Check: Ensure incoming report has enough bytes for initialization header + data payload
        if (len < 7 + ctapReceivedLen) {
            ctapExpectedLen = 0;
            ctapReceivedLen = 0;
            return;
        }

        memcpy(ctapBuffer, &buffer[7], ctapReceivedLen);
        ctapExpectedSeq = 0;

        lastPacketTime = millis();
    } 
    else { // Continuation Packet
        if (ctapExpectedLen == 0 || channel != ctapCurrentChannel) return;
        
        if (buffer[4] != ctapExpectedSeq) {
            uint8_t err = 0x04; // CTAPHID_ERR_INVALID_SEQ
            sendCtapResponse(channel, CTAPHID_ERROR, &err, 1);
            ctapExpectedLen = 0; 
            ctapReceivedLen = 0;
            return;
        }
        
        ctapExpectedSeq++;
        uint16_t chunk = (ctapExpectedLen - ctapReceivedLen > 59) ? 59 : (ctapExpectedLen - ctapReceivedLen);
        
        // SECURITY FIX 1: Prevent writing past the end of ctapBuffer
        if (ctapReceivedLen + chunk > sizeof(ctapBuffer)) {
            uint8_t err = 0x01; // CTAPHID_ERR_INVALID_LEN
            sendCtapResponse(channel, CTAPHID_ERROR, &err, 1);
            ctapExpectedLen = 0; 
            ctapReceivedLen = 0;
            return;
        }

        // SECURITY FIX 2: Prevent reading past the end of the incoming USB report array
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
        // SECURITY FIX 3: Ensure we don't copy more than the physical size of pendingData
        uint16_t finalCopyLen = (ctapExpectedLen > sizeof(pendingData)) ? sizeof(pendingData) : ctapExpectedLen;

        pendingChannel = channel;
        pendingCmd = ctapCurrentCmd;
        memcpy(pendingData, ctapBuffer, finalCopyLen);
        pendingLen = finalCopyLen;
        hasPendingCommand = true; 
        
        ctapExpectedLen = 0; 
        ctapReceivedLen = 0;
    }
}

FIDO2HIDDevice FidoHID;