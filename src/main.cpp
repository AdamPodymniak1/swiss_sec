#include <Arduino.h>
#include "Globals.h"
#include "DisplayManager.h"
#include "FingerprintManager.h"
#include "CryptoManager.h"
#include "StorageManager.h"
#include "SelfTestManager.h"
#include "CborEngine.h"

#include "soc/soc.h"
#include "soc/rtc_cntl_reg.h"

#include "USB.h"
#include "USBCDC.h"
#include "USBHID.h"

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecp.h"
#include <EEPROM.h>

// CTAPHID Command Constants
#define CTAPHID_PING  0x81
#define CTAPHID_MSG   0x83
#define CTAPHID_INIT  0x86
#define CTAPHID_WINK  0x88
#define CTAPHID_CBOR  0x90
#define CTAPHID_CANCEL 0x91
#define CTAPHID_ERROR 0xBF
#define CTAPHID_KEEPALIVE 0xBB

#define SIGN_COUNT_ADDR 0 

uint32_t loadPersistedSignCount() {
    uint32_t count = 0;
    // Read 4 bytes from EEPROM
    EEPROM.begin(512); // Initialize EEPROM size if needed
    EEPROM.get(SIGN_COUNT_ADDR, count);
    
    // Safety check: if count is 0xFFFFFFFF (uninitialized), set to 0
    if (count == 0xFFFFFFFF) return 0;
    return count;
}

void savePersistedSignCount(uint32_t count) {
    EEPROM.put(SIGN_COUNT_ADDR, count);
    EEPROM.commit(); // Essential for ESP32/Flash-based EEPROM emulation
}

void dumpHex(const uint8_t* buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (buf[i] < 0x10) Terminal.print("0");
        Terminal.print(buf[i], HEX);
    }
    Terminal.println();
}

// Robust single-shot biometric check shared by the FIDO2 ceremonies.
// The R503 sensor sleeps after inactivity: the first getImage() once a finger is
// placed wakes the UART but returns a comms error instead of FINGERPRINT_OK.
// We retry immediately in the same frame (like the working old.cpp loop) so the
// read isn't lost before the finger is lifted. Without this, the GetAssertion
// loop never matches and the host login times out.
static bool fidoVerifyFingerprint() {
    uint8_t img = finger.getImage();

    // Sensor woke but errored on the first poll -> hammer it a few times right now,
    // instead of waiting a full loop iteration (by then the finger is usually gone).
    for (uint8_t retry = 0; retry < 3 && img != FINGERPRINT_OK && img != FINGERPRINT_NOFINGER; retry++) {
        delay(50);
        img = finger.getImage();
    }

    if (img != FINGERPRINT_OK) return false;              // no finger / still waking
    if (finger.image2Tz() != FINGERPRINT_OK) return false;
    if (finger.fingerSearch() != FINGERPRINT_OK) return false;
    return finger.confidence > 50;                        // reject weak matches
}

void debugAssertInputs(
    const char* rpId,
    uint8_t authData[37],
    uint8_t clientDataHash[32]
) {
    Serial.println("\n===== CTAP DEBUG CHECK =====");

    // 1. Verify authData structure
    Serial.print("authData length: ");
    Serial.println(37);

    Serial.print("flags: 0x");
    Serial.println(authData[32], HEX);

    uint32_t counter =
        (authData[33] << 24) |
        (authData[34] << 16) |
        (authData[35] << 8)  |
        (authData[36]);

    Serial.print("counter: ");
    Serial.println(counter);

    // 2. Recompute RP ID hash for comparison
    uint8_t expectedRpHash[32];

    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);

    const mbedtls_md_info_t* info =
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

    mbedtls_md_setup(&ctx, info, 0);
    mbedtls_md_starts(&ctx);
    mbedtls_md_update(&ctx, (const unsigned char*)rpId, strlen(rpId));
    mbedtls_md_finish(&ctx, expectedRpHash);
    mbedtls_md_free(&ctx);

    Serial.println("\nRP ID hash comparison:");
    Serial.print("Expected: ");
    dumpHex(expectedRpHash, 32);

    Serial.print("Actual  : ");
    dumpHex(authData, 32);

    if (memcmp(expectedRpHash, authData, 32) != 0) {
        Serial.println("❌ RP ID HASH MISMATCH (THIS BREAKS LOGIN)");
    } else {
        Serial.println("✅ RP ID hash OK");
    }

    // 3. Validate sign buffer consistency
    uint8_t signBuffer[69];
    memcpy(signBuffer, authData, 37);
    memcpy(signBuffer + 37, clientDataHash, 32);

    Serial.println("\nSign buffer check:");
    Serial.print("authData part: ");
    dumpHex(signBuffer, 37);

    Serial.print("clientDataHash part: ");
    dumpHex(signBuffer + 37, 32);

    Serial.println("============================\n");
}

bool verifyDebugSignature(
    uint8_t* publicKey,
    uint8_t authData[37],
    uint8_t clientDataHash[32],
    uint8_t* signature,
    size_t sigLen
) {
    uint8_t msg[69];
    memcpy(msg, authData, 37);
    memcpy(msg + 37, clientDataHash, 32);

    uint8_t hash[32];

    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);

    const mbedtls_md_info_t* info =
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

    mbedtls_md_setup(&ctx, info, 0);
    mbedtls_md_starts(&ctx);
    mbedtls_md_update(&ctx, msg, 69);
    mbedtls_md_finish(&ctx, hash);
    mbedtls_md_free(&ctx);

    Serial.print("Message hash: ");
    dumpHex(hash, 32);

    // OPTIONAL: plug into verify function if you have one
    return true;
}

static const uint8_t fido_report_descriptor[] = {
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

class FIDO2HIDDevice : public USBHIDDevice {
private:
    USBHID hid;
    
    // CTAPHID Reassembly State Machine
    uint32_t activeChannelID = 0;
    uint8_t  ctapBuffer[1024];
    uint16_t ctapExpectedLen = 0;
    uint16_t ctapReceivedLen = 0;
    uint8_t  ctapExpectedSeq = 0;
    uint8_t  ctapCurrentCmd = 0;
    uint32_t ctapCurrentChannel = 0;

public:
    volatile bool hasPendingCommand = false;
    uint32_t pendingChannel = 0;
    uint8_t pendingCmd = 0;
    uint8_t pendingData[1024];
    uint16_t pendingLen = 0;

    FIDO2HIDDevice() {
        hid.addDevice(this, sizeof(fido_report_descriptor));
    }
    
    void begin() { hid.begin(); }

    uint16_t _onGetDescriptor(uint8_t* dst) override {
        memcpy(dst, fido_report_descriptor, sizeof(fido_report_descriptor));
        return sizeof(fido_report_descriptor);
    }

    // Handles fragmenting large CTAP payloads into 64-byte chunks
    void sendCtapResponse(uint32_t channel, uint8_t cmd, const uint8_t* data, uint16_t len) {
        uint8_t packet[64] = {0};
        uint16_t offset = 0;

        // 1. INIT Packet (Frame 0)
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

        // Force-retry until the INIT packet successfully clears the USB buffer
        while (!hid.SendReport(0, packet, 64)) {
            delay(1); 
        }
        offset += chunkLen;

        // 2. Continuation Packets
        uint8_t seq = 0;
        while (offset < len) {
            memset(packet, 0, 64);
            packet[0] = (channel >> 24) & 0xFF;
            packet[1] = (channel >> 16) & 0xFF;
            packet[2] = (channel >> 8) & 0xFF;
            packet[3] = channel & 0xFF;
            
            // --- FIX: Ensure high bit is never set (max 127 continuation packets) ---
            packet[4] = seq & 0x7F;

            chunkLen = (len - offset > 59) ? 59 : (len - offset);
            if (chunkLen > 0 && data != nullptr) {
                memcpy(&packet[5], data + offset, chunkLen);
            }

            if (hid.SendReport(0, packet, 64)) {
                offset += chunkLen;
                seq++;
            } else {
                delay(2); // Slightly longer delay to allow USB buffer clearing
            }
        }
    }

    // High-level CTAP2 Command Router
    void processCtapCommand(uint32_t channel, uint8_t cmd, uint8_t* data, uint16_t len) {
        if (cmd == CTAPHID_INIT) {
            // FIX: Prevent out-of-bounds memory reads if payload is malformed
            if (len < 8) {
                uint8_t err = 0x01; // CTAPHID_ERR_INVALID_LEN
                sendCtapResponse(channel, CTAPHID_ERROR, &err, 1);
                return;
            }

            uint8_t resp[17] = {0};
            memcpy(resp, data, 8); // Echo 8-byte nonce
            
            uint32_t newCid = esp_random();
            if (newCid == 0) newCid = 1; // avoid CID 0
            activeChannelID = newCid; // Allocate dynamic channel

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
            sendCtapResponse(channel, CTAPHID_PING, data, len); // Echo payload
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

    // Inner CTAP2 CBOR Command Execution
    void processCborCommand(uint32_t channel, uint8_t* data, uint16_t len) {
        if (len == 0) return;
        uint8_t ctap2Cmd = data[0];

        uint8_t responseBuffer[512];
        responseBuffer[0] = 0x00; // CTAP2_OK Status code
        CborEncoder encoder(&responseBuffer[1], 511);

        // ==========================================
        // COMMAND 0x04: authenticatorGetInfo
        // ==========================================
        if (ctap2Cmd == 0x04) {
            responseBuffer[0] = 0x00;
            CborEncoder encoder(&responseBuffer[1], 511);

            encoder.writeMapHeader(8);

            // versions
            encoder.writeUnsignedInt(1);
            encoder.writeArrayHeader(1);
            encoder.writeTextString("FIDO_2_0");

            // aaguid
            encoder.writeUnsignedInt(3);

            uint8_t aaguid[16] = {
                0x11,0x22,0x33,0x44,
                0x55,0x66,0x77,0x88,
                0x99,0xAA,0xBB,0xCC,
                0xDD,0xEE,0xFF,0x00
            };

            encoder.writeByteString(aaguid, 16);

            // options
            encoder.writeUnsignedInt(4);
            encoder.writeMapHeader(3);

            encoder.writeTextString("rk");
            encoder.writeBoolean(true);

            encoder.writeTextString("up");
            encoder.writeBoolean(true);

            encoder.writeTextString("uv");
            encoder.writeBoolean(true);

            // maxMsgSize
            encoder.writeUnsignedInt(5);
            encoder.writeUnsignedInt(1024);

            // maxCredentialCountInList
            encoder.writeUnsignedInt(7);
            encoder.writeUnsignedInt(8);

            // maxCredentialIdLength
            encoder.writeUnsignedInt(8);
            encoder.writeUnsignedInt(64);

            // transports
            encoder.writeUnsignedInt(9);
            encoder.writeArrayHeader(1);
            encoder.writeTextString("usb");

            // algorithms
            encoder.writeUnsignedInt(10);
            encoder.writeArrayHeader(1);

            encoder.writeMapHeader(2);

            encoder.writeTextString("alg");
            encoder.writeNegativeInt(-7);

            encoder.writeTextString("type");
            encoder.writeTextString("public-key");

            sendCtapResponse(
                channel,
                CTAPHID_CBOR,
                responseBuffer,
                1 + encoder.getOffset()
            );

            return;
        }
        else if (ctap2Cmd == 0x0B) { // authenticatorSelection
            responseBuffer[0] = 0x00;
            sendCtapResponse(channel, CTAPHID_CBOR, responseBuffer, 1);
            return;
        }
        // ==========================================
        // COMMAND 0x01: authenticatorMakeCredential (REGISTRATION)
        // ==========================================
        else if (ctap2Cmd == 0x01) { // authenticatorMakeCredential
            if (!authenticated) {
                uint8_t err = 0x31; // CTAP2_ERR_PUAT_REQUIRED
                sendCtapResponse(channel, CTAPHID_CBOR, &err, 1);
                return; 
            }

            // Initialize State Variables
            char targetRpId[128] = {0};
            uint8_t userIdRaw[64] = {0};
            size_t userIdLen = 0;
            char userName[128] = {0};

            // 1. BOUNDS-CHECKED STREAM PARSING OF REQUEST MAP
            CborParser parser(data + 1, len - 1);
            uint8_t rootType;
            uint64_t rootElements;

            if (parser.readTypeAndValue(rootType, rootElements) && rootType == 5) {
                for (uint64_t i = 0; i < rootElements; i++) {
                    uint8_t keyType;
                    uint64_t mapKey;
                    if (!parser.readTypeAndValue(keyType, mapKey) || keyType != 0) {
                        parser.skipValue(); // Unexpected key type
                        continue;
                    }

                    if (mapKey == 0x02) { // RP Entity Map
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
                    else if (mapKey == 0x03) { // User Entity Map
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
                    else {
                        parser.skipValue(); // Bypass parameters (0x01, 0x04, 0x07 etc.)
                    }
                }
            }

            // Fail immediately if host parsing conditions aren't satisfied
            if (strlen(targetRpId) == 0 || userIdLen == 0) {
                uint8_t err = 0x0A; // CTAP2_ERR_MISSING_PARAMETER
                sendCtapResponse(channel, CTAPHID_CBOR, &err, 1);
                return;
            }

            // 2. BIOMETRIC INTERACTIVE LOOP
            tft.fillScreen(TFT_YELLOW);
            tft.setCursor(10, 20);
            tft.println("PLACE FINGER...");
            
            bool biometricVerified = false;
            unsigned long authStart = millis();
            unsigned long lastKeepAlive = 0;
            
            while (millis() - authStart < 15000) {
                if (millis() - lastKeepAlive > 500) {
                    uint8_t status = 0x02; // TUP_NEEDED
                    sendCtapResponse(channel, CTAPHID_KEEPALIVE, &status, 1); 
                    lastKeepAlive = millis();
                }
                
                if (fidoVerifyFingerprint()) {
                    biometricVerified = true;
                    break;
                }
                delay(50);
            }

            if (!biometricVerified) {
                uint8_t err = 0x34; // CTAP2_ERR_USER_ACTION_TIMEOUT
                sendCtapResponse(channel, CTAPHID_CBOR, &err, 1);
                return;
            }

            // 3. CRYPTOGRAPHIC KEYPAIR GENERATION
            uint8_t private_key_d[32] = {0};
            uint8_t x_coords[32] = {0};
            uint8_t y_coords[32] = {0};
            uint8_t public_key[65] = {0};

            if (!generateKeypairP256(private_key_d, public_key)) {
                uint8_t err = 0x01;
                sendCtapResponse(channel, CTAPHID_CBOR, &err, 1);
                return;
            }

            memcpy(x_coords, public_key + 1, 32);
            memcpy(y_coords, public_key + 33, 32);

            Serial.print("[REG] privKey: ");
            for (int _i = 0; _i < 32; _i++) Serial.printf("%02x", private_key_d[_i]);
            Serial.println();
            Serial.print("[REG] pubKey X: ");
            for (int _i = 0; _i < 32; _i++) Serial.printf("%02x", x_coords[_i]);
            Serial.println();
            Serial.print("[REG] pubKey Y: ");
            for (int _i = 0; _i < 32; _i++) Serial.printf("%02x", y_coords[_i]);
            Serial.println();

            // =====================================================
            // FORCE ALIGNED TOHEX SERIALIZATION
            // =====================================================
            uint8_t rawCredId[16];
            for(int i = 0; i < 16; i++) rawCredId[i] = esp_random() & 0xFF;
            
            String credentialIdHex = toHex(rawCredId, 16);
            String userIdHex = toHex(userIdRaw, userIdLen);
            
            // Hardened string translation pass to verify strict 64-character formatting
            char privKeyStringBuf[65] = {0};
            for (int i = 0; i < 32; i++) {
                sprintf(&privKeyStringBuf[i * 2], "%02x", private_key_d[i]);
            }
            String privateKeyHex = String(privKeyStringBuf);

            // Write-Path Attempt
            if (!savePasskeyRecord(credentialIdHex, String(targetRpId), userIdHex, String(userName), privateKeyHex)) {
                uint8_t err = 0x21; // CTAP2_ERR_KEY_STORE_FULL
                sendCtapResponse(channel, CTAPHID_CBOR, &err, 1);
                return;
            }

            // CRITICAL VERIFICATION CHECK: Confirm data persistence before finalizing
            String verifyRpId, verifyUser, verifyName, verifyKey;
            if (!getPasskeyRecord(credentialIdHex, verifyRpId, verifyUser, verifyName, verifyKey) || verifyKey != privateKeyHex) {
                uint8_t err = 0x22; // CTAP2_ERR_CHANGES_NOT_PERSISTED
                sendCtapResponse(channel, CTAPHID_CBOR, &err, 1);
                return;
            }

            // 5. ASSEMBLE ATTESTATION RESPONSE OBJECT (FIXED & SYNCHRONIZED)
            uint8_t responseBuffer[512];
            responseBuffer[0] = 0x00; // CTAP2_OK
            CborEncoder encoder(&responseBuffer[1], 511);

            encoder.writeMapHeader(3);
            encoder.writeUnsignedInt(1);
            encoder.writeTextString("none");

            encoder.writeUnsignedInt(2);
            uint8_t authData[200] = {0};
            
            // Hash the dynamically captured RP ID
            mbedtls_md_context_t sha_ctx;
            mbedtls_md_init(&sha_ctx);
            mbedtls_md_setup(&sha_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 0);
            mbedtls_md_starts(&sha_ctx);
            mbedtls_md_update(&sha_ctx, (const unsigned char *)targetRpId, strlen(targetRpId));
            mbedtls_md_finish(&sha_ctx, &authData[0]);
            mbedtls_md_free(&sha_ctx);

            // =====================================================
            // PATCH 1: SYNCHRONIZED 4-BYTE BIG-ENDIAN COUNTER
            // =====================================================
            authData[32] = 0x45; // Flags: UP + UV + AT

            uint32_t startingSignCount = loadPersistedSignCount();
            authData[33] = (uint8_t)((startingSignCount >> 24) & 0xFF);
            authData[34] = (uint8_t)((startingSignCount >> 16) & 0xFF);
            authData[35] = (uint8_t)((startingSignCount >> 8) & 0xFF);
            authData[36] = (uint8_t)(startingSignCount & 0xFF); // Sets base offset cleanly to 0x00000001
            
            uint8_t aaguid[16] = {0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x00};
            memcpy(&authData[37], aaguid, 16);
            
            authData[53] = 0x00; authData[54] = 0x10; // Credential Length (16)
            memcpy(&authData[55], rawCredId, 16);

            // =====================================================
            // PATCH 2: CANONICAL SPEC-COMPLIANT COSE KEY STRUCTS
            // =====================================================
            // Maps integer key markers directly: 1->2 (EC2), 3->-7 (ES256), -1->1 (P256), -2->X_COORD
            uint8_t coseHeader[10] = {0xA5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20};
            
            // Map integer subkey directly: -3->Y_COORD
            uint8_t coseYHeader[3]  = {0x22, 0x58, 0x20};

            uint8_t finalAuthData[250];
            int offset = 0;
            memcpy(&finalAuthData[offset], authData, 71); offset += 71;
            memcpy(&finalAuthData[offset], coseHeader, 10); offset += 10;
            memcpy(&finalAuthData[offset], x_coords, 32); offset += 32;
            memcpy(&finalAuthData[offset], coseYHeader, 3); offset += 3;
            memcpy(&finalAuthData[offset], y_coords, 32); offset += 32;

            Serial.print("[REG] finalAuthData (" ); Serial.print(offset); Serial.print("B): ");
            for (int _i = 0; _i < offset; _i++) Serial.printf("%02x", finalAuthData[_i]);
            Serial.println();

            encoder.writeByteString(finalAuthData, offset);

            encoder.writeUnsignedInt(3);
            encoder.writeMapHeader(0);

            // Send packet frame down the communication conduit
            sendCtapResponse(channel, CTAPHID_CBOR, responseBuffer, 1 + encoder.getOffset());
            
            tft.fillScreen(TFT_GREEN);
            tft.println("REGISTERED SUCCESS!");
            return;
        }
        else if (ctap2Cmd == 0x02) {
            Serial.print("[RAW] GetAssertion bytes: ");
            for (int _i = 1; _i < (int)len && _i < 128; _i++)
                Serial.printf("%02X", data[_i]);
            Serial.println();

            char targetRpId[128] = {0};

            uint8_t clientDataHash[32] = {0};
            size_t clientDataHashLen = 0;

            static const size_t MAX_ALLOW_CREDENTIALS = 32;
            static uint8_t allowCredentialIds[MAX_ALLOW_CREDENTIALS][64];
            static size_t allowCredentialIdLens[MAX_ALLOW_CREDENTIALS];
            memset(allowCredentialIds, 0, sizeof(allowCredentialIds));
            memset(allowCredentialIdLens, 0, sizeof(allowCredentialIdLens));
            size_t allowCredentialCount = 0;

            // =====================================================
            // 1. PARSE authenticatorGetAssertion REQUEST
            // =====================================================
            CborParser parser(data + 1, len - 1);

            uint8_t rootType;
            uint64_t rootElements;

            if (!parser.readTypeAndValue(rootType, rootElements) || rootType != 5) {
                uint8_t err = 0x12; // CTAP2_ERR_INVALID_CBOR
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
                    uint8_t arrType;
                    uint64_t arrCount;

                    if (parser.readTypeAndValue(arrType, arrCount) && arrType == 4) {
                        for (uint64_t a = 0; a < arrCount; a++) {
                            uint8_t mapType;
                            uint64_t mapElements;

                            if (parser.readTypeAndValue(mapType, mapElements) && mapType == 5) {
                                for (uint64_t j = 0; j < mapElements; j++) {
                                    char key[32] = {0};
                                    if (!parser.readTextString(key, sizeof(key))) {
                                        parser.skipValue();
                                        continue;
                                    }

                                    if (strcmp(key, "id") == 0) {
                                        if (allowCredentialCount < MAX_ALLOW_CREDENTIALS &&
                                            parser.readByteString(allowCredentialIds[allowCredentialCount],
                                                                  sizeof(allowCredentialIds[allowCredentialCount]),
                                                                  allowCredentialIdLens[allowCredentialCount])) {
                                            allowCredentialCount++;
                                        } else {
                                            parser.skipValue();
                                        }
                                    }
                                    else {
                                        parser.skipValue();
                                    }
                                }
                            }
                        }
                    }
                }
                else {
                    parser.skipValue();
                }
            }

            Terminal.print("DEBUG: Length of RP ID: "); Terminal.println(strlen(targetRpId));

            // =====================================================
            // 2. VALIDATE REQUEST
            // =====================================================
            if (strlen(targetRpId) == 0 || clientDataHashLen != 32) {
                uint8_t err = 0x0A; // CTAP2_ERR_MISSING_PARAMETER
                sendCtapResponse(channel, CTAPHID_CBOR, &err, 1);
                return;
            }

            // =====================================================
            // 3. FIND CREDENTIAL
            // =====================================================
            String credentialIdHex;

            if (allowCredentialCount > 0) {
                for (size_t i = 0; i < allowCredentialCount; i++) {
                    String candidateIdHex = toHex(allowCredentialIds[i], allowCredentialIdLens[i]);
                    String candidateRpId;
                    String candidateUserIdHex;
                    String candidateUserName;
                    String candidatePrivateKeyHex;

                    if (getPasskeyRecord(candidateIdHex, candidateRpId, candidateUserIdHex,
                                         candidateUserName, candidatePrivateKeyHex) &&
                        candidateRpId == String(targetRpId)) {
                        credentialIdHex = candidateIdHex;
                        break;
                    }
                }
            }
            else {
                credentialIdHex = findCredentialIdByRpAndUser(String(targetRpId), "");
            }

            if (credentialIdHex == "") {
                uint8_t err = 0x2E; // CTAP2_ERR_NO_CREDENTIALS
                sendCtapResponse(channel, CTAPHID_CBOR, &err, 1);
                return;
            }

            // =====================================================
            // 4. LOAD STORED CREDENTIAL
            // =====================================================
            String storedRpId;
            String storedUserIdHex;
            String storedUserName;
            String storedPrivateKeyHex;

            if (!getPasskeyRecord(credentialIdHex, storedRpId, storedUserIdHex, storedUserName, storedPrivateKeyHex)) {
                uint8_t err = 0x2E;
                sendCtapResponse(channel, CTAPHID_CBOR, &err, 1);
                return;
            }

            if (storedRpId != String(targetRpId)) {
                uint8_t err = 0x2E;
                sendCtapResponse(channel, CTAPHID_CBOR, &err, 1);
                return;
            }

            // =====================================================
            // 5. BIOMETRIC VERIFICATION
            // =====================================================
            tft.fillScreen(TFT_YELLOW);
            tft.setCursor(10, 20);
            tft.println("VERIFY FINGERPRINT");
            tft.println("TO SIGN IN...");

            bool biometricVerified = false;
            unsigned long authStart = millis();
            unsigned long lastKeepAlive = 0;

            // Wait up to 15 seconds for a valid fingerprint
            while (millis() - authStart < 15000) {
                // Safely send the "User Presence Needed" keepalive every 500ms
                if (millis() - lastKeepAlive > 500) {
                    uint8_t status = 0x02; // 0x02 = UP_NEEDED
                    sendCtapResponse(channel, CTAPHID_KEEPALIVE, &status, 1);
                    lastKeepAlive = millis();
                }

                // Check fingerprint sensor (wake-up aware; see fidoVerifyFingerprint)
                if (fidoVerifyFingerprint()) {
                    biometricVerified = true;
                    break; // Finger matched! Exit the loop.
                }
                delay(50);
            }

            // If the loop timed out without a valid finger, tell Windows we failed.
            if (!biometricVerified) {
                uint8_t err = 0x34; // CTAP2_ERR_OPERATION_DENIED
                sendCtapResponse(channel, CTAPHID_CBOR, &err, 1);
                return;
            }

            // DO NOT PUT ANY KEEPALIVES OR DELAYS HERE!
            // The USB endpoint is now clear and ready to blast the CBOR response.

            // =====================================================
            // 6. BUILD AUTHDATA
            // =====================================================
            static uint8_t authData[37];
            memset(authData, 0, sizeof(authData));

            uint32_t currentSignCount = loadPersistedSignCount();
            currentSignCount++;
            savePersistedSignCount(currentSignCount);

            // --- RP ID HASH (stable + safe) ---
            mbedtls_md_context_t sha_ctx;
            mbedtls_md_init(&sha_ctx);

            const mbedtls_md_info_t* info =
                mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

            mbedtls_md_setup(&sha_ctx, info, 0);
            mbedtls_md_starts(&sha_ctx);

            // IMPORTANT: ensure clean rpId string
            char cleanRpId[128];
            memset(cleanRpId, 0, sizeof(cleanRpId));
            strncpy(cleanRpId, targetRpId, sizeof(cleanRpId) - 1);

            mbedtls_md_update(&sha_ctx,
                            (const unsigned char*)cleanRpId,
                            strlen(cleanRpId));

            mbedtls_md_finish(&sha_ctx, authData);
            mbedtls_md_free(&sha_ctx);

            // --- FLAGS ---
            authData[32] = 0x05; // UP + UV

            // --- COUNTER (BIG ENDIAN) ---
            authData[33] = (currentSignCount >> 24) & 0xFF;
            authData[34] = (currentSignCount >> 16) & 0xFF;
            authData[35] = (currentSignCount >> 8) & 0xFF;
            authData[36] = (currentSignCount) & 0xFF;

            // =====================================================
            // 7. SIGN authData || clientDataHash
            // =====================================================
            
            // STATIC zapobiega wyjebaniu stosu pamięci na ESP32, chuja chuja, nie ruszaj tego
            static uint8_t signBuffer[69];
            static uint8_t hashedMessage[32];
            static uint8_t signatureASN1[100];

            memset(signBuffer, 0, sizeof(signBuffer));
            memset(hashedMessage, 0, sizeof(hashedMessage));
            memset(signatureASN1, 0, sizeof(signatureASN1));

            // --- BUILD MESSAGE ---
            memcpy(signBuffer, authData, 37);
            memcpy(signBuffer + 37, clientDataHash, 32);

            // --- DEBUG (SAFE PRINT) ---
            Serial.println("\n[DEBUG] SIGN BUFFER:");
            for (int i = 0; i < 69; i++) {
                Serial.printf("%02X", signBuffer[i]);
            }
            Serial.println();

            // --- HASH WEBAUTHN SIGNATURE INPUT ---
            mbedtls_md_context_t ctx;
            mbedtls_md_init(&ctx);
            const mbedtls_md_info_t* infoSign = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
            mbedtls_md_setup(&ctx, infoSign, 0);
            mbedtls_md_starts(&ctx);
            mbedtls_md_update(&ctx, signBuffer, sizeof(signBuffer));
            mbedtls_md_finish(&ctx, hashedMessage);
            mbedtls_md_free(&ctx);

            size_t finalSigLen = sizeof(signatureASN1); 
            
            // Generujemy podpis. Zauważ, kurwa, że wywaliłem ten stary encoder stąd!
            Serial.print("[LOGIN] privKey: ");
            Serial.println(storedPrivateKeyHex);

            if (!generateFido2Signature(storedPrivateKeyHex, hashedMessage, 32, signatureASN1, &finalSigLen)) {
                Serial.println("[ERR] SIGN FAILED");
                uint8_t err = 0x01; // CTAP1_ERR_INVALID_COMMAND
                sendCtapResponse(channel, CTAPHID_CBOR, &err, 1);
                return;
            }
            
            // =====================================================
            // 8. BUILD ASSERTION RESPONSE (NAPRAWIONE)
            // =====================================================
            // Boże, błagam, żeby to zadziałało. Używamy NOWEJ, czystej struktury, 
            // żeby poprzedni encoder z początku funkcji nas nie sabotował.
            
            uint8_t localRespBuf[512];
            localRespBuf[0] = 0x00; // Success status code (CTAP2_OK)

            CborEncoder localEncoder(&localRespBuf[1], 511);

            // Oddajemy dokładnie 4 klucze: 1 (credential), 2 (authData), 3 (signature), 4 (user)
            localEncoder.writeMapHeader(4); 

            // --- Key 1: Credential Descriptor ---
            localEncoder.writeUnsignedInt(0x01); 
            localEncoder.writeMapHeader(2);
            // KANONICZNE SORTOWANIE (nie psuj tego!): "id" (dł. 2) musi być przed "type" (dł. 4)
            localEncoder.writeTextString("id");
            
            uint8_t binCredId[64];
            size_t binCredLen = credentialIdHex.length() / 2;
            if (binCredLen > sizeof(binCredId)) binCredLen = sizeof(binCredId); // Zabezpieczenie przed overflowem
            fromHex(credentialIdHex, binCredId, binCredLen);
            localEncoder.writeByteString(binCredId, binCredLen); 
            
            localEncoder.writeTextString("type");
            localEncoder.writeTextString("public-key");

            // --- Key 2: Authenticator Data ---
            localEncoder.writeUnsignedInt(0x02);
            localEncoder.writeByteString(authData, 37);

            // --- Key 3: Signature ---
            localEncoder.writeUnsignedInt(0x03);
            localEncoder.writeByteString(signatureASN1, finalSigLen);

            // --- Key 4: User Entity ---
            // Windows dostaje szału jak tu czegoś brakuje przy resident keys!
            localEncoder.writeUnsignedInt(0x04);
            localEncoder.writeMapHeader(3); 
            
            // Kanonicznie: "id" (2), "name" (4), "displayName" (11)
            localEncoder.writeTextString("id");
            uint8_t rawUserIdBytes[64] = {0};
            size_t userIdLen = storedUserIdHex.length() / 2;
            if (userIdLen > sizeof(rawUserIdBytes)) userIdLen = sizeof(rawUserIdBytes);
            fromHex(storedUserIdHex, rawUserIdBytes, userIdLen);
            localEncoder.writeByteString(rawUserIdBytes, userIdLen);
            
            localEncoder.writeTextString("name");
            localEncoder.writeTextString(storedUserName.c_str());

            localEncoder.writeTextString("displayName");
            localEncoder.writeTextString(storedUserName.c_str()); // Wymagane przez specyfikację CTAP2!

            // --- TRANSMIT ---
            // Liczymy offset bezpiecznie używając naszego świeżego lokalnego encodera
            size_t finalPayloadSize = localEncoder.getOffset() + 1;
            sendCtapResponse(channel, CTAPHID_CBOR, localRespBuf, finalPayloadSize);

            // Daj USB chwilę na wypchnięcie ostatnich ramek odpowiedzi.
            #if defined(ARDUINO_ARCH_ESP32)
                vTaskDelay(10 / portTICK_PERIOD_MS);
            #else
                delay(10);
            #endif

            tft.fillScreen(TFT_BLACK);
            tft.setTextColor(TFT_GREEN, TFT_BLACK);
            tft.println("VERIFICATION SUCCESS");

            // UWAGA: zero logow Serial/Terminal w tym miejscu. Wczesniejszy dlugi dump
            // diagnostyczny (a) blokowal powrot z ceremonii na ~100 ms, dajac _onOutput
            // czas na zakolejkowanie kolejnego GetAssertion, ktore poll() potem kasowal
            // (login -> timeout), oraz (b) ryzykowal kolizje na stosie USB. Flage kolejki
            // czysci wylacznie poll(), juz po powrocie stad.
            return;
        }
        // ==========================================
        // OTHER COMMANDS (Assertion/Login)
        // ==========================================
        else {
            uint8_t err = 0x11; // CTAP2_ERR_UNSUPPORTED_OPTION
            sendCtapResponse(channel, CTAPHID_CBOR, &err, 1);
        }
    }

    void poll() {
        if (!hasPendingCommand) return;

        // Zrob snapshot zadania i ZWOLNIJ kolejke PRZED przetwarzaniem. Ceremonia
        // GetAssertion blokuje tu na sekundy (czekanie na palec); zaraz po odpowiedzi
        // na pre-flight up:false Windows wysyla prawdziwy GetAssertion up:true.
        // _onOutput musi moc go zakolejkowac w trakcie - inaczej (czyszczenie flagi
        // PO przetworzeniu) swieze zadanie zostaje skasowane i host nigdy nie dostaje
        // asercji (login -> timeout).
        //
        // Dane snapshotujemy do lokalnego bufora, bo po zwolnieniu flagi _onOutput
        // moze nadpisac pendingData kolejnym zadaniem, gdy jeszcze konczymy to.
        uint32_t ch   = pendingChannel;
        uint8_t  cmd  = pendingCmd;
        uint16_t dlen = pendingLen;
        static uint8_t data[sizeof(pendingData)];
        memcpy(data, pendingData, dlen);
        hasPendingCommand = false;

        processCtapCommand(ch, cmd, data, dlen);
    }

    // Hardware Capture Point - Demuxer
    void _onOutput(uint8_t report_id, const uint8_t* buffer, uint16_t len) override {
        if (len < 7) return;

        uint32_t channel = (buffer[0] << 24) | (buffer[1] << 16) | (buffer[2] << 8) | buffer[3];

        // 1. Process an Initialization Packet (Command bit 7 is set)
        if (buffer[4] & 0x80) {
            uint8_t cmd = buffer[4];

            // If it's a KEEP-ALIVE or CANCEL response/status frame from the host, 
            // do not flag it as a busy violation or overwrite the active processing buffer.
            if (hasPendingCommand && channel == pendingChannel) {
                // Let the host query the device without resetting our cryptographic state
                return; 
            }
            
            // If it's a completely different command trying to interrupt an active process:
            if (hasPendingCommand) {
                uint8_t err = 0x05; // CTAPHID_ERR_CHANNEL_BUSY
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
            memcpy(ctapBuffer, &buffer[7], ctapReceivedLen);
            ctapExpectedSeq = 0;
        } 
        // 2. Process Continuation Packets
        else {
            // Guard: If we aren't expecting data or data belongs to an inactive channel, drop it safely
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
            memcpy(ctapBuffer + ctapReceivedLen, &buffer[5], chunk);
            ctapReceivedLen += chunk;
        }

        // 3. Queue the fully reassambled packet for processing
        if (ctapExpectedLen > 0 && ctapReceivedLen >= ctapExpectedLen) {
            pendingChannel = channel;
            pendingCmd = ctapCurrentCmd;
            memcpy(pendingData, ctapBuffer, ctapExpectedLen);
            pendingLen = ctapExpectedLen;
            hasPendingCommand = true; 
            
            // Clear tracking variables so background frames can't re-trigger this block
            ctapExpectedLen = 0; 
            ctapReceivedLen = 0;
        }
    }
};

FIDO2HIDDevice FidoHID;

// Explicit global redirect to protect existing core execution logic
// =========================================================================

void setup() {
    WRITE_PERI_REG(RTC_CNTL_BROWN_OUT_REG, 0);

    #ifdef RGB_BUILTIN
        pinMode(RGB_BUILTIN, OUTPUT);
        neopixelWrite(RGB_BUILTIN, 0, 0, 0);
    #endif

    tft.init();
    tft.setRotation(1); 
    tft.fillScreen(TFT_BLACK);
    tft.setTextColor(TFT_WHITE, TFT_BLACK);
    tft.setTextSize(2);
    tft.setCursor(10, 20);
    tft.println("[SYS] BOOTING...");

    // Fire up the multi-interface USB device stack layers concurrently
    Serial.begin(115200);
    FidoHID.begin();
    USB.begin();

    // Give the USB CDC driver a solid chance to lock tracking frequencies
    unsigned long startMillis = millis();
    while (!Serial && (millis() - startMillis < 4000)) delay(10);

    // Clear serial rings completely before initial crypto sequences kick off
    delay(200);
    Serial.flush();
    while(Serial.available() > 0) { Serial.read(); }

    initCrypto();

    if (!initStorage()) {
        Serial.println("[SYS] ERR:SPIFFS_MOUNT_FAILED");
        tft.fillScreen(TFT_RED);
        tft.setCursor(10, 20);
        tft.println("SPIFFS FAILED");
        return;
    }

    initFingerprintSensor();

    tft.fillScreen(TFT_BLACK);
    tft.setCursor(10, 20);
    tft.println("Awaiting Auth...");
}

void loop() {
    FidoHID.poll();
    // 1. Check asynchronous hardware sensors first
    updateFingerprintAsync();

    // 2. Early exit out of serial processing pipeline if frame buffers are empty
    if (!Serial.available()) return;

    String rawInput = Serial.readStringUntil('\n');
    rawInput.trim();
    String input = rawInput;

    // Global Check: Handshake evaluation engine
    if (rawInput.startsWith("DH_INIT:")) {
        processHandshake(rawInput.substring(8));
        authenticated = false;
        currentCommandState = STATE_READY;
        Terminal.flush();
        return;
    }

    // Secure Decryption Layer
    if (rawInput.startsWith("ENC:")) {
        input = decryptMsg(rawInput);
        if (input == "") return; 
    }
    else if (encryptionActive) {
        return; // Drop unencrypted frames if encryption state engine demands tunnel enforcement
    }

    // Global Administrative Interrupt Framework
    if (input == "RESTART_SYSTEM") {
        authenticated = false;
        clearStorageKey();
        currentCommandState = STATE_READY;
        tft.fillScreen(TFT_BLACK);
        tft.setCursor(10, 20);
        tft.println("Awaiting Auth...");
        Terminal.println("[SYS] STATUS:BOOT");
        if (!isMasterPinSet()) {
            Terminal.println("[AUTH] STATUS:NO_MASTER_PIN_SET");
        } else if (!isPinSet()) {
            Terminal.println("[AUTH] STATUS:NEW_PIN_REQ");
        } else {
            Terminal.println("[AUTH] STATUS:PIN_REQ");
        }
        Terminal.flush();
        return;
    }

    if (input == "DISCONNECT") {
        authenticated = false;
        encryptionActive = false;
        clearStorageKey();
        currentCommandState = STATE_READY;
        tft.fillScreen(TFT_BLACK);
        tft.setCursor(10, 20);
        tft.println("Disconnected.");
        Terminal.println("[SYS] STATUS:DISCONNECTED");
        Terminal.flush();
        return;
    }

    // STEP 1: INITIAL PIN / MASTER PIN ENFORCEMENT ENGINE
    if (!isMasterPinSet()) {
        if (currentCommandState != STATE_AWAITING_MASTER_PIN_SETUP) {
            Terminal.println("[AUTH] STATUS:NO_MASTER_PIN_SET");
            Terminal.println("[AUTH] REQ:CREATE_MASTER_PIN");
            Terminal.flush();
            currentCommandState = STATE_AWAITING_MASTER_PIN_SETUP;
            return;
        } else {
            if (createMasterPinPBKDF2(input)) {
                Terminal.println("[AUTH] STATUS:MASTER_PIN_CREATED");
                Terminal.println("[AUTH] STATUS:NEW_PIN_REQ");
                currentCommandState = STATE_READY;
            } else {
                Terminal.println("[ERR] CODE:MASTER_PIN_GEN_FAIL");
            }
            Terminal.flush();
            return;
        }
    }

    if (!isPinSet()) {
        createPin(input);
        Terminal.println("[AUTH] STATUS:PIN_CREATED");
        Terminal.println("[AUTH] STATUS:PIN_REQ");
        Terminal.flush();
        return;
    }

    if (!authenticated) {
        if (verifyPin(input)) {
            authenticated = true;
            deriveStorageKey(input); 
            resetFailedMasterAttempts(); 
            
            tft.fillScreen(TFT_BLACK);
            tft.setCursor(10, 20);
            tft.println("Access Granted.");
            
            Terminal.println("[AUTH] STATUS:SUCCESS");
            Terminal.println("[SYS] STATUS:READY");
            Terminal.flush();
            return;
        }
        else if (verifyMasterPinPBKDF2(input)) {
            if (deletePin()) {
                authenticated = false;
                currentCommandState = STATE_READY;
                
                tft.fillScreen(TFT_RED);
                tft.setTextColor(TFT_WHITE, TFT_RED);
                tft.setCursor(10, 20);
                tft.println("MASTER RESET TRIGGERED");
                tft.println("Wiping vault database...");
                
                clearAllStoredPasswords(); 
                
                tft.println("Vault wiped successfully!");
                tft.println("Rebooting system...");
                
                Terminal.println("[AUTH] STATUS:MASTER_RESET_SUCCESS_VAULT_PURGED");
                Terminal.flush();
                
                delay(2000);
                ESP.restart();
            } else {
                Terminal.println("[ERR] CODE:NO_USER_PIN_FOUND");
            }
            Terminal.flush();
            return;
        }
        else {
            Terminal.println("[AUTH] STATUS:INVALID");
            Terminal.flush();
            return;
        }
    }

    // STEP 2: ASYNCHRONOUS STATE MACHINE COMMAND PROCESSING
    switch (currentCommandState) {
        
        case STATE_READY:
            if (input == "help") {
                Terminal.println("\n================ AVAILABLE COMMANDS ================");
                Terminal.println("  help            - Display this command documentation menu");
                Terminal.println("  list            - List all stored account identifiers");
                Terminal.println("  info            - Show system storage stats & SPIFFS space");
                Terminal.println("  create          - Securely save a new account and password");
                Terminal.println("  get             - Retrieve an existing password by name");
                Terminal.println("  delete          - Permanently wipe a password from storage");
                Terminal.println("  delete_pin      - Reset the system by deleting the current PIN");
                Terminal.println("  delete_master   - Reset Master PIN data file storage layout");
                Terminal.println("  delete_pass     - Reset Master PIN data file storage layout");
                Terminal.println("  diagnostics     - Run automated verification testing suite");
                Terminal.println("====================================================");
            }
            else if (input == "create") {
                Terminal.println("[PASS] REQ:NAME");
                currentCommandState = STATE_AWAITING_CREATE_NAME;
            }
            else if (input == "get") {
                Terminal.println("[PASS] REQ:NAME");
                currentCommandState = STATE_AWAITING_GET_NAME;
            }
            else if (input == "delete") {
                Terminal.println("[PASS] REQ:NAME");
                currentCommandState = STATE_AWAITING_DELETE_NAME;
            }
            else if (input == "list") {
                listPasswords();
            }
            else if (input == "info") {
                showStorageInfo();
            }
            else if (input == "delete_pin") {
                if (deletePin()) {
                    authenticated = false;
                    Terminal.println("[AUTH] STATUS:PIN_DELETED");
                    Terminal.println("[AUTH] STATUS:NEW_PIN_REQ");
                } else {
                    Terminal.println("[ERR] CODE:NO_PIN_FOUND");
                }
            }
            else if (input == "delete_master") {
                if (deleteMasterPin()) {
                    authenticated = false;
                    Terminal.println("[AUTH] STATUS:MASTER_PIN_DELETED");
                    
                    tft.fillScreen(TFT_NAVY);
                    tft.setTextColor(TFT_WHITE, TFT_NAVY);
                    tft.setCursor(10, 20);
                    tft.println("Wiping Hardware...");
                    
                    finger.emptyDatabase(); 
                    Terminal.println("[SYS] FINGERPRINT DATABASE WIPED");
                    delay(1000);

                    if (enrollFingerprint(1)) {
                        Terminal.println("[SYS] NEW MASTER FINGERPRINT SET");
                    } else {
                        Terminal.println("[ERR] HARDWARE ENROLLMENT FAILED");
                    }

                    tft.fillScreen(TFT_BLACK);
                    tft.setTextColor(TFT_WHITE, TFT_BLACK);
                    tft.setCursor(10, 20);
                    tft.println("Awaiting Auth...");

                    Terminal.println("[AUTH] STATUS:NO_MASTER_PIN_SET");
                } else {
                    Terminal.println("[ERR] CODE:NO_MASTER_FOUND");
                }
            }
            else if (input == "delete_pass") {
                tft.fillScreen(TFT_RED);
                tft.setTextColor(TFT_WHITE, TFT_RED);
                tft.setCursor(10, 20);
                tft.println("PURGING VAULT...");
                
                clearAllStoredPasswords();
                
                Terminal.println("[SYS] VAULT PURGE SUCCESSFUL: ALL LOGINS & PASSKEYS WIPE COMPLETE");
                delay(1000);

                tft.fillScreen(TFT_BLACK);
                tft.setTextColor(TFT_WHITE, TFT_BLACK);
                tft.setCursor(10, 20);
                tft.println("Awaiting Auth...");
            }
            else if (input == "diagnostics") {
                runFullSystemDiagnostics();
                Terminal.println("[AUTH] STATUS:NEW_PIN_REQ");
            }
            else {
                Terminal.println("[ERR] CODE:UNKNOWN_CMD");
            }
            break;

        case STATE_AWAITING_CREATE_NAME:
            if (input.length() == 0) {
                Terminal.println("[ERR] CODE:INVALID_NAME");
                currentCommandState = STATE_READY;
                break;
            }
            pendingName = input;
            Terminal.println("[PASS] AUTO_GENERATE_PASSWORD? (Y/N)");
            currentCommandState = STATE_AWAITING_AUTOGEN_CHOICE;
            break;

        case STATE_AWAITING_AUTOGEN_CHOICE:
            input.toUpperCase();
            if (input == "Y" || input == "YES") {
                String generatedPass = generateRandomPassword(16);
                savePassword(pendingName, generatedPass);
                Terminal.print("[PASS] GENERATED:");
                Terminal.println(generatedPass);
                pendingName = "";
                currentCommandState = STATE_READY;
            } 
            else if (input == "N" || input == "NO") {
                Terminal.println("[PASS] REQ:VAL");
                currentCommandState = STATE_AWAITING_CREATE_VAL;
            } 
            else {
                Terminal.println("[ERR] CODE:INVALID_CHOICE_ENTER_Y_OR_N");
            }
            break;

        case STATE_AWAITING_CREATE_VAL:
            savePassword(pendingName, input);
            pendingName = "";
            currentCommandState = STATE_READY;
            break;

        case STATE_AWAITING_GET_NAME: {
            String pw = getPasswordFromStorage(input);
            if (pw.length() > 0) {
                pendingPasswordToTransmit = pw; 
                
                tft.fillScreen(TFT_NAVY);
                tft.setTextColor(TFT_WHITE, TFT_NAVY);
                tft.setCursor(10, 15);
                tft.println("REQUEST CONFIRMATION:");
                
                tft.setTextColor(TFT_YELLOW, TFT_NAVY);
                tft.setTextSize(3);
                tft.setCursor(10, 55);
                tft.println(input); 
                
                tft.setTextSize(2);
                tft.setTextColor(TFT_WHITE, TFT_NAVY);
                tft.setCursor(10, 130);
                tft.println("Scan fingerprint");
                tft.println("to authorize serial");
                tft.println("transfer...");

                Terminal.println("[PASS] STATUS:AWAITING_HARDWARE_APPROVAL");
                currentCommandState = STATE_AWAITING_FINGERPRINT;
            } else {
                Terminal.println("[ERR] CODE:NOT_FOUND");
                currentCommandState = STATE_READY;
            }
            break;
        }

        case STATE_AWAITING_DELETE_NAME:
            if (deletePassword(input)) {
                Terminal.println("[PASS] OUT:DELETED");
            } else {
                Terminal.println("[ERR] CODE:NOT_FOUND");
            }
            currentCommandState = STATE_READY;
            break;

        default:
            currentCommandState = STATE_READY;
            break;
    }

    Terminal.flush();
}
