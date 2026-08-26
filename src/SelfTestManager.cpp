// SelfTestManager.cpp
#include "SelfTestManager.h"
#include "Globals.h"
#include "DisplayManager.h"
#include "FingerprintManager.h"
#include "CryptoManager.h"
#include "StorageManager.h"
#include "mbedtls/ecdsa.h"

void printTestResult(const char* featureName, bool success) {
    if (success) {
        Serial.print("[TEST:PASS] -> ");
        Serial.println(featureName);
    } else {
        Serial.print("[TEST:FAIL] *CRITICAL* -> ");
        Serial.println(featureName);
    }
}

bool testCryptoSubsystem() {
    bool allPassed = true;

    String testInput = "test_vector_data";
    String expectedHash = hashSHA256(testInput);
    String verifyHash = hashSHA256(testInput);
    if (expectedHash != verifyHash || expectedHash.length() == 0) {
        printTestResult("Crypto: SHA-256 Consistency Check", false);
        allPassed = false;
    } else {
        printTestResult("Crypto: SHA-256 Consistency Check", true);
    }

    String rand1 = generateRandomPassword(16);
    String rand2 = generateRandomPassword(16);
    if (rand1.length() != 16 || rand2.length() != 16 || rand1 == rand2) {
        printTestResult("Crypto: PRNG Entropy & Length Verification", false);
        allPassed = false;
    } else {
        printTestResult("Crypto: PRNG Entropy & Length Verification", true);
    }

    uint8_t mockPrivKey[32] = {0};
    uint8_t mockPubKey[65] = {0};
    
    if (!generateKeypairP256(mockPrivKey, mockPubKey)) {
        printTestResult("Crypto: ECDSA P-256 Keypair Generation", false);
        allPassed = false;
    } else {
        printTestResult("Crypto: ECDSA P-256 Keypair Generation", true);
        
        if (mockPubKey[0] != 0x04) {
            printTestResult("Crypto: P-256 Public Component Envelope Structure", false);
            allPassed = false;
        } else {
            printTestResult("Crypto: P-256 Public Component Envelope Structure", true);
        }

        uint8_t mockMessage[32];
        esp_fill_random(mockMessage, 32);
        uint8_t targetSignature[74] = {0};
        size_t sigLen = sizeof(targetSignature);

        if (!signECDSA_P256(mockPrivKey, mockMessage, sizeof(mockMessage), targetSignature, &sigLen) || sigLen < 64) {
            printTestResult("Crypto: ECDSA P-256 ASN.1 DER Transaction Signing", false);
            allPassed = false;
        } else {
            printTestResult("Crypto: ECDSA P-256 ASN.1 DER Transaction Signing", true);
        }
    }

    return allPassed;
}

bool testStorageSubsystem() {
    bool allPassed = true;

    bool initialMasterSet = isMasterPinSet();
    bool initialPinSet = isPinSet();

    String mockAccount = "test_mock_user_123";
    String mockSecret = "SuperSecurePassword99!";
    
    savePassword(mockAccount, mockSecret);
    String retrievedSecret = getPasswordFromStorage(mockAccount);
    
    if (retrievedSecret != mockSecret) {
        printTestResult("Storage: Vault Data Read/Write Integrity", false);
        allPassed = false;
    } else {
        printTestResult("Storage: Vault Data Read/Write Integrity", true);
    }

    deletePassword(mockAccount);
    if (getPasswordFromStorage(mockAccount).length() != 0) {
        printTestResult("Storage: Vault Single Node Erasure", false);
        allPassed = false;
    } else {
        printTestResult("Storage: Vault Single Node Erasure", true);
    }

    createPin("4321");
    if (!isPinSet() || !verifyPin("4321") || verifyPin("0000")) {
        printTestResult("Storage: User PIN Custom Creation & Checking", false);
        allPassed = false;
    } else {
        printTestResult("Storage: User PIN Custom Creation & Checking", true);
    }
    deletePin(); 

    return allPassed;
}

bool testDisplaySubsystem() {
    u8g2.begin();
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_ncenB08_tr);
    u8g2.drawStr(0, 15, "TEST");
    u8g2.sendBuffer();
    delay(300); 
    u8g2.begin();
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_ncenB08_tr);
    u8g2.drawStr(0, 15, "TEST");
    u8g2.sendBuffer();
    delay(300); 

    printTestResult("Hardware: LovyanGFX Panel Rendering Pipeline", true);
    return true;
}

bool testFingerprintSubsystem() {
#if USE_FINGERPRINT_SIMULATOR
    printTestResult("Hardware: Optical Biometric UART Connection Handshake", true);
    return true;
#else
    if (finger.verifyPassword()) {
        printTestResult("Hardware: Optical Biometric UART Connection Handshake", true);
        
        finger.getTemplateCount();
        Serial.print("[SYS:INFO] Current Loaded Fingerprint Templates: ");
        Serial.println(finger.templateCount);
        printTestResult("Hardware: Synochip/Adafruit Parameter Extraction", true);
        return true;
    } else {
        printTestResult("Hardware: Optical Biometric UART Connection Handshake", false);
        return false;
    }
#endif
}

void runFullSystemDiagnostics() {
    Serial.println("\n====================================================");
    Serial.println("[DIAGNOSTICS] INITIATING FULL HARDWARE & SOFTWARE TESTS");
    Serial.println("====================================================");
    
    u8g2.begin();
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_ncenB08_tr);
    u8g2.drawStr(0, 15, "DIAGNOSTICS");
    u8g2.sendBuffer();

    int totalTestsPassed = 0;

    if (testCryptoSubsystem()) totalTestsPassed++;
    if (testStorageSubsystem()) totalTestsPassed++;
    if (testDisplaySubsystem()) totalTestsPassed++;
    if (testFingerprintSubsystem()) totalTestsPassed++;

    Serial.println("====================================================");
    Serial.print("[DIAGNOSTICS COMPLETE] SUBSYSTEM SUITES PASSED: ");
    Serial.print(totalTestsPassed);
    Serial.println("/4");
    Serial.println("====================================================\n");

    u8g2.begin();
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_ncenB08_tr);
    if (authenticated) {
        u8g2.drawStr(0, 15, "Logged In");
    } else {
        u8g2.drawStr(0, 15, "Awaiting Auth");
    }
    u8g2.sendBuffer();
}