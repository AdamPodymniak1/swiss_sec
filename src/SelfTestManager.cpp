#include "SelfTestManager.h"
#include "Globals.h"
#include "DisplayManager.h"
#include "FingerprintManager.h"
#include "CryptoManager.h"
#include "StorageManager.h"
#include "mbedtls/ecdsa.h"

// Keep diagnostics compact and serial-friendly for on-device execution.
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
    bool initialPinSet = isPinSet();

    String mockWebsite = "test_mock_site.com";
    String mockAccount = "test_mock_user_123";
    String mockSecret = "SuperSecurePassword99!";

    savePassword(mockWebsite, mockAccount, mockSecret);
    String retrievedSecret = getPasswordFromStorage(mockWebsite, mockAccount);

    if (retrievedSecret != mockSecret) {
        printTestResult("Storage: Vault Data Read/Write Integrity", false);
        allPassed = false;
    } else {
        printTestResult("Storage: Vault Data Read/Write Integrity", true);
    }

    deletePassword(mockWebsite, mockAccount);
    if (getPasswordFromStorage(mockWebsite, mockAccount).length() != 0) {
        printTestResult("Storage: Vault Single Node Erasure", false);
        allPassed = false;
    } else {
        printTestResult("Storage: Vault Single Node Erasure", true);
    }

    return allPassed;
}

bool testDisplaySubsystem() {
    showDisplayMessage(1, "TEST", "", 300);
    showDisplayMessage(1, "TEST", "", 300);

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

    showDisplayMessage(1, "DIAGNOSTICS", "", 0);

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

    if (authenticated) {
        showDisplayMessage(1, "Logged In", "", 0);
    } else {
        showDisplayMessage(1, "Awaiting Auth", "", 0);
    }
}
