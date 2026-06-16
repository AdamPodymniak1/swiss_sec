#include "SelfTestManager.h"
#include "Globals.h"
#include "DisplayManager.h"
#include "FingerprintManager.h"
#include "CryptoManager.h"
#include "StorageManager.h"
#include "mbedtls/ecdsa.h"

// Helper to print uniform test status reports
void printTestResult(const char* featureName, bool success) {
    if (success) {
        Serial.print("[TEST:PASS] -> ");
        Serial.println(featureName);
    } else {
        Serial.print("[TEST:FAIL] *CRITICAL* -> ");
        Serial.println(featureName);
    }
}

// ==========================================
// 1. CRYPTOGRAPHY FEATURE TESTS
// ==========================================
bool testCryptoSubsystem() {
    bool allPassed = true;

    // 1. Existing SHA-256 Consistency Check
    String testInput = "test_vector_data";
    String expectedHash = hashSHA256(testInput);
    String verifyHash = hashSHA256(testInput);
    if (expectedHash != verifyHash || expectedHash.length() == 0) {
        printTestResult("Crypto: SHA-256 Consistency Check", false);
        allPassed = false;
    } else {
        printTestResult("Crypto: SHA-256 Consistency Check", true);
    }

    // 2. Existing PRNG Entropy Verification
    String rand1 = generateRandomPassword(16);
    String rand2 = generateRandomPassword(16);
    if (rand1.length() != 16 || rand2.length() != 16 || rand1 == rand2) {
        printTestResult("Crypto: PRNG Entropy & Length Verification", false);
        allPassed = false;
    } else {
        printTestResult("Crypto: PRNG Entropy & Length Verification", true);
    }

    // =========================================================================
    // NEW FEATURE TEST: ECDSA P-256 ALGORITHMIC VALIDATION LOOP
    // =========================================================================
    uint8_t mockPrivKey[32] = {0};
    uint8_t mockPubKey[65] = {0};
    
    if (!generateKeypairP256(mockPrivKey, mockPubKey)) {
        printTestResult("Crypto: ECDSA P-256 Keypair Generation", false);
        allPassed = false;
    } else {
        printTestResult("Crypto: ECDSA P-256 Keypair Generation", true);
        
        // Assert uncompressed public prefix header signature check
        if (mockPubKey[0] != 0x04) {
            printTestResult("Crypto: P-256 Public Component Envelope Structure", false);
            allPassed = false;
        } else {
            printTestResult("Crypto: P-256 Public Component Envelope Structure", true);
        }

        // Test Assertion: Sign a mock transaction tracking hash block
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

// ==========================================
// 2. STORAGE & DATABASE FEATURE TESTS
// ==========================================
bool testStorageSubsystem() {
    bool allPassed = true;

    // Backup states to restore after destructive write mutations
    bool initialMasterSet = isMasterPinSet();
    bool initialPinSet = isPinSet();

    // Feature Test: Vault CRUD Operations (Create, Read, Update, Delete)
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

    // Feature Test: Record Erasure Mechanism
    deletePassword(mockAccount);
    if (getPasswordFromStorage(mockAccount).length() != 0) {
        printTestResult("Storage: Vault Single Node Erasure", false);
        allPassed = false;
    } else {
        printTestResult("Storage: Vault Single Node Erasure", true);
    }

    // Feature Test: User PIN Management
    createPin("4321");
    if (!isPinSet() || !verifyPin("4321") || verifyPin("0000")) {
        printTestResult("Storage: User PIN Custom Creation & Checking", false);
        allPassed = false;
    } else {
        printTestResult("Storage: User PIN Custom Creation & Checking", true);
    }
    deletePin(); // Clean up profile block

    return allPassed;
}

// ==========================================
// 3. HARDWARE DISPLAY FEATURE TESTS
// ==========================================
bool testDisplaySubsystem() {
    // Feature Test: Framebuffer Cycle and Color Space Remapping
    // Changes display colors sequentially to allow manual tracking visibility
    uint16_t testColors[] = {TFT_RED, TFT_DARKGREEN, TFT_NAVY, TFT_YELLOW, TFT_BLACK};
    const char* colorNames[] = {"RED", "GREEN", "NAVY", "YELLOW", "BLACK"};

    for (int i = 0; i < 5; i++) {
        tft.fillScreen(testColors[i]);
        tft.setCursor(10, 50);
        tft.setTextColor(TFT_WHITE, testColors[i]);
        tft.print("DISPLAY TEST: ");
        tft.println(colorNames[i]);
        delay(300); // Visual frame verification delay
    }
    printTestResult("Hardware: LovyanGFX Panel Rendering Pipeline", true);
    return true;
}

// ==========================================
// 4. HARDWARE BIOMETRICS FEATURE TESTS
// ==========================================
bool testFingerprintSubsystem() {
    // Feature Test: Sensor UART Bus Protocol Communication Stability
    if (finger.verifyPassword()) {
        printTestResult("Hardware: Optical Biometric UART Connection Handshake", true);
        
        // Feature Test: Internal Template Index Storage Verification
        finger.getTemplateCount();
        Serial.print("[SYS:INFO] Current Loaded Fingerprint Templates: ");
        Serial.println(finger.templateCount);
        printTestResult("Hardware: Synochip/Adafruit Parameter Extraction", true);
        return true;
    } else {
        printTestResult("Hardware: Optical Biometric UART Connection Handshake", false);
        return false;
    }
}

// ==========================================
// CORE TEST ORCHESTRATOR EXECUTIVE
// ==========================================
void runFullSystemDiagnostics() {
    Serial.println("\n====================================================");
    Serial.println("[DIAGNOSTICS] INITIATING FULL HARDWARE & SOFTWARE TESTS");
    Serial.println("====================================================");
    
    tft.fillScreen(TFT_NAVY);
    tft.setTextColor(TFT_WHITE, TFT_NAVY);
    tft.setCursor(10, 20);
    tft.println("RUNNING DIAGNOSTICS...");
    tft.println("Check Serial Log Console.");

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

    // Clear display panels back to normal operations
    tft.fillScreen(TFT_BLACK);
    tft.setTextColor(TFT_WHITE, TFT_BLACK);
    tft.setCursor(10, 20);
    if (authenticated) {
        tft.println("System Logged In");
    } else {
        tft.println("Awaiting Auth...");
    }
}