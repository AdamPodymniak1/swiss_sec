#include <Arduino.h>
#include "Globals.h"
#include "DisplayManager.h"
#include "FingerprintManager.h"
#include "CryptoManager.h"
#include "StorageManager.h"
#include "SelfTestManager.h"
#include "FIDO2Manager.h"

#include "soc/soc.h"
#include "soc/rtc_cntl_reg.h"

#include "USB.h"
#include "USBCDC.h"

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