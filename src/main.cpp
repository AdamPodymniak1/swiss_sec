// main.cpp
#include <Arduino.h>
#include <sys/time.h>
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

    u8g2.begin();
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_ncenB08_tr);
    u8g2.drawStr(0, 15, "BOOTING...");
    u8g2.sendBuffer();

    Serial.begin(115200);
    FidoHID.begin();
    USB.begin();

    unsigned long startMillis = millis();
    while (!Serial && (millis() - startMillis < 4000)) delay(10);

    delay(200);
    Serial.flush();
    while(Serial.available() > 0) { Serial.read(); }

    initCrypto();

    if (!initStorage()) {
        Serial.println("[SYS] ERR:SPIFFS_MOUNT_FAILED");
        u8g2.clearBuffer();
        u8g2.setFont(u8g2_font_ncenB08_tr);
        u8g2.drawStr(0, 15, "SPIFFS FAILED");
        u8g2.sendBuffer();
        return;
    }

    initFingerprintSensor();

    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_ncenB08_tr);
    u8g2.drawStr(0, 15, "AWAITING AUTH");
    u8g2.sendBuffer();
}

void loop() {
    FidoHID.poll();
    updateFingerprintAsync();

    if (!Serial.available()) return;

    String rawInput = Serial.readStringUntil('\n');
    rawInput.trim();
    String input = rawInput;

    if (rawInput.startsWith("DH_INIT:")) {
        processHandshake(rawInput.substring(8));
        authenticated = false;
        currentCommandState = STATE_READY;
        Terminal.flush();
        return;
    }

    if (rawInput.startsWith("ENC:")) {
        input = decryptMsg(rawInput);
        if (input == "") return; 
    }
    else if (encryptionActive) {
        return; 
    }

    if (input == "RESTART_SYSTEM") {
        authenticated = false;
        clearStorageKey();
        currentCommandState = STATE_READY;
        u8g2.clearBuffer();
        u8g2.setFont(u8g2_font_ncenB08_tr);
        u8g2.drawStr(0, 15, "AWAITING AUTH");
        u8g2.sendBuffer();
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
        u8g2.clearBuffer();
        u8g2.setFont(u8g2_font_ncenB08_tr);
        u8g2.drawStr(0, 15, "DISCONNECTED");
        u8g2.sendBuffer();
        Terminal.println("[SYS] STATUS:DISCONNECTED");
        Terminal.flush();
        return;
    }

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
            
            u8g2.clearBuffer();
            u8g2.setFont(u8g2_font_ncenB08_tr);
            u8g2.drawStr(0, 15, "ACCESS GRANTED");
            u8g2.sendBuffer();
            
            Terminal.println("[AUTH] STATUS:SUCCESS");
            Terminal.println("[SYS] STATUS:READY");
            Terminal.flush();
            return;
        }
        else if (verifyMasterPinPBKDF2(input)) {
            if (deletePin()) {
                authenticated = false;
                currentCommandState = STATE_READY;
                
                u8g2.clearBuffer();
                u8g2.setFont(u8g2_font_ncenB08_tr);
                u8g2.drawStr(0, 15, "MASTER RESET");
                u8g2.drawStr(0, 30, "WIPING VAULT");
                u8g2.sendBuffer();
                
                clearAllStoredPasswords();

                
                u8g2.clearBuffer();
                u8g2.setFont(u8g2_font_ncenB08_tr);
                u8g2.drawStr(0, 15, "WIPED");
                u8g2.sendBuffer();
                
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
                Terminal.println("  list_fido       - List all saved FIDO2 website names");
                Terminal.println("  get_fido        - Read stored FIDO2 website info and users");
                Terminal.println("  delete_fido     - Wipe a FIDO2 website and all saved keys");
                Terminal.println("  delete_pin      - Reset the system by deleting current PIN");
                Terminal.println("  delete_master   - Reset Master PIN data file storage layout");
                Terminal.println("  delete_pass     - Purge vault passwords and passkeys");
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
                    
                    u8g2.clearBuffer();
                    u8g2.setFont(u8g2_font_ncenB08_tr);
                    u8g2.drawStr(0, 15, "WIPING HARDWARE");
                    u8g2.sendBuffer();
                    
                    finger.emptyDatabase(); 
                    Terminal.println("[SYS] FINGERPRINT DATABASE WIPED");
                    delay(1000);

                    if (enrollFingerprint(1)) {
                        Terminal.println("[SYS] NEW MASTER FINGERPRINT SET");
                    } else {
                        Terminal.println("[ERR] HARDWARE ENROLLMENT FAILED");
                    }
                    
                    u8g2.clearBuffer();
                    u8g2.setFont(u8g2_font_ncenB08_tr);
                    u8g2.drawStr(0, 15, "AWAITING AUTH");
                    u8g2.sendBuffer();

                    Terminal.println("[AUTH] STATUS:NO_MASTER_PIN_SET");
                } else {
                    Terminal.println("[ERR] CODE:NO_MASTER_FOUND");
                }
            }
            else if (input == "delete_pass") {
                u8g2.clearBuffer();
                u8g2.setFont(u8g2_font_ncenB08_tr);
                u8g2.drawStr(0, 15, "PURGING VAULT");
                u8g2.sendBuffer();
                
                clearAllStoredPasswords();
                
                Terminal.println("[SYS] VAULT PURGE SUCCESSFUL: ALL LOGINS & PASSKEYS WIPE COMPLETE");
                delay(1000);

                u8g2.clearBuffer();
                u8g2.setFont(u8g2_font_ncenB08_tr);
                u8g2.drawStr(0, 15, "AWAITING AUTH");
                u8g2.sendBuffer();
            }
            else if (input == "diagnostics") {
                runFullSystemDiagnostics();
                Terminal.println("[AUTH] STATUS:NEW_PIN_REQ");
            }
            else if (input == "list_fido") {
                listFidoWebsites();
            }
            else if (input == "get_fido") {
                Terminal.println("[FIDO2] REQ:WEBSITE_DOMAIN");
                currentCommandState = STATE_AWAITING_FIDO_GET_NAME;
            }
            else if (input == "delete_fido") {
                Terminal.println("[FIDO2] REQ:WEBSITE_DOMAIN");
                currentCommandState = STATE_AWAITING_FIDO_DELETE_NAME;
            }
            else if (input.startsWith("SET_TIME:")) {
                struct timeval tv;
                tv.tv_sec = input.substring(9).toInt();
                tv.tv_usec = 0;
                settimeofday(&tv, NULL);
                Terminal.println("[SYS] TIME_SYNCED");
            }
            else if (input == "totp_add") {
                Terminal.println("[TOTP] REQ:NAME");
                currentCommandState = STATE_AWAITING_TOTP_NAME;
            }
            else if (input == "totp_get") {
                Terminal.println("[TOTP] REQ:NAME");
                currentCommandState = STATE_AWAITING_TOTP_GET;
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
                
                u8g2.clearBuffer();
                u8g2.setFont(u8g2_font_ncenB08_tr);
                u8g2.drawStr(0, 14, "GETTING:");
                u8g2.drawStr(0, 28, input.c_str());
                u8g2.sendBuffer();

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

        case STATE_AWAITING_FIDO_GET_NAME: {
            String info = getFidoWebsiteInfo(input);
            if (info.length() > 0) {
                Terminal.print(info);
            } else {
                Terminal.println("[ERR] CODE:NOT_FOUND");
            }
            currentCommandState = STATE_READY;
            break;
        }

        case STATE_AWAITING_FIDO_DELETE_NAME:
            if (deleteFidoWebsite(input)) {
                Terminal.println("[PASS] OUT:DELETED");
            } else {
                Terminal.println("[ERR] CODE:NOT_FOUND");
            }
            currentCommandState = STATE_READY;
            break;
        
        case STATE_AWAITING_TOTP_NAME:
            pendingName = input;
            Terminal.println("[TOTP] REQ:BASE32_SECRET");
            currentCommandState = STATE_AWAITING_TOTP_SECRET;
            break;

        case STATE_AWAITING_TOTP_SECRET:
            saveTotpSecret(pendingName, input);
            pendingName = "";
            currentCommandState = STATE_READY;
            break;

        case STATE_AWAITING_TOTP_GET: {
            String secret = getTotpSecret(input);
            if (secret.length() > 0) {
                struct timeval tv;
                gettimeofday(&tv, NULL);
                String code = generateTOTP(secret, tv.tv_sec);
                
                u8g2.clearBuffer();
                u8g2.setFont(u8g2_font_ncenB08_tr);
                u8g2.drawStr(0, 14, input.c_str());
                u8g2.drawStr(0, 30, code.c_str());
                u8g2.sendBuffer();
                
                Terminal.print("[TOTP] CODE:");
                Terminal.println(code);
            } else {
                Terminal.println("[ERR] CODE:NOT_FOUND");
            }
            currentCommandState = STATE_READY;
            break;
        }

        default:
            currentCommandState = STATE_READY;
            break;
    }

    Terminal.flush();
}