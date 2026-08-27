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

void fidoTask(void *pvParameters) {
    while (1) {
        FidoHID.poll();
        vTaskDelay(10 / portTICK_PERIOD_MS);
    }
}

void cliTask(void *pvParameters) {
    while (1) {
        updateFingerprintAsync();

        if (Serial.available()) {
            String rawInput = Serial.readStringUntil('\n');
            rawInput.trim();
            String input = rawInput;

            if (rawInput.startsWith("DH_INIT:")) {
                processHandshake(rawInput.substring(8));
                authenticated = false;
                currentCommandState = STATE_READY;
                Terminal.flush();
                continue;
            }

            if (rawInput.startsWith("ENC:")) {
                input = decryptMsg(rawInput);
                if (input == "") continue;
            } else if (encryptionActive) {
                continue;
            }

            if (input == "RESTART_SYSTEM") {
                authenticated = false;
                clearStorageKey();
                currentCommandState = STATE_READY;
                xSemaphoreTake(displayMutex, portMAX_DELAY);
                u8g2.clearBuffer();
                u8g2.setFont(u8g2_font_ncenB08_tr);
                u8g2.drawStr(0, 15, "AWAITING AUTH");
                u8g2.sendBuffer();
                xSemaphoreGive(displayMutex);
                Terminal.println("[SYS] STATUS:BOOT");
                if (!isPinSet()) {
                    Terminal.println("[AUTH] STATUS:NEW_PIN_REQ");
                } else {
                    Terminal.println("[AUTH] STATUS:PIN_REQ");
                }
                Terminal.flush();
                continue;
            }

            if (input == "DISCONNECT") {
                authenticated = false;
                encryptionActive = false;
                clearStorageKey();
                currentCommandState = STATE_READY;
                xSemaphoreTake(displayMutex, portMAX_DELAY);
                u8g2.clearBuffer();
                u8g2.setFont(u8g2_font_ncenB08_tr);
                u8g2.drawStr(0, 15, "DISCONNECTED");
                u8g2.sendBuffer();
                xSemaphoreGive(displayMutex);
                Terminal.println("[SYS] STATUS:DISCONNECTED");
                Terminal.flush();
                continue;
            }

            if (!isPinSet()) {
                createPin(input);
                Terminal.println("[AUTH] STATUS:PIN_CREATED");
                Terminal.println("[AUTH] STATUS:PIN_REQ");
                Terminal.flush();
                continue;
            }

            if (!authenticated) {
                if (verifyPin(input)) {
                    authenticated = true;
                    deriveStorageKey(input);
                    xSemaphoreTake(displayMutex, portMAX_DELAY);
                    u8g2.clearBuffer();
                    u8g2.setFont(u8g2_font_ncenB08_tr);
                    u8g2.drawStr(0, 15, "ACCESS GRANTED");
                    u8g2.sendBuffer();
                    xSemaphoreGive(displayMutex);
                    Terminal.println("[AUTH] STATUS:SUCCESS");
                    Terminal.println("[SYS] STATUS:READY");
                    Terminal.flush();
                    continue;
                } else {
                    Terminal.println("[AUTH] STATUS:INVALID");
                    Terminal.flush();
                    continue;
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
                        Terminal.println("  totp_add        - Add a new Base32 TOTP secret");
                        Terminal.println("  totp_get        - Generate a 6-digit TOTP code");
                        Terminal.println("  delete_pin      - FACTORY RESET (Wipes PIN, Vault, & Fingerprints)");
                        Terminal.println("  delete_pass     - Purge vault passwords and passkeys");
                        Terminal.println("  diagnostics     - Run automated verification testing suite");
                        Terminal.println("====================================================");
                    } else if (input == "create") {
                        Terminal.println("[PASS] REQ:NAME");
                        currentCommandState = STATE_AWAITING_CREATE_NAME;
                    } else if (input == "get") {
                        Terminal.println("[PASS] REQ:NAME");
                        currentCommandState = STATE_AWAITING_GET_NAME;
                    } else if (input == "delete") {
                        Terminal.println("[PASS] REQ:NAME");
                        currentCommandState = STATE_AWAITING_DELETE_NAME;
                    } else if (input == "list") {
                        listPasswords();
                    } else if (input == "info") {
                        showStorageInfo();
                    } else if (input == "delete_pin") {
                        if (deletePin()) {
                            authenticated = false;
                            Terminal.println("[AUTH] STATUS:FACTORY_RESET_COMPLETE");
                            xSemaphoreTake(displayMutex, portMAX_DELAY);
                            u8g2.clearBuffer();
                            u8g2.setFont(u8g2_font_ncenB08_tr);
                            u8g2.drawStr(0, 15, "WIPING HARDWARE");
                            u8g2.sendBuffer();
                            xSemaphoreGive(displayMutex);
                            xSemaphoreTake(fingerprintMutex, portMAX_DELAY);
                            finger.emptyDatabase();
                            xSemaphoreGive(fingerprintMutex);
                            Terminal.println("[SYS] FINGERPRINT DATABASE WIPED");
                            vTaskDelay(1000 / portTICK_PERIOD_MS);
                            xSemaphoreTake(displayMutex, portMAX_DELAY);
                            u8g2.clearBuffer();
                            u8g2.setFont(u8g2_font_ncenB08_tr);
                            u8g2.drawStr(0, 15, "SYSTEM RESET");
                            u8g2.sendBuffer();
                            xSemaphoreGive(displayMutex);
                            vTaskDelay(2000 / portTICK_PERIOD_MS);
                            ESP.restart();
                        } else {
                            Terminal.println("[ERR] CODE:NO_PIN_FOUND");
                        }
                    } else if (input == "delete_pass") {
                        xSemaphoreTake(displayMutex, portMAX_DELAY);
                        u8g2.clearBuffer();
                        u8g2.setFont(u8g2_font_ncenB08_tr);
                        u8g2.drawStr(0, 15, "PURGING VAULT");
                        u8g2.sendBuffer();
                        xSemaphoreGive(displayMutex);
                        clearAllStoredPasswords();
                        Terminal.println("[SYS] VAULT PURGE SUCCESSFUL: ALL LOGINS & PASSKEYS WIPE COMPLETE");
                        vTaskDelay(1000 / portTICK_PERIOD_MS);
                        xSemaphoreTake(displayMutex, portMAX_DELAY);
                        u8g2.clearBuffer();
                        u8g2.setFont(u8g2_font_ncenB08_tr);
                        u8g2.drawStr(0, 15, "AWAITING AUTH");
                        u8g2.sendBuffer();
                        xSemaphoreGive(displayMutex);
                    } else if (input == "diagnostics") {
                        runFullSystemDiagnostics();
                        Terminal.println("[AUTH] STATUS:NEW_PIN_REQ");
                    } else if (input == "list_fido") {
                        listFidoWebsites();
                    } else if (input == "get_fido") {
                        Terminal.println("[FIDO2] REQ:WEBSITE_DOMAIN");
                        currentCommandState = STATE_AWAITING_FIDO_GET_NAME;
                    } else if (input == "delete_fido") {
                        Terminal.println("[FIDO2] REQ:WEBSITE_DOMAIN");
                        currentCommandState = STATE_AWAITING_FIDO_DELETE_NAME;
                    } else if (input.startsWith("SET_TIME:")) {
                        struct timeval tv;
                        tv.tv_sec = input.substring(9).toInt();
                        tv.tv_usec = 0;
                        settimeofday(&tv, NULL);
                        Terminal.println("[SYS] TIME_SYNCED");
                    } else if (input == "totp_add") {
                        Terminal.println("[TOTP] REQ:NAME");
                        currentCommandState = STATE_AWAITING_TOTP_NAME;
                    } else if (input == "totp_get") {
                        Terminal.println("[TOTP] REQ:NAME");
                        currentCommandState = STATE_AWAITING_TOTP_GET;
                    } else {
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
                    } else if (input == "N" || input == "NO") {
                        Terminal.println("[PASS] REQ:VAL");
                        currentCommandState = STATE_AWAITING_CREATE_VAL;
                    } else {
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
                        xSemaphoreTake(displayMutex, portMAX_DELAY);
                        u8g2.clearBuffer();
                        u8g2.setFont(u8g2_font_ncenB08_tr);
                        u8g2.drawStr(0, 14, "GETTING:");
                        u8g2.drawStr(0, 28, input.c_str());
                        u8g2.sendBuffer();
                        xSemaphoreGive(displayMutex);
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
                        xSemaphoreTake(displayMutex, portMAX_DELAY);
                        u8g2.clearBuffer();
                        u8g2.setFont(u8g2_font_ncenB08_tr);
                        u8g2.drawStr(0, 14, input.c_str());
                        u8g2.drawStr(0, 30, code.c_str());
                        u8g2.sendBuffer();
                        xSemaphoreGive(displayMutex);
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
        vTaskDelay(50 / portTICK_PERIOD_MS);
    }
}

void setup() {
    WRITE_PERI_REG(RTC_CNTL_BROWN_OUT_REG, 0);

    displayMutex = xSemaphoreCreateMutex();
    fingerprintMutex = xSemaphoreCreateMutex();
    storageMutex = xSemaphoreCreateMutex();

    #ifdef RGB_BUILTIN
        pinMode(RGB_BUILTIN, OUTPUT);
        neopixelWrite(RGB_BUILTIN, 0, 0, 0);
    #endif

    xSemaphoreTake(displayMutex, portMAX_DELAY);
    u8g2.begin();
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_ncenB08_tr);
    u8g2.drawStr(0, 15, "BOOTING...");
    u8g2.sendBuffer();
    xSemaphoreGive(displayMutex);

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
        xSemaphoreTake(displayMutex, portMAX_DELAY);
        u8g2.clearBuffer();
        u8g2.setFont(u8g2_font_ncenB08_tr);
        u8g2.drawStr(0, 15, "SPIFFS FAILED");
        u8g2.sendBuffer();
        xSemaphoreGive(displayMutex);
        return;
    }

    initFingerprintSensor();

    xSemaphoreTake(displayMutex, portMAX_DELAY);
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_ncenB08_tr);
    u8g2.drawStr(0, 15, "AWAITING AUTH");
    u8g2.sendBuffer();
    xSemaphoreGive(displayMutex);

    xTaskCreatePinnedToCore(fidoTask, "FidoTask", 8192, NULL, 2, NULL, 0);
    xTaskCreatePinnedToCore(cliTask, "CliTask", 8192, NULL, 1, NULL, 1);
}

void loop() {
    vTaskDelete(NULL);
}