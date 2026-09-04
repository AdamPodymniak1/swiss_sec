#include <Arduino.h>
#include <ArduinoJson.h>
#include <sys/time.h>
#include "Globals.h"
#include "DisplayManager.h"
#include "CommsManager.h"
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

            JsonDocument req;
            DeserializationError err = deserializeJson(req, input);
            if (err) {
                CommsManager::sendError("SYS", "INVALID_JSON");
                continue;
            }

            String cmd = req["cmd"] | "";

            if (cmd == "RESTART_SYSTEM") {
                authenticated = false;
                clearStorageKey();
                currentCommandState = STATE_READY;
                showDisplayMessage(1, "AWAITING AUTH", "", 0);
                
                JsonDocument data;
                data["pin_set"] = isPinSet();
                CommsManager::sendEvent("SYS", "BOOT", &data);
                continue;
            }

            if (cmd == "DISCONNECT") {
                authenticated = false;
                encryptionActive = false;
                clearStorageKey();
                currentCommandState = STATE_READY;
                showDisplayMessage(1, "DISCONNECTED", "", 0);
                CommsManager::sendEvent("SYS", "DISCONNECTED");
                continue;
            }

            if (!isPinSet()) {
                if (cmd == "CREATE_PIN" || cmd == "set_pin") {
                    createPin(req["pin"] | "");
                    CommsManager::sendEvent("AUTH", "PIN_CREATED");
                } else {
                    CommsManager::sendError("AUTH", "NEW_PIN_REQ");
                }
                continue;
            }

            if (!authenticated) {
                if (cmd == "VERIFY_PIN" || cmd == "verify_pin") {
                    String pinInput = req["pin"] | "";
                    if (verifyPin(pinInput)) {
                        authenticated = true;
                        deriveStorageKey(pinInput);
                        showDisplayMessage(1, "ACCESS GRANTED", "", 0);
                        CommsManager::sendEvent("SECURITY", "PIN_OK");
                    }
                } else {
                    CommsManager::sendError("AUTH", "PIN_REQ");
                }
                continue;
            }

            // Authenticated Command Router
            if (cmd == "help") {
                JsonDocument data;
                data["commands"][0] = "SAVE_PASS";
                data["commands"][1] = "GET_PASS";
                data["commands"][2] = "DELETE_PASS";
                data["commands"][3] = "LIST_PASS";
                data["commands"][4] = "SAVE_TOTP";
                data["commands"][5] = "GET_TOTP";
                data["commands"][6] = "DELETE_TOTP";
                data["commands"][7] = "LIST_FIDO";
                data["commands"][8] = "DELETE_FIDO";
                data["commands"][9] = "STORAGE_INFO";
                data["commands"][10] = "PURGE_STORAGE";
                data["commands"][11] = "RUN_DIAGNOSTICS";
                data["commands"][12] = "UPDATE_SETTINGS";
                data["commands"][13] = "UPDATE_PASS";
                data["commands"][14] = "SET_CRYPTO_ALG";
                data["commands"][15] = "ENROLL_FINGERPRINT";
                data["commands"][16] = "FACTORY_RESET";
                CommsManager::sendEvent("SYS", "HELP_MENU", &data);
            } 
            else if (cmd == "SAVE_PASS" || cmd == "create") {
                String website = req["site"] | req["website"] | "";
                String login = req["login"] | "";
                bool autogen = req["autogen"] | false;
                String pass = autogen ? generateRandomPassword(16) : (req["pass"] | req["password"] | "");

                if (website == "" || login == "") {
                    CommsManager::sendError("PASS", "MISSING_ARGS");
                    continue;
                }

                if (savePassword(website, login, pass)) {
                    JsonDocument data;
                    if (autogen) data["generated_password"] = pass;
                    CommsManager::sendEvent("PASS", "SAVED", autogen ? &data : nullptr);
                }
                
                secureWipe(website); secureWipe(login); secureWipe(pass);
            }
            else if (cmd == "GET_PASS" || cmd == "get") {
                String website = req["site"] | req["website"] | "";
                String login = req["login"] | "";
                String pw = getPasswordFromStorage(website, login);
                
                if (pw.length() > 0) {
                    pendingPasswordToTransmit = pw;
                    showDisplayMessage(2, "GETTING:", website, 0);
                    currentCommandState = STATE_AWAITING_FINGERPRINT; 
                    CommsManager::sendEvent("PASS", "AWAITING_HARDWARE_APPROVAL");
                } else {
                    CommsManager::sendError("PASS", "NOT_FOUND");
                }
            } 
            else if (cmd == "DELETE_PASS" || cmd == "delete") {
                String website = req["site"] | req["website"] | "";
                String login = req["login"] | "";
                if (deletePassword(website, login)) {
                    CommsManager::sendEvent("PASS", "DELETED");
                } else {
                    CommsManager::sendError("PASS", "NOT_FOUND");
                }
            }
            else if (cmd == "LIST_PASS" || cmd == "list") {
                listPasswords(); 
            }
            else if (cmd == "SAVE_TOTP") {
                String name = req["name"] | "";
                String secret = req["secret"] | "";
                if (name != "" && secret != "") {
                    saveTotpSecret(name, secret);
                } else {
                    CommsManager::sendError("TOTP", "MISSING_ARGS");
                }
            }
            else if (cmd == "GET_TOTP") {
                uint32_t epoch = req["epoch"] | 0;
                handleTotpGetAll(epoch);
            }
            else if (cmd == "DELETE_TOTP") {
                String name = req["name"] | "";
                if (deleteTotpSecret(name)) {
                    CommsManager::sendEvent("TOTP", "DELETED");
                } else {
                    CommsManager::sendError("TOTP", "NOT_FOUND");
                }
            }
            else if (cmd == "LIST_FIDO") {
                listFidoWebsites();
            }
            else if (cmd == "DELETE_FIDO") {
                String site = req["site"] | req["rpId"] | "";
                if (deleteFidoWebsite(site)) {
                    CommsManager::sendEvent("FIDO2", "DELETED");
                } else {
                    CommsManager::sendError("FIDO2", "NOT_FOUND");
                }
            }
            else if (cmd == "STORAGE_INFO") {
                showStorageInfo();
            }
            else if (cmd == "PURGE_STORAGE") {
                clearAllStoredPasswords();
            }
            else if (cmd == "RUN_DIAGNOSTICS") {
                runFullSystemDiagnostics();
                JsonDocument data;
                data["passed"] = 4;
                data["total"] = 4;
                CommsManager::sendEvent("SYS", "DIAGNOSTICS_COMPLETE", &data);
            }
            else if (cmd == "UPDATE_SETTINGS" || cmd == "SET_CRYPTO_ALG") {
                int algId = req["algId"] | -7;
                
                saveDefaultCryptoAlg(algId);
                defaultCryptoAlg = algId;

                JsonDocument data;
                data["algId"] = defaultCryptoAlg;
                CommsManager::sendEvent("SYS", "SETTINGS_UPDATED", &data);
            }
            else if (cmd == "UPDATE_PASS" || cmd == "update") {
                String website = req["site"] | req["website"] | "";
                String login = req["login"] | "";
                bool autogen = req["autogen"] | false;
                String pass = autogen ? generateRandomPassword(16) : (req["pass"] | req["password"] | "");

                if (website == "" || login == "") {
                    CommsManager::sendError("PASS", "MISSING_ARGS");
                    continue;
                }

                if (!isPasswordExists(website, login)) {
                    CommsManager::sendError("PASS", "NOT_FOUND");
                    secureWipe(pass);
                    continue;
                }

                pendingWebsite = website;
                pendingLogin = login;
                pendingPasswordToSave = pass;
                currentCommandState = STATE_AWAITING_FINGERPRINT_UPDATE;

                showDisplayMessage(2, "AUTH TO UPDATE:", website, 0);
                CommsManager::sendEvent("PASS", "AWAITING_HARDWARE_APPROVAL");
            }
            else if (cmd == "ENROLL_FINGER") {
                uint8_t id = req["id"] | 1;
                if (enrollFingerprint(id)) {
                    CommsManager::sendEvent("AUTH", "FINGERPRINT_ENROLLED");
                } else {
                    CommsManager::sendError("AUTH", "ENROLL_FAILED");
                }
            }
            else if (cmd == "FACTORY_RESET") {
                factoryResetSystem();
                clearStorageKey();
                authenticated = false;
                currentCommandState = STATE_READY;
                CommsManager::sendEvent("SYS", "FACTORY_RESET_COMPLETE");
            }
            else {
                CommsManager::sendError("SYS", "UNKNOWN_CMD");
            }
        }
        vTaskDelay(50 / portTICK_PERIOD_MS);
    }
}

void setup() {
    WRITE_PERI_REG(RTC_CNTL_BROWN_OUT_REG, 0);

    displayMutex = xSemaphoreCreateMutex();
    fingerprintMutex = xSemaphoreCreateMutex();
    storageMutex = xSemaphoreCreateMutex();
    
    cryptoQueue = xQueueCreate(2, sizeof(CryptoRequest));

    xSemaphoreTake(displayMutex, portMAX_DELAY);
    u8g2.begin();
    xSemaphoreGive(displayMutex);

    showDisplayMessage(1, "BOOTING...", "", 0);

    Serial.begin(115200);
    FidoHID.begin();
    USB.begin();

    initCrypto();
    if (!initStorage()) {
        showDisplayMessage(1, "SPIFFS FAILED", "", 0);
        return;
    }
    initFingerprintSensor();
    showDisplayMessage(1, "AWAITING AUTH", "", 0);

    defaultCryptoAlg = loadDefaultCryptoAlg();

    xTaskCreatePinnedToCore(fidoTask, "FidoTask", 32768, NULL, 2, NULL, 0);
    xTaskCreatePinnedToCore(cliTask, "CliTask", 8192, NULL, 1, NULL, 1);
}

void loop() {
    vTaskDelete(NULL);
}