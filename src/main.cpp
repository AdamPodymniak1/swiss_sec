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
                if (cmd == "set_pin") {
                    createPin(req["pin"] | "");
                    CommsManager::sendEvent("AUTH", "PIN_CREATED");
                } else {
                    CommsManager::sendError("AUTH", "NEW_PIN_REQ");
                }
                continue;
            }

            if (!authenticated) {
                if (cmd == "verify_pin") {
                    if (verifyPin(req["pin"] | "")) {
                        authenticated = true;
                        deriveStorageKey(req["pin"] | "");
                        showDisplayMessage(1, "ACCESS GRANTED", "", 0);
                        CommsManager::sendEvent("AUTH", "SUCCESS");
                    } else {
                        CommsManager::sendError("AUTH", "INVALID_PIN");
                    }
                } else {
                    CommsManager::sendError("AUTH", "PIN_REQ");
                }
                continue;
            }

            // Authenticated Command Router
            if (cmd == "help") {
                JsonDocument data;
                data["commands"][0] = "create";
                data["commands"][1] = "get";
                data["commands"][2] = "delete";
                data["commands"][3] = "diagnostics";
                CommsManager::sendEvent("SYS", "HELP_MENU", &data);
            } 
            else if (cmd == "create") {
                String website = req["website"] | "";
                String login = req["login"] | "";
                bool autogen = req["autogen"] | false;
                String pass = autogen ? generateRandomPassword(16) : req["password"] | "";

                if (website == "" || login == "") {
                    CommsManager::sendError("PASS", "MISSING_ARGS");
                    continue;
                }

                savePassword(website, login, pass);
                
                JsonDocument data;
                if (autogen) data["generated_password"] = pass;
                CommsManager::sendEvent("PASS", "SAVED", autogen ? &data : nullptr);
                
                secureWipe(website); secureWipe(login); secureWipe(pass);
            } 
            else if (cmd == "get") {
                String website = req["website"] | "";
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
            else if (cmd == "delete") {
                if (deletePassword(req["website"] | "", req["login"] | "")) {
                    CommsManager::sendEvent("PASS", "DELETED");
                } else {
                    CommsManager::sendError("PASS", "NOT_FOUND");
                }
            }
            else if (cmd == "list") {
                listPasswords(); 
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