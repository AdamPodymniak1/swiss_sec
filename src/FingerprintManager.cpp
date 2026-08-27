#include "FingerprintManager.h"
#include "DisplayManager.h"
#include "Globals.h"
#include "CryptoManager.h"

HardwareSerial mySerial(1);
Adafruit_Fingerprint finger = Adafruit_Fingerprint(&mySerial);

// Simulator mode keeps auth flows testable without the UART fingerprint module.
void initFingerprintSensor() {
#if USE_FINGERPRINT_SIMULATOR
    pinMode(SIMULATOR_BUTTON_PIN, INPUT_PULLUP);
    Serial.println("SIMULATOR READY");
#else
    mySerial.begin(57600, SERIAL_8N1, FINGERPRINT_RX, FINGERPRINT_TX);

    xSemaphoreTake(fingerprintMutex, portMAX_DELAY);
    finger.begin(57600);
    bool verified = finger.verifyPassword();
    xSemaphoreGive(fingerprintMutex);

    if (verified) {
        Serial.println("READY");
    } else {
        showDisplayMessage(1, "SENSOR ERROR!", "", 2000);
    }
#endif
}

bool enrollFingerprint(uint8_t id) {
#if USE_FINGERPRINT_SIMULATOR
    showDisplayMessage(1, "Press Button 1", "", 0);

    while(digitalRead(SIMULATOR_BUTTON_PIN) == HIGH) { vTaskDelay(50 / portTICK_PERIOD_MS); }
    while(digitalRead(SIMULATOR_BUTTON_PIN) == LOW) { vTaskDelay(50 / portTICK_PERIOD_MS); }

    showDisplayMessage(1, "Press Button 2", "", 0);

    while(digitalRead(SIMULATOR_BUTTON_PIN) == HIGH) { vTaskDelay(50 / portTICK_PERIOD_MS); }
    while(digitalRead(SIMULATOR_BUTTON_PIN) == LOW) { vTaskDelay(50 / portTICK_PERIOD_MS); }

    showDisplayMessage(1, "STORED OK", "", 2000);
    return true;
#else
    int p = -1;

    showDisplayMessage(1, "Place finger", "", 0);

    while (p != FINGERPRINT_OK) {
        xSemaphoreTake(fingerprintMutex, portMAX_DELAY);
        p = finger.getImage();
        xSemaphoreGive(fingerprintMutex);
        if (p != FINGERPRINT_OK) {
            vTaskDelay(50 / portTICK_PERIOD_MS);
        }
    }

    xSemaphoreTake(fingerprintMutex, portMAX_DELAY);
    p = finger.image2Tz(1);
    xSemaphoreGive(fingerprintMutex);
    if (p != FINGERPRINT_OK) return false;

    showDisplayMessage(1, "Remove finger", "", 0);
    vTaskDelay(1500 / portTICK_PERIOD_MS);

    p = 0;
    while (p != FINGERPRINT_NOFINGER) {
        xSemaphoreTake(fingerprintMutex, portMAX_DELAY);
        p = finger.getImage();
        xSemaphoreGive(fingerprintMutex);
        vTaskDelay(50 / portTICK_PERIOD_MS);
    }

    showDisplayMessage(2, "Place SAME", "finger again", 0);

    p = -1;
    while (p != FINGERPRINT_OK) {
        xSemaphoreTake(fingerprintMutex, portMAX_DELAY);
        p = finger.getImage();
        xSemaphoreGive(fingerprintMutex);
        if (p != FINGERPRINT_OK) {
            vTaskDelay(50 / portTICK_PERIOD_MS);
        }
    }

    xSemaphoreTake(fingerprintMutex, portMAX_DELAY);
    p = finger.image2Tz(2);
    xSemaphoreGive(fingerprintMutex);
    if (p != FINGERPRINT_OK) return false;

    xSemaphoreTake(fingerprintMutex, portMAX_DELAY);
    p = finger.createModel();
    xSemaphoreGive(fingerprintMutex);
    if (p != FINGERPRINT_OK) {
        showDisplayMessage(1, "MISMATCH!", "", 3000);
        return false;
    }

    xSemaphoreTake(fingerprintMutex, portMAX_DELAY);
    p = finger.storeModel(id);
    xSemaphoreGive(fingerprintMutex);
    if (p == FINGERPRINT_OK) {
        showDisplayMessage(1, "STORED OK", "", 2000);
        return true;
    } else {
        return false;
    }
#endif
}

// Password release is polled from the CLI task instead of blocking on sensor reads.
void updateFingerprintAsync() {
    if (currentCommandState != STATE_AWAITING_FINGERPRINT) return;

#if USE_FINGERPRINT_SIMULATOR
    if (digitalRead(SIMULATOR_BUTTON_PIN) == LOW) {
        while(digitalRead(SIMULATOR_BUTTON_PIN) == LOW) { vTaskDelay(50 / portTICK_PERIOD_MS); }
        String challengeNonce = generateRandomPassword(16);
        String securePayload = challengeNonce + "1";
        String computedResponse = hashSHA256(securePayload);

        Terminal.println(pendingPasswordToTransmit);
        Terminal.flush();

        pendingPasswordToTransmit = "";
        currentCommandState = STATE_READY;

        showDisplayMessage(1, "TRANSMITTED!", "", 0);
    }
#else
    xSemaphoreTake(fingerprintMutex, portMAX_DELAY);
    uint8_t imageResult = finger.getImage();
    xSemaphoreGive(fingerprintMutex);

    for (uint8_t retry = 0; retry < 3 && imageResult != FINGERPRINT_OK && imageResult != FINGERPRINT_NOFINGER; retry++) {
        vTaskDelay(50 / portTICK_PERIOD_MS);
        xSemaphoreTake(fingerprintMutex, portMAX_DELAY);
        imageResult = finger.getImage();
        xSemaphoreGive(fingerprintMutex);
    }

    if (imageResult == FINGERPRINT_OK) {
        xSemaphoreTake(fingerprintMutex, portMAX_DELAY);
        uint8_t tzResult = finger.image2Tz();
        xSemaphoreGive(fingerprintMutex);

        if (tzResult == FINGERPRINT_OK) {
            String challengeNonce = generateRandomPassword(16);

            xSemaphoreTake(fingerprintMutex, portMAX_DELAY);
            uint8_t searchResult = finger.fingerSearch();
            uint8_t matchedID = finger.fingerID;
            uint8_t matchConfidence = finger.confidence;
            xSemaphoreGive(fingerprintMutex);

            if (searchResult == FINGERPRINT_OK) {
                if (matchConfidence > 50) { 
                    String securePayload = challengeNonce + String(matchedID);
                    String computedResponse = hashSHA256(securePayload); 

                    Terminal.println(computedResponse);
                    Terminal.println(pendingPasswordToTransmit);
                    Terminal.flush();

                    pendingPasswordToTransmit = ""; 
                    currentCommandState = STATE_READY;

                    showDisplayMessage(1, "TRANSMITTED!", "", 0);

                    unsigned long startWait = millis();
                    while (millis() - startWait < 1200) { vTaskDelay(10 / portTICK_PERIOD_MS); }

                    showDisplayMessage(1, "Logged In", "", 0);
                } else {
                    showDisplayMessage(1, "Try again", "", 1000);
                }
            } else {
                showDisplayMessage(1, "Unknown Finger", "", 2000);
            }
        } else {
            vTaskDelay(500 / portTICK_PERIOD_MS);
        }
    } 
    else if (imageResult != FINGERPRINT_NOFINGER) {
        vTaskDelay(500 / portTICK_PERIOD_MS);
    }
#endif
}
