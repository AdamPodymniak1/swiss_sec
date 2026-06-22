#include "FingerprintManager.h"
#include "DisplayManager.h"
#include "Globals.h"
#include "CryptoManager.h"

HardwareSerial mySerial(1);
Adafruit_Fingerprint finger = Adafruit_Fingerprint(&mySerial);

void initFingerprintSensor() {
    mySerial.begin(57600, SERIAL_8N1, FINGERPRINT_RX, FINGERPRINT_TX);
    finger.begin(57600);
    
    if (finger.verifyPassword()) {
        Serial.println("[SYS] FINGERPRINT MODULE READY");
    } else {
        Serial.println("[SYS] ERR: FINGERPRINT SENSOR NOT FOUND!");
        tft.fillScreen(TFT_RED);
        tft.setCursor(10, 20);
        tft.println("SENSOR ERROR!");
        delay(2000);
    }
}

bool enrollFingerprint(uint8_t id) {
    int p = -1;
    
    tft.fillScreen(TFT_NAVY);
    tft.setTextColor(TFT_WHITE, TFT_NAVY);
    tft.setCursor(10, 20);
    tft.println("SYSTEM RESET:");
    tft.setTextColor(TFT_YELLOW, TFT_NAVY);
    tft.setCursor(10, 50);
    tft.println("Place finger on");
    tft.println("sensor now...");
    Terminal.println("[SYS] ENROLL: AWAITING FIRST FINGER PRESS");

    while (p != FINGERPRINT_OK) {
        p = finger.getImage();
        if (p == FINGERPRINT_OK) {
            Terminal.println("[SYS] ENROLL: IMAGE 1 TAKEN");
        } else {
            delay(50);
        }
    }

    p = finger.image2Tz(1);
    if (p != FINGERPRINT_OK) return false;

    tft.fillScreen(TFT_NAVY);
    tft.setTextColor(TFT_WHITE, TFT_NAVY);
    tft.setCursor(10, 50);
    tft.println("Remove finger...");
    Terminal.println("[SYS] ENROLL: AWAITING FINGER REMOVAL");
    
    delay(1500); 
    p = 0;
    while (p != FINGERPRINT_NOFINGER) {
        p = finger.getImage();
        delay(50);
    }

    tft.fillScreen(TFT_NAVY);
    tft.setCursor(10, 50);
    tft.println("Place SAME");
    tft.println("finger again...");
    Terminal.println("[SYS] ENROLL: AWAITING SECOND FINGER PRESS");

    p = -1;
    while (p != FINGERPRINT_OK) {
        p = finger.getImage();
        if (p == FINGERPRINT_OK) {
            Terminal.println("[SYS] ENROLL: IMAGE 2 TAKEN");
        } else {
            delay(50);
        }
    }

    p = finger.image2Tz(2);
    if (p != FINGERPRINT_OK) return false;

    p = finger.createModel();
    if (p != FINGERPRINT_OK) {
        Terminal.println("[ERR] ENROLL: FINGER MISMATCH");
        tft.fillScreen(TFT_RED);
        tft.setTextColor(TFT_WHITE, TFT_RED);
        tft.setCursor(10, 50);
        tft.println("MISMATCH!");
        tft.println("Enrollment Failed.");
        delay(3000);
        return false;
    }

    p = finger.storeModel(id);
    if (p == FINGERPRINT_OK) {
        Terminal.println("[SYS] ENROLL: SUCCESS");
        tft.fillScreen(TFT_DARKGREEN);
        tft.setTextColor(TFT_WHITE, TFT_DARKGREEN);
        tft.setCursor(10, 50);
        tft.println("STORED OK!");
        delay(2000);
        return true;
    } else {
        return false;
    }
}

void updateFingerprintAsync() {
    if (currentCommandState != STATE_AWAITING_FINGERPRINT) return;

    uint8_t imageResult = finger.getImage();

    for (uint8_t retry = 0; retry < 3 && imageResult != FINGERPRINT_OK && imageResult != FINGERPRINT_NOFINGER; retry++) {
        delay(50);
        imageResult = finger.getImage();
    }

    if (imageResult == FINGERPRINT_OK) {
        uint8_t tzResult = finger.image2Tz();
        
        if (tzResult == FINGERPRINT_OK) {
            String challengeNonce = generateRandomPassword(16); 
            Terminal.println("[SYS] BIOMETRIC_CHALLENGE:" + challengeNonce);
            
            if (finger.fingerSearch() == FINGERPRINT_OK) {
                uint8_t matchedID = finger.fingerID;
                uint8_t matchConfidence = finger.confidence;

                if (matchConfidence > 50) { 
                    String securePayload = challengeNonce + String(matchedID);
                    String computedResponse = hashSHA256(securePayload); 

                    Terminal.println("[SYS] AUTH_RESPONSE_TOKEN:" + computedResponse);
                    Terminal.println("[PASS] VALUE:" + pendingPasswordToTransmit);
                    Terminal.flush();
                    
                    pendingPasswordToTransmit = ""; 
                    securePayload = "";
                    computedResponse = "";
                    currentCommandState = STATE_READY;
                    
                    tft.fillScreen(TFT_DARKGREEN);
                    tft.setTextColor(TFT_WHITE, TFT_DARKGREEN);
                    tft.setCursor(20, 50);
                    tft.println("TRANSMITTED!");
                    
                    unsigned long startWait = millis();
                    while (millis() - startWait < 1200) {
                        yield();
                    }
                    
                    tft.fillScreen(TFT_BLACK);
                    tft.setTextColor(TFT_WHITE, TFT_BLACK);
                    tft.setCursor(10, 20);
                    tft.println("System Logged In");
                } else {
                    Terminal.println("[ERR] AUTH: CONFIDENCE_TOO_LOW");
                    tft.setCursor(10, 200);
                    tft.println("Try again (Low Con.)");
                    delay(1000);
                }
            } else {
                Terminal.println("[ERR] AUTH: BIOMETRIC_MISMATCH");
                tft.setCursor(10, 200);
                tft.println("Unknown Finger");
                delay(1000);
            }
        } else {
            Terminal.print("[ERR] IMAGE_CONVERSION_FAILED: 0x");
            Terminal.println(String(tzResult, HEX));
            delay(500); 
        }
    } 
    else if (imageResult != FINGERPRINT_NOFINGER) {
        Terminal.print("[ERR] SENSOR_READ_ERROR: 0x");
        Terminal.println(String(imageResult, HEX));
        delay(500);
    }
}