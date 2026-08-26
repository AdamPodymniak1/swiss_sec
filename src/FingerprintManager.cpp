#include "FingerprintManager.h"
#include "DisplayManager.h"
#include "Globals.h"
#include "CryptoManager.h"

HardwareSerial mySerial(1);
Adafruit_Fingerprint finger = Adafruit_Fingerprint(&mySerial);

void initFingerprintSensor() {
#if USE_FINGERPRINT_SIMULATOR
    pinMode(SIMULATOR_BUTTON_PIN, INPUT_PULLUP);
    Serial.println("SIMULATOR READY");
#else
    mySerial.begin(57600, SERIAL_8N1, FINGERPRINT_RX, FINGERPRINT_TX);
    finger.begin(57600);
    
    if (finger.verifyPassword()) {
        Serial.println("READY");
    } else {
        tft.fillScreen(TFT_BLACK);
        tft.setCursor(0, 0);
        tft.println("SENSOR ERROR!");
        delay(2000);
    }
#endif
}

bool enrollFingerprint(uint8_t id) {
#if USE_FINGERPRINT_SIMULATOR
    tft.fillScreen(TFT_BLACK);
    tft.setCursor(0, 0);
    tft.println("Press Button 1");
    while(digitalRead(SIMULATOR_BUTTON_PIN) == HIGH) { delay(50); }
    while(digitalRead(SIMULATOR_BUTTON_PIN) == LOW) { delay(50); }

    tft.fillScreen(TFT_BLACK);
    tft.setCursor(0, 0);
    tft.println("Press Button 2");
    while(digitalRead(SIMULATOR_BUTTON_PIN) == HIGH) { delay(50); }
    while(digitalRead(SIMULATOR_BUTTON_PIN) == LOW) { delay(50); }

    tft.fillScreen(TFT_BLACK);
    tft.setCursor(0, 0);
    tft.println("STORED OK");
    delay(2000);
    return true;
#else
    int p = -1;
    tft.fillScreen(TFT_BLACK);
    tft.setCursor(0, 0);
    tft.println("Place finger");

    while (p != FINGERPRINT_OK) {
        p = finger.getImage();
        if (p != FINGERPRINT_OK) {
            delay(50);
        }
    }

    p = finger.image2Tz(1);
    if (p != FINGERPRINT_OK) return false;

    tft.fillScreen(TFT_BLACK);
    tft.setCursor(0, 0);
    tft.println("Remove finger");
    
    delay(1500); 
    p = 0;
    while (p != FINGERPRINT_NOFINGER) {
        p = finger.getImage();
        delay(50);
    }

    tft.fillScreen(TFT_BLACK);
    tft.setCursor(0, 0);
    tft.println("Place SAME");
    tft.println("finger again");

    p = -1;
    while (p != FINGERPRINT_OK) {
        p = finger.getImage();
        if (p != FINGERPRINT_OK) {
            delay(50);
        }
    }

    p = finger.image2Tz(2);
    if (p != FINGERPRINT_OK) return false;

    p = finger.createModel();
    if (p != FINGERPRINT_OK) {
        tft.fillScreen(TFT_BLACK);
        tft.setCursor(0, 0);
        tft.println("MISMATCH!");
        delay(3000);
        return false;
    }

    p = finger.storeModel(id);
    if (p == FINGERPRINT_OK) {
        tft.fillScreen(TFT_BLACK);
        tft.setCursor(0, 0);
        tft.println("STORED OK!");
        delay(2000);
        return true;
    } else {
        return false;
    }
#endif
}

void updateFingerprintAsync() {
    if (currentCommandState != STATE_AWAITING_FINGERPRINT) return;

#if USE_FINGERPRINT_SIMULATOR
    if (digitalRead(SIMULATOR_BUTTON_PIN) == LOW) {
        while(digitalRead(SIMULATOR_BUTTON_PIN) == LOW) { delay(50); }
        String challengeNonce = generateRandomPassword(16);
        String securePayload = challengeNonce + "1";
        String computedResponse = hashSHA256(securePayload);
        
        Terminal.println(computedResponse);
        Terminal.println(pendingPasswordToTransmit);
        Terminal.flush();
        
        pendingPasswordToTransmit = "";
        currentCommandState = STATE_READY;
        
        tft.fillScreen(TFT_BLACK);
        tft.setCursor(0, 0);
        tft.println("TRANSMITTED!");
        
        unsigned long startWait = millis();
        while (millis() - startWait < 1200) { yield(); }
        
        tft.fillScreen(TFT_BLACK);
        tft.setCursor(0, 0);
        tft.println("Logged In");
    }
#else
    uint8_t imageResult = finger.getImage();

    for (uint8_t retry = 0; retry < 3 && imageResult != FINGERPRINT_OK && imageResult != FINGERPRINT_NOFINGER; retry++) {
        delay(50);
        imageResult = finger.getImage();
    }

    if (imageResult == FINGERPRINT_OK) {
        uint8_t tzResult = finger.image2Tz();
        
        if (tzResult == FINGERPRINT_OK) {
            String challengeNonce = generateRandomPassword(16); 
            
            if (finger.fingerSearch() == FINGERPRINT_OK) {
                uint8_t matchedID = finger.fingerID;
                uint8_t matchConfidence = finger.confidence;

                if (matchConfidence > 50) { 
                    String securePayload = challengeNonce + String(matchedID);
                    String computedResponse = hashSHA256(securePayload); 

                    Terminal.println(computedResponse);
                    Terminal.println(pendingPasswordToTransmit);
                    Terminal.flush();
                    
                    pendingPasswordToTransmit = ""; 
                    currentCommandState = STATE_READY;
                    
                    tft.fillScreen(TFT_BLACK);
                    tft.setCursor(0, 0);
                    tft.println("TRANSMITTED!");
                    
                    unsigned long startWait = millis();
                    while (millis() - startWait < 1200) { yield(); }
                    
                    tft.fillScreen(TFT_BLACK);
                    tft.setCursor(0, 0);
                    tft.println("Logged In");
                } else {
                    tft.fillScreen(TFT_BLACK);
                    tft.setCursor(0, 0);
                    tft.println("Try again");
                    delay(1000);
                }
            } else {
                tft.fillScreen(TFT_BLACK);
                tft.setCursor(0, 0);
                tft.println("Unknown Finger");
                delay(1000);
            }
        } else {
            delay(500); 
        }
    } 
    else if (imageResult != FINGERPRINT_NOFINGER) {
        delay(500);
    }
#endif
}