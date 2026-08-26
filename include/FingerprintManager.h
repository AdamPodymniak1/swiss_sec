#include <Adafruit_Fingerprint.h>

#define FINGERPRINT_RX 16
#define FINGERPRINT_TX 17

extern HardwareSerial mySerial;
extern Adafruit_Fingerprint finger;

// Core functions
void initFingerprintSensor();
bool enrollFingerprint(uint8_t id);
void updateFingerprintAsync();