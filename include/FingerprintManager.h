#include <Adafruit_Fingerprint.h>

// UART pin map for the fingerprint module.
#define FINGERPRINT_RX 16
#define FINGERPRINT_TX 17

extern HardwareSerial mySerial;
extern Adafruit_Fingerprint finger;

void initFingerprintSensor();
bool enrollFingerprint(uint8_t id);
void updateFingerprintAsync();
