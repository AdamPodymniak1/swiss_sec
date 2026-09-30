// Deliberately gated, one-off tool to PERMANENTLY lock the ATECC's Config
// zone. This is the one irreversible step in the whole ATECC bench-testing
// effort (see AteccManager.h) - GenKey (opcode 0x40, mode 0x04) refuses to
// create a private key in a slot until the chip's Config zone is locked,
// confirmed against real hardware (status 0x0F) in
// src/debug_genkey_sign/AteccGenKeySignTest.cpp.
//
// Locking does NOT brick the chip or erase anything - it just permanently
// fixes whatever is currently in the Config zone (SlotConfig/KeyConfig for
// all 16 slots, the I2C address, etc.). There is no Unlock command; this
// cannot be undone on this physical chip, ever.
//
// Safety: this tool does nothing destructive on its own. It reads the
// Config zone (always safe), prints it, and only calls
// atecc_lock_config_zone() if you type the exact confirmation phrase over
// serial within the time window. Anything else - wrong text, silence,
// timeout - cancels with zero side effects.
//
//   pio run -e esp32s3-atecc-lock-config -t upload -t monitor

#include <Arduino.h>
#include "AteccManager.h"

#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>
SemaphoreHandle_t ateccMutex = NULL;

static const char *CONFIRM_PHRASE = "LOCK CONFIG";
static const uint32_t CONFIRM_WINDOW_MS = 30000;

static void printHex(const uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (buf[i] < 0x10) Serial.print('0');
        Serial.print(buf[i], HEX);
        Serial.print(' ');
    }
    Serial.println();
}

void setup() {
    Serial.begin(115200);
    uint32_t t0 = millis();
    while (!Serial && millis() - t0 < 3000) { delay(10); }

    Serial.println(F("\n\n================================================================"));
    Serial.println(F(" ATECC Config zone lock tool - IRREVERSIBLE if you confirm below"));
    Serial.println(F("================================================================\n"));

    ateccMutex = xSemaphoreCreateMutex();

    if (!atecc_init()) {
        Serial.println(F("atecc_init() reports chip absent - stopping. Nothing was touched."));
        return;
    }

    uint8_t cfg[128];
    if (!atecc_read_config_zone(cfg)) {
        Serial.println(F("Failed to read Config zone - stopping. Nothing was touched."));
        return;
    }

    bool alreadyLocked = (cfg[87] != 0x55);
    Serial.printf("LockConfig (byte 87) = 0x%02X (%s)\n", cfg[87], alreadyLocked ? "LOCKED" : "unlocked");
    if (alreadyLocked) {
        Serial.println(F("\nConfig zone is already locked - there is nothing for this tool to do."));
        return;
    }

    Serial.println(F("\nCurrent Config zone (this is what would become PERMANENT):"));
    for (int block = 0; block < 4; block++) {
        Serial.printf("  [%3d] ", block * 32);
        printHex(cfg + block * 32, 32);
    }
    Serial.print(F("  SlotConfig[0] (bytes 20-21) = "));
    printHex(cfg + 20, 2);
    Serial.print(F("  KeyConfig[0]  (bytes 96-97) = "));
    printHex(cfg + 96, 2);

    Serial.println(F("\nThis chip has NO Unlock command. Once locked, this Config zone"));
    Serial.println(F("content is permanent on this physical chip, forever."));
    Serial.printf("\nType exactly:  %s\n", CONFIRM_PHRASE);
    Serial.printf("and press Enter within %lu seconds to proceed. Anything else, or\n", CONFIRM_WINDOW_MS / 1000);
    Serial.println(F("silence, cancels with zero changes made.\n"));

    String line;
    uint32_t deadline = millis() + CONFIRM_WINDOW_MS;
    bool confirmed = false;
    while (millis() < deadline) {
        if (Serial.available()) {
            char c = Serial.read();
            if (c == '\n') {
                line.trim();
                if (line == CONFIRM_PHRASE) {
                    confirmed = true;
                }
                break;
            }
            line += c;
        }
        delay(10);
    }

    if (!confirmed) {
        Serial.println(F("\nNot confirmed (wrong text, nothing typed, or timed out)."));
        Serial.println(F("Cancelled - nothing was changed. Re-run this tool to try again."));
        return;
    }

    Serial.println(F("\nConfirmed. Locking Config zone now ..."));
    if (atecc_lock_config_zone()) {
        Serial.println(F("\nDone. Config zone is now permanently locked."));
        Serial.println(F("Re-run the esp32s3-atecc-genkey-sign-test env to verify GenKey/Sign now work."));
    } else {
        Serial.println(F("\nLock command failed - see the [SYS] ATECC_LOCK_CONFIG status line above."));
        Serial.println(F("The zone is very likely still unlocked; safe to investigate and retry."));
    }
}

void loop() {
    delay(5000);
}
