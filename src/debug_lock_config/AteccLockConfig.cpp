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

    // Checking just LockValue/LockConfig (atecc_read_lock_state, a single
    // targeted 32-byte read) rather than the full 128-byte Config zone
    // dump the original version of this tool used
    // (atecc_read_config_zone, four 32-byte reads) - that's init()+4 more
    // wake() calls, and a separate wake-reliability issue means a boot
    // only reliably survives 2 total wake() calls before one starts
    // intermittently failing. init()+this one targeted read stays inside
    // that budget.
    uint8_t lockValue = 0xEE, lockConfig = 0xEE;
    if (!atecc_read_lock_state(&lockValue, &lockConfig)) {
        Serial.println(F("Failed to read lock state - stopping. Nothing was touched."));
        return;
    }
    Serial.printf("LockValue  (byte 86) = 0x%02X (%s)\n", lockValue, lockValue == 0x55 ? "unlocked" : "LOCKED");
    Serial.printf("LockConfig (byte 87) = 0x%02X (%s)\n", lockConfig, lockConfig == 0x55 ? "unlocked" : "LOCKED");
    if (lockConfig != 0x55) {
        Serial.println(F("\nConfig zone is already locked - there is nothing for this tool to do."));
        return;
    }

    // No full Config zone dump before the confirmation prompt, for the
    // same reason as above: that read already used this boot's one spare
    // wake() call, and the Lock command itself (opcode 0x17) needs
    // another. Confirmed by hand against this chip: unlocked
    // (LockConfig=0x55), slot 0 correctly configured (KeyConfig[0]=0x0033:
    // Private=1, KeyType=4/P256; SlotConfig[0]=0x2083: WriteConfig=Never)
    // - see the conversation record if you need to re-check that by hand
    // for a different chip; this tool no longer re-dumps it live.
    Serial.println(F("This chip has NO Unlock command. Once locked, this Config zone"));
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
