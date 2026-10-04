// One-off hardware-in-the-loop validation for AteccManager's GenKey/Sign
// path (src/AteccManager.cpp), run against real silicon to answer the open
// question from AteccManager.h: does Sign actually work with the chip's
// zones left unlocked? The env building this (see platformio.ini) links
// the real src/AteccManager.cpp via build_src_filter rather than
// reimplementing any of its logic, so what's tested here is exactly what
// ships in the firmware.
//
//   pio run -e esp32s3-atecc-genkey-sign-test -t upload -t monitor

#include <Arduino.h>
#include "mbedtls/ecdsa.h"
#include "mbedtls/version.h"
#include "AteccManager.h"

#if MBEDTLS_VERSION_NUMBER >= 0x03000000
    #define M_GRP MBEDTLS_PRIVATE(grp)
    #define M_Q   MBEDTLS_PRIVATE(Q)
#else
    #define M_GRP grp
    #define M_Q   Q
#endif

// AteccManager.cpp only touches ateccMutex out of everything Globals.h
// declares, so define just that here instead of pulling in the rest of
// the app (Globals.cpp, StorageManager, etc.) that this test doesn't need.
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>
SemaphoreHandle_t ateccMutex = NULL;

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

    Serial.println(F("\n\n================================================"));
    Serial.println(F(" ATECC GenKey/Sign hardware validation (slot 0)"));
    Serial.println(F("================================================\n"));

    ateccMutex = xSemaphoreCreateMutex();

    if (!atecc_init()) {
        Serial.println(F("atecc_init() reports chip absent - stopping."));
        return;
    }

    // No Step 0 Config-zone dump here: that's a separate 4x wake() call
    // (atecc_read_config_zone) and combining it with GenKey+Sign in one
    // boot runs into a wake-reliability issue unrelated to zone locking -
    // past the 2nd wake() call in a single boot, the 3rd+ intermittently
    // fails. Use the dedicated lock-state check or a standalone config
    // read if you need that dump; this tool stays within the proven-
    // reliable 2-wake-call range (init, then GenKey) before Sign adds a 3rd
    // and becomes a candidate to hit the same issue.
    Serial.println(F("Step 1: GenKey (create new random private key in slot 0) ..."));
    uint8_t pub64[64];
    if (!atecc_genkey_p256(0, pub64)) {
        Serial.println(F("  -> FAILED. See [SYS] ATECC_GENKEY status line above for the reason."));
        return;
    }
    Serial.print(F("  -> OK, public key (X||Y): "));
    printHex(pub64, 64);

    Serial.println(F("\nStep 2: Sign a test digest with that same slot ..."));
    uint8_t digest[32];
    for (int i = 0; i < 32; i++) digest[i] = (uint8_t)(i * 7 + 1); // arbitrary fixed pattern, not a real hash
    Serial.print(F("  digest: "));
    printHex(digest, 32);

    uint8_t sig[64];
    if (!atecc_sign_p256(0, digest, sig)) {
        Serial.println(F("  -> FAILED. See [SYS] ATECC_SIGN status line above for the reason."));
        Serial.println(F("     If the status is 0x0F (execution error), that's the datasheet's"));
        Serial.println(F("     \"not allowed in current state\" - plausibly the unlocked-zone"));
        Serial.println(F("     restriction AteccManager.h warns about. Locking would be the next"));
        Serial.println(F("     thing to try, deliberately, once you're ready for that to be permanent."));
        return;
    }
    Serial.print(F("  -> OK, signature (R||S): "));
    printHex(sig, 64);

    Serial.println(F("\nStep 3: verify the signature against the public key, in software,"));
    Serial.println(F("so a wrong-but-plausible-looking signature doesn't read as success ..."));

    mbedtls_ecdsa_context ctx;
    mbedtls_ecdsa_init(&ctx);
    int ret = mbedtls_ecp_group_load(&ctx.M_GRP, MBEDTLS_ECP_DP_SECP256R1);
    uint8_t pubFull[65];
    pubFull[0] = 0x04;
    memcpy(pubFull + 1, pub64, 64);
    if (ret == 0) ret = mbedtls_ecp_point_read_binary(&ctx.M_GRP, &ctx.M_Q, pubFull, 65);

    mbedtls_mpi r, s;
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);
    if (ret == 0) ret = mbedtls_mpi_read_binary(&r, sig, 32);
    if (ret == 0) ret = mbedtls_mpi_read_binary(&s, sig + 32, 32);

    if (ret == 0) {
        ret = mbedtls_ecdsa_verify(&ctx.M_GRP, digest, sizeof(digest), &ctx.M_Q, &r, &s);
    }

    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    mbedtls_ecdsa_free(&ctx);

    if (ret == 0) {
        Serial.println(F("  -> VALID. Hardware GenKey + Sign round-trips correctly end to end."));
    } else {
        Serial.printf("  -> INVALID (mbedtls error -0x%04X). Something is wrong with the\n", -ret);
        Serial.println(F("     signature/pubkey pairing even though the chip returned OK status."));
    }
}

void loop() {
    delay(5000);
}
