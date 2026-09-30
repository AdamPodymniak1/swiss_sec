#ifndef ATECC_MANAGER_H
#define ATECC_MANAGER_H

#include <Arduino.h>

// Optional ATECC508A/608A crypto-authentication chip on the I2C bus
// (SDA=GPIO8, SCL=GPIO7, address 0x60 - see src/debug/AteccDebug.cpp for
// how that was confirmed on the bench). Every entry point here degrades to
// "chip absent" instead of failing if the part isn't present or stops
// responding, so the rest of the firmware must keep working fine without
// it - this is a hardware add-on, never a hard dependency.
//
// IMPORTANT: this chip's config/data zones are intentionally left UNLOCKED
// (no Lock command is implemented here - locking is permanent and a wrong
// config bricks the chip for that purpose forever). atecc_fill_random works
// fine unlocked (bench-verified). atecc_genkey_p256 does NOT: on real
// hardware (ATECC608, silicon rev 00 00 60 02) GenKey-private fails with
// status 0x0F (execution error) until the zones are locked - see
// src/debug_genkey_sign/AteccGenKeySignTest.cpp, which is how this was
// confirmed. atecc_sign_p256 was never reached in that test as a result and
// remains unverified. Both functions are kept here, dormant, for when zone
// locking is deliberately taken on as its own task.

bool atecc_init();
bool atecc_available();

// Fills `len` bytes with output from the chip's hardware RNG (opcode 0x1B,
// Random command), concatenating 32-byte blocks as needed. Returns false -
// and leaves `out` untouched - if the chip is absent or any I2C/CRC error
// happens partway through. Callers must always have their own independent
// RNG as the primary source and only mix this in (see secureFillRandom in
// CryptoManager.cpp).
bool atecc_fill_random(uint8_t *out, size_t len);

// Generates a new random private key inside chip slot `slot` (GenKey,
// opcode 0x40, mode 0x04) - the private key never leaves the chip. Returns
// the resulting 64-byte uncompressed public key (X||Y, no 0x04 prefix).
bool atecc_genkey_p256(uint8_t slot, uint8_t pubKeyOut64[64]);

// Signs a pre-computed 32-byte digest with the private key held in `slot`
// (created via atecc_genkey_p256, or already provisioned there). Loads the
// digest into TempKey via a Nonce pass-through (opcode 0x16, mode 0x03),
// then runs Sign in external-digest mode (opcode 0x41, mode 0x80). Returns
// a raw 64-byte (R||S) signature - DER-encode it the same way
// signECDSA_P256 does if you need that format.
bool atecc_sign_p256(uint8_t slot, const uint8_t digest32[32], uint8_t sigOut64[64]);

// Reads the full 128-byte Config zone (Read, opcode 0x02, four 32-byte
// blocks). Always legal regardless of lock state - purely diagnostic, no
// side effects. Byte 87 (LockConfig) and byte 86 (LockValue) report the
// zones' current lock state: 0x55 = unlocked, 0x00 = locked.
bool atecc_read_config_zone(uint8_t configOut128[128]);

// PERMANENTLY locks the Config zone (Lock, opcode 0x17, mode 0x80 =
// LOCK_ZONE_CONFIG | LOCK_ZONE_NO_CRC). This cannot be undone, ever, on
// this physical chip - it is the one genuinely irreversible operation in
// this file. Everything else here (including GenKey/Sign) degrades
// gracefully on failure; this does not, by definition. Not called from
// anywhere in the live app - only from the deliberately-gated
// src/debug_lock_config/AteccLockConfig.cpp tool, which requires typing a
// confirmation phrase over serial before calling this.
bool atecc_lock_config_zone();

#endif
