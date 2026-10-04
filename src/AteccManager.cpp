#include "AteccManager.h"
#include "Globals.h"
#include <Wire.h>

namespace {

constexpr int SDA_PIN = 8;
constexpr int SCL_PIN = 7;
constexpr uint8_t ATECC_ADDR = 0x60;

bool ateccPresent = false;

// The esp32-arduino Wire driver can leave stale bytes from a previous
// transaction sitting in its RX buffer - observed concretely here: after
// wake()'s throwaway write to address 0x00 (which is expected to NACK,
// that's how the wake pulse trick works), the next requestFrom() sometimes
// returned leftover Config-zone bytes from an earlier successful Read
// instead of a real wake response. Defensively drain before trusting a
// fresh read.
void flushWireRx() {
    while (Wire.available()) Wire.read();
}

// Atmel/Microchip CRC-16 (polynomial 0x8005, not reflected) per the
// ATECC508A/608A datasheet appendix.
void atcaCrc(const uint8_t *data, uint8_t length, uint8_t crcOut[2]) {
    uint16_t crcRegister = 0;
    const uint16_t polynom = 0x8005;
    for (uint8_t counter = 0; counter < length; counter++) {
        for (uint8_t shiftReg = 0x01; shiftReg > 0x00; shiftReg <<= 1) {
            uint8_t dataBit = (data[counter] & shiftReg) ? 1 : 0;
            uint8_t crcBit = (uint8_t)(crcRegister >> 15);
            crcRegister <<= 1;
            if (dataBit != crcBit) crcRegister ^= polynom;
        }
    }
    crcOut[0] = (uint8_t)(crcRegister & 0x00FF);
    crcOut[1] = (uint8_t)(crcRegister >> 8);
}

// Caller must hold ateccMutex. The chip's watchdog puts it back to sleep
// ~1.3s after the last transaction, so every command sequence re-wakes it.
//
// This MUST be a genuine "hold SDA low outside of clocked I2C protocol"
// pulse, not a normal Wire transaction. An earlier version of this function
// used Wire.beginTransmission(0x00)/write/endTransmission() (a commonly
// cited trick), which is a completely ordinary, clocked I2C write that
// happens to get NACK'd - not a real wake condition. That only "worked" on
// the very first call after power-on (chip genuinely asleep, so almost
// anything touching the bus tends to rouse it); on every later call in the
// same boot it silently did nothing, and the chip just re-presented its
// last real response again - confirmed on real hardware by the fact that
// the "wake response" bytes exactly matched leftover data from the
// previous command, byte for byte, reproducibly, regardless of retries,
// Wire re-inits, added delays, or even fully power-cycling the chip and
// the ESP32. None of those could have mattered, because the actual wake
// pulse was never real to begin with.
//
// The correct approach (matching Microchip's own reference driver): take
// direct GPIO control of SDA, drive it low for >= tWLO (60us min), then
// release it and let the pull-up bring it back high, before touching I2C
// at all.
bool wake() {
    for (int attempt = 0; attempt < 4; attempt++) {
        Wire.end();

        pinMode(SDA_PIN, OUTPUT);
        digitalWrite(SDA_PIN, LOW);
        delayMicroseconds(100); // > tWLO (60us min), with margin
        pinMode(SDA_PIN, INPUT); // release; external pull-up brings it back high
        delayMicroseconds(1500); // tWHI
        delay(1);

        Wire.begin(SDA_PIN, SCL_PIN);
        Wire.setClock(100000);
        Wire.setTimeOut(50);

        flushWireRx();
        int got = Wire.requestFrom((int)ATECC_ADDR, 4);
        if (got == 4) {
            uint8_t resp[4];
            for (int i = 0; i < 4; i++) resp[i] = Wire.read();
            if (resp[0] == 0x04 && resp[1] == 0x11) {
                uint8_t crc[2];
                atcaCrc(resp, 2, crc);
                if (crc[0] == resp[2] && crc[1] == resp[3]) return true;
            }
        }
        delay(5);
    }
    return false;
}

// Builds and sends one command packet, waits, then reads the response.
//
// On success, copies the response payload (everything between the count
// byte and the trailing CRC) into respOut and returns true - the caller
// must pass the exact payload length it expects in respLen, including the
// respLen==1 case used by ack-only commands (Nonce pass-through) whose
// single data byte is 0x00 on success and a real ATECC error code
// otherwise (the caller checks that byte itself).
//
// On failure, returns false. If the chip replied with a well-formed 4-byte
// error packet and the caller wasn't expecting a 1-byte response (so a
// 4-byte reply can only mean "error, not payload"), the error code is
// written to *errStatus when non-null.
//
// Caller must hold ateccMutex and have called wake() earlier in this
// transaction.
bool runCommand(uint8_t opcode, uint8_t param1, uint16_t param2,
                 const uint8_t *data, uint8_t dataLen,
                 uint16_t initialDelayMs,
                 uint8_t *respOut, uint8_t respLen,
                 uint8_t *errStatus = nullptr) {
    uint8_t packet[1 + 1 + 1 + 2 + 32 + 2]; // count+opcode+param1+param2+data(<=32)+crc
    if (dataLen > 32) return false;

    uint8_t idx = 0;
    packet[idx++] = 0; // count placeholder, filled in below
    packet[idx++] = opcode;
    packet[idx++] = param1;
    packet[idx++] = (uint8_t)(param2 & 0xFF);
    packet[idx++] = (uint8_t)(param2 >> 8);
    if (data && dataLen) {
        memcpy(&packet[idx], data, dataLen);
        idx += dataLen;
    }
    packet[0] = idx + 2; // + CRC
    uint8_t crc[2];
    atcaCrc(packet, idx, crc);
    packet[idx++] = crc[0];
    packet[idx++] = crc[1];

    // Synthetic codes for failures that happen on OUR side of the wire,
    // outside the 0x00-0xEE range the chip itself actually uses for status
    // bytes - so a caller/log can tell "the chip said no" apart from "we
    // never got a trustworthy answer at all" instead of misreading a
    // leftover/default value as a real chip status.
    if (errStatus) *errStatus = 0xF0; // default: no attempt reached far enough to know more

    Wire.beginTransmission(ATECC_ADDR);
    Wire.write((uint8_t)0x03); // word address: Command
    Wire.write(packet, idx);
    if (Wire.endTransmission() != 0) {
        if (errStatus) *errStatus = 0xF1; // I2C write/address failed
        return false;
    }

    delay(initialDelayMs);

    // Poll for the response: the chip NACKs reads while still executing.
    // Bounded generously (up to ~750ms beyond initialDelayMs) to cover the
    // slowest commands (GenKey/Sign) on either chip variant.
    uint8_t respPacketLen = 0;
    bool gotLen = false;
    flushWireRx();
    for (int attempt = 0; attempt < 50 && !gotLen; attempt++) {
        int got = Wire.requestFrom((int)ATECC_ADDR, 1);
        if (got == 1) {
            respPacketLen = Wire.read();
            gotLen = true;
            break;
        }
        delay(15);
    }
    if (!gotLen) {
        if (errStatus) *errStatus = 0xF2; // no response within the poll window
        return false;
    }
    if (respPacketLen < 4) {
        if (errStatus) *errStatus = 0xF3; // garbage/too-short length byte
        return false;
    }

    uint8_t resp[96];
    if (respPacketLen > sizeof(resp)) {
        if (errStatus) *errStatus = 0xF4; // implausibly large length byte
        return false;
    }
    int remaining = respPacketLen - 1;
    int got2 = Wire.requestFrom((int)ATECC_ADDR, remaining);
    if (got2 != remaining) {
        if (errStatus) *errStatus = 0xF5; // short read of the response body
        return false;
    }
    resp[0] = respPacketLen;
    for (int i = 0; i < remaining; i++) resp[1 + i] = Wire.read();

    uint8_t crcCheck[2];
    atcaCrc(resp, respPacketLen - 2, crcCheck);
    if (crcCheck[0] != resp[respPacketLen - 2] || crcCheck[1] != resp[respPacketLen - 1]) {
        if (errStatus) *errStatus = 0xF6; // response CRC mismatch (noise/timing)
        return false;
    }

    if (respPacketLen == 4 && respLen != 1) {
        // Caller expected a real payload but got the short status packet -
        // that's only ever sent to report an error in this case. This IS a
        // genuine chip-reported status byte, unlike the synthetic 0xFx
        // codes above.
        if (errStatus) *errStatus = resp[1];
        return false;
    }

    uint8_t payloadLen = respPacketLen - 3;
    if (payloadLen != respLen) {
        if (errStatus) *errStatus = 0xF7; // valid, CRC-correct reply of an unexpected length
        return false;
    }
    memcpy(respOut, &resp[1], payloadLen);
    return true;
}

} // namespace

bool atecc_init() {
    Wire.begin(SDA_PIN, SCL_PIN);
    Wire.setClock(100000);
    Wire.setTimeOut(50); // esp32-arduino Wire can hang forever on a stuck/floating
                          // bus (no pull-ups, unresponsive device) without this

    xSemaphoreTake(ateccMutex, portMAX_DELAY);
    ateccPresent = wake();
    xSemaphoreGive(ateccMutex);

    Serial.println(ateccPresent
        ? "[SYS] ATECC_INIT: chip detected, using as auxiliary entropy source"
        : "[SYS] ATECC_INIT: chip not detected, continuing on ESP32 TRNG only");
    return ateccPresent;
}

bool atecc_available() {
    return ateccPresent;
}

bool atecc_fill_random(uint8_t *out, size_t len) {
    if (!ateccPresent || len == 0) return false;

    xSemaphoreTake(ateccMutex, portMAX_DELAY);
    uint8_t scratch[32];
    size_t filled = 0;
    bool ok = true;
    while (filled < len) {
        if (!wake() || !runCommand(0x1B /*Random*/, 0x00, 0x0000, nullptr, 0, 23, scratch, 32)) {
            ok = false;
            break;
        }
        size_t chunk = min((size_t)32, len - filled);
        memcpy(out + filled, scratch, chunk);
        filled += chunk;
    }
    xSemaphoreGive(ateccMutex);

    if (!ok) {
        Serial.println("[SYS] ATECC_RANDOM: chip did not respond, falling back to ESP32 TRNG only");
    }
    return ok;
}

bool atecc_genkey_p256(uint8_t slot, uint8_t pubKeyOut64[64]) {
    if (!ateccPresent) return false;

    xSemaphoreTake(ateccMutex, portMAX_DELAY);
    uint8_t errStatus = 0xF8; // wake() itself failed, if this survives untouched below
    bool ok = wake() && runCommand(0x40 /*GenKey*/, 0x04 /*create new random private key*/, slot,
                                    nullptr, 0, 115, pubKeyOut64, 64, &errStatus);
    xSemaphoreGive(ateccMutex);

    if (!ok) {
        Serial.printf("[SYS] ATECC_GENKEY: failed on slot %u (status 0x%02X)\n", slot, errStatus);
    }
    return ok;
}

bool atecc_sign_p256(uint8_t slot, const uint8_t digest32[32], uint8_t sigOut64[64]) {
    if (!ateccPresent) return false;

    xSemaphoreTake(ateccMutex, portMAX_DELAY);
    uint8_t errStatus = 0xF8; // wake() itself failed, if this survives untouched below
    bool ok = false;
    if (wake()) {
        uint8_t ack = 0xFF;
        if (runCommand(0x16 /*Nonce*/, 0x03 /*pass-through, target TempKey*/, 0x0000,
                        digest32, 32, 20, &ack, 1, &errStatus)) {
            if (ack == 0x00) {
                ok = runCommand(0x41 /*Sign*/, 0x80 /*external digest in TempKey*/, slot,
                                 nullptr, 0, 60, sigOut64, 64, &errStatus);
            } else {
                errStatus = ack;
            }
        }
    }
    xSemaphoreGive(ateccMutex);

    if (!ok) {
        Serial.printf("[SYS] ATECC_SIGN: failed on slot %u (status 0x%02X)\n", slot, errStatus);
    }
    return ok;
}

bool atecc_lock_config_zone() {
    if (!ateccPresent) return false;

    xSemaphoreTake(ateccMutex, portMAX_DELAY);
    uint8_t errStatus = 0xF8; // wake() itself failed, if this survives untouched below
    uint8_t ack = 0xFF;
    // Mode 0x80 = LOCK_ZONE_CONFIG (0x00) | LOCK_ZONE_NO_CRC (0x80): lock
    // the Config zone, skip the optional summary-CRC verification (so
    // Param2/summary_crc is unused, left at 0).
    bool ok = wake() && runCommand(0x17 /*Lock*/, 0x80, 0x0000, nullptr, 0, 30, &ack, 1, &errStatus);
    xSemaphoreGive(ateccMutex);

    if (ok && ack != 0x00) {
        ok = false;
        errStatus = ack;
    }

    if (ok) {
        Serial.println("[SYS] ATECC_LOCK_CONFIG: Config zone permanently locked");
    } else {
        Serial.printf("[SYS] ATECC_LOCK_CONFIG: failed (status 0x%02X)\n", errStatus);
    }
    return ok;
}

bool atecc_read_config_zone(uint8_t configOut128[128]) {
    if (!ateccPresent) return false;

    xSemaphoreTake(ateccMutex, portMAX_DELAY);
    bool ok = true;
    for (uint8_t block = 0; block < 4 && ok; block++) {
        uint8_t errStatus = 0xF8; // wake() itself failed, if this survives untouched below
        ok = wake();
        if (ok) {
            // Zone=0x80: Config zone (0x00) | 32-byte read length (0x80).
            // Address=block*8: each unit is a 4-byte word, so block*8 words
            // = block*32 bytes, landing each read on the next 32-byte chunk.
            ok = runCommand(0x02 /*Read*/, 0x80, (uint16_t)block * 8, nullptr, 0, 5,
                             configOut128 + block * 32, 32, &errStatus);
        }
        if (!ok) {
            Serial.printf("[SYS] ATECC_READ_CONFIG: failed at block %u (status 0x%02X)\n", block, errStatus);
        }
    }
    xSemaphoreGive(ateccMutex);
    return ok;
}

bool atecc_read_lock_state(uint8_t *lockValueOut, uint8_t *lockConfigOut) {
    if (!ateccPresent) return false;

    xSemaphoreTake(ateccMutex, portMAX_DELAY);
    uint8_t block2[32];
    uint8_t errStatus = 0xF8;
    // Bytes 86/87 live in block 2 (bytes 64-95): offsets 86-64=22, 87-64=23.
    bool ok = wake() && runCommand(0x02 /*Read*/, 0x80, (uint16_t)2 * 8, nullptr, 0, 5, block2, 32, &errStatus);
    xSemaphoreGive(ateccMutex);

    if (!ok) {
        Serial.printf("[SYS] ATECC_READ_LOCK_STATE: failed (status 0x%02X)\n", errStatus);
        return false;
    }
    if (lockValueOut) *lockValueOut = block2[22];
    if (lockConfigOut) *lockConfigOut = block2[23];
    return true;
}
