// Standalone ATECC508A/608A I2C diagnostic sketch.
// Built only by the `esp32s3-atecc-debug` PlatformIO env (see platformio.ini) so it
// never links against the real firmware's setup()/loop() in src/main.cpp.
//
// Wiring assumed: SDA = GPIO8, SCL = GPIO7 (per user). Swap SDA_PIN/SCL_PIN below
// if that's wrong. Also wire a pull-up (2.2k-10k) to 3V3 on both lines if your
// breakout doesn't already have them on board - most bare ATECC modules don't.
//
// What this does, in order, printing a verdict after each step:
//   1. Full I2C bus scan (7-bit addresses 0x08-0x77) - confirms wiring/power/pull-ups.
//   2. ATECC wake sequence + wake response check at the common candidate addresses.
//   3. Sends the Info command (opcode 0x30) to a chip that woke, and decodes the
//      reply (or the error status byte).
//
// Usage:
//   pio run -e esp32s3-atecc-debug -t upload -t monitor

#include <Arduino.h>
#include <Wire.h>

static constexpr int SDA_PIN = 8;
static constexpr int SCL_PIN = 7;

// Addresses actually seen in the wild: 0x60 is the factory default on virtually
// every ATECC508A/608A part and breakout (Microchip, Adafruit, SparkFun). 0x6C
// and 0x35 show up on some pre-provisioned/relabeled modules. We probe all three
// explicitly in addition to the generic scan, since a woken ATECC often won't
// ACK normal scan traffic the same way a plain I2C peripheral does.
static const uint8_t CANDIDATE_ADDRS[] = {0x60, 0x6C, 0x35};

// ---------------------------------------------------------------------------
// Atmel/Microchip CRC-16 (polynomial 0x8005, not reflected) as specified in the
// ATECC508A/608A datasheet appendix. Used to both build outgoing command packets
// and verify incoming response packets.
// ---------------------------------------------------------------------------
static void atcaCrc(const uint8_t *data, uint8_t length, uint8_t crcOut[2]) {
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

static void printHex(const uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (buf[i] < 0x10) Serial.print('0');
        Serial.print(buf[i], HEX);
        Serial.print(' ');
    }
    Serial.println();
}

// ---------------------------------------------------------------------------
// Step 1: plain I2C bus scan. This alone tells you a lot:
//   - nothing found at all           -> wiring, power, or pull-up problem
//   - something found, not at 0x60   -> address mismatch, check your part/label
//   - 0x60 (or another ATECC addr)   -> bus is fine, problem is in the protocol
// Note a *sleeping* ATECC normally will NOT ack a plain scan - that's expected,
// it needs the wake sequence first. So an empty scan is not proof the chip is
// dead; step 2 is the real test.
// ---------------------------------------------------------------------------
static void scanBus() {
    Serial.println(F("\n=== Step 1: I2C bus scan ==="));
    int found = 0;
    for (uint8_t addr = 0x08; addr < 0x78; addr++) {
        Wire.beginTransmission(addr);
        uint8_t err = Wire.endTransmission();
        if (err == 0) {
            Serial.printf("  Device ACKed at 0x%02X\n", addr);
            found++;
        }
    }
    if (found == 0) {
        Serial.println(F("  No devices found. A sleeping ATECC will NOT show up here -"));
        Serial.println(F("  that's expected. If step 2 also finds nothing, check wiring:"));
        Serial.println(F("  SDA/SCL swapped, no pull-ups, wrong voltage (ATECC is 3.3V/1.8V,"));
        Serial.println(F("  never 5V), or a bad/unsoldered connection."));
    } else {
        Serial.printf("  %d device(s) ACKed a plain scan (ATECC itself may still be asleep).\n", found);
    }
}

// ---------------------------------------------------------------------------
// Step 2: wake the chip and check the wake response.
//
// Wake mechanism: hold SDA low for >= tWLO (60us min) while SCL is idle. The
// standard trick with the Wire library is to address 0x00 (general call) and
// let the driver's clock-stretched write hold the line low long enough - this
// is what Microchip's own Arduino wrapper and most community libraries do,
// since Wire gives no direct bit-banging control. We don't care about the
// ACK/NACK of that dummy transmission, only that it happened.
//
// After releasing, wait tWHI (worst case ~2.5ms across 508A/608A parts) then
// read 4 bytes. A healthy wake reply is exactly:  04 11 33 43
//   byte0 = 0x04           (count)
//   byte1 = 0x11           (status: "after wake, all good")
//   byte2,3 = CRC of [0x04, 0x11]
// Any other byte1 (e.g. watchdog-about-to-expire, CRC error, etc.) or a failed
// I2C read means either the wrong address, a dead/unpowered chip, or noise.
// ---------------------------------------------------------------------------
static bool wakeAndCheck(uint8_t addr) {
    Serial.printf("  Trying wake against address 0x%02X ... ", addr);

    // Generic wake pulse: address 0x00 write, ignore result.
    Wire.beginTransmission(0x00);
    Wire.write((uint8_t)0x00);
    Wire.endTransmission();

    delayMicroseconds(1500); // tWHI worst case (608A ~1.5ms, 508A can need up to 2.5ms)
    delay(1);                // extra margin for slower 508A parts

    int got = Wire.requestFrom((int)addr, 4);
    if (got != 4) {
        Serial.printf("no response (requestFrom returned %d bytes)\n", got);
        return false;
    }

    uint8_t resp[4];
    for (int i = 0; i < 4; i++) resp[i] = Wire.read();

    Serial.print("raw reply: ");
    printHex(resp, 4);

    if (resp[0] == 0x04 && resp[1] == 0x11) {
        uint8_t crc[2];
        atcaCrc(resp, 2, crc);
        if (crc[0] == resp[2] && crc[1] == resp[3]) {
            Serial.println(F("    -> valid wake response, chip is alive and responsive."));
            return true;
        }
        Serial.println(F("    -> status looks right but CRC mismatch - bus noise, missing"));
        Serial.println(F("       pull-ups, or I2C clock too fast/unstable. Try slower Wire.setClock()."));
        return false;
    }

    if (resp[0] == 0x04 && resp[1] == 0x07) {
        Serial.println(F("    -> self-test error reported on wake. Chip woke but is unhappy -"));
        Serial.println(F("       check supply voltage/decoupling, or the chip may be damaged/fused."));
        return false;
    }

    Serial.println(F("    -> unrecognized wake reply - probably not an ATECC at this address,"));
    Serial.println(F("       or timing (tWLO/tWHI) isn't being met at this I2C speed."));
    return false;
}

// ---------------------------------------------------------------------------
// Step 3: send the Info command (opcode 0x30, param1=0 "revision") to a chip
// that just woke, and decode the reply. This is the simplest command that
// needs no config/keys, so it's a good "is the protocol layer actually
// working" check independent of provisioning state.
// ---------------------------------------------------------------------------
static void sendInfoCommand(uint8_t addr) {
    Serial.println(F("  Sending Info command (opcode 0x30) ..."));

    // Packet (everything after the I2C word-address byte):
    //   [count][opcode][param1][param2_lo][param2_hi][crc_lo][crc_hi]
    uint8_t packet[7];
    packet[0] = 7;      // count = bytes from here through CRC inclusive
    packet[1] = 0x30;   // Info opcode
    packet[2] = 0x00;   // param1 = revision mode
    packet[3] = 0x00;   // param2 lo
    packet[4] = 0x00;   // param2 hi
    uint8_t crc[2];
    atcaCrc(packet, 5, crc);
    packet[5] = crc[0];
    packet[6] = crc[1];

    Wire.beginTransmission(addr);
    Wire.write((uint8_t)0x03); // word address: 0x03 = Command
    Wire.write(packet, sizeof(packet));
    uint8_t txErr = Wire.endTransmission();
    if (txErr != 0) {
        Serial.printf("    -> I2C write failed (endTransmission error %d). Chip may have gone\n", txErr);
        Serial.println(F("       back to sleep, or NACKed - it needs a fresh wake right before"));
        Serial.println(F("       every command; the watchdog puts it back to sleep after ~1.3s idle."));
        return;
    }

    delay(5); // Info execution time is short (~1ms on 608A) but give margin

    // Response is [count][data...][crc_lo][crc_hi]; for Info success that's
    // count=7, 4 bytes of silicon revision, 2 bytes CRC. Retry a few times -
    // the chip NACKs reads while still executing.
    uint8_t respLen = 0;
    uint8_t resp[32];
    bool gotResponse = false;
    for (int attempt = 0; attempt < 5 && !gotResponse; attempt++) {
        int got = Wire.requestFrom((int)addr, 1);
        if (got == 1) {
            respLen = Wire.read();
            if (respLen >= 4 && respLen <= sizeof(resp)) {
                // Need the rest of the packet: respLen total, 1 already read.
                int remaining = respLen - 1;
                int got2 = Wire.requestFrom((int)addr, remaining);
                if (got2 == remaining) {
                    resp[0] = respLen;
                    for (int i = 0; i < remaining; i++) resp[1 + i] = Wire.read();
                    gotResponse = true;
                    break;
                }
            }
        }
        delay(2);
    }

    if (!gotResponse) {
        Serial.println(F("    -> no valid response after retries. Command layer isn't working -"));
        Serial.println(F("       double check the wake-then-command timing and that nothing else"));
        Serial.println(F("       is holding the bus (only one master allowed)."));
        return;
    }

    Serial.print("    raw response: ");
    printHex(resp, respLen);

    if (respLen == 4) {
        // A 4-byte reply here is a single status/error byte packet, not data.
        uint8_t status = resp[1];
        Serial.printf("    -> error status byte 0x%02X: ", status);
        switch (status) {
            case 0x01: Serial.println(F("checkmac/verify miscompare")); break;
            case 0x03: Serial.println(F("parse error - malformed command packet")); break;
            case 0x05: Serial.println(F("ECC fault")); break;
            case 0x0F: Serial.println(F("execution error - command not allowed in current state")); break;
            case 0xEE: Serial.println(F("watchdog about to expire - resend after a fresh wake")); break;
            case 0xFF: Serial.println(F("CRC or other communication error on the request")); break;
            default:   Serial.println(F("unrecognized status code, check datasheet table")); break;
        }
        return;
    }

    // Verify CRC over everything except the trailing CRC bytes.
    uint8_t crcCheck[2];
    atcaCrc(resp, respLen - 2, crcCheck);
    if (crcCheck[0] != resp[respLen - 2] || crcCheck[1] != resp[respLen - 1]) {
        Serial.println(F("    -> CRC mismatch on response - bus noise or missing pull-ups."));
        return;
    }

    Serial.println(F("    -> Info command succeeded. Silicon revision bytes:"));
    Serial.print("       ");
    printHex(&resp[1], respLen - 3);
    Serial.println(F("       (A real ATECC608A/508A reports revision like 00 00 60 02 / 00 00 50 00 -"));
    Serial.println(F("        compare against your datasheet's expected value.)"));
}

void setup() {
    Serial.begin(115200);
    uint32_t t0 = millis();
    while (!Serial && millis() - t0 < 3000) { delay(10); }

    Serial.println(F("\n\n==================================="));
    Serial.println(F(" ATECC508A/608A I2C diagnostic tool"));
    Serial.println(F("===================================\n"));
    Serial.printf("SDA = GPIO%d, SCL = GPIO%d\n", SDA_PIN, SCL_PIN);

    Wire.begin(SDA_PIN, SCL_PIN);
    Wire.setClock(100000);  // start conservative; ATECC supports up to 1MHz but
                             // start slow to rule out timing issues first
    Wire.setTimeOut(50);    // esp32-arduino Wire can hang forever on a stuck/floating
                             // bus (no pull-ups, unresponsive device) without this

    scanBus();

    Serial.println(F("\n=== Step 2: ATECC wake sequence ==="));
    uint8_t workingAddr = 0;
    for (uint8_t addr : CANDIDATE_ADDRS) {
        if (wakeAndCheck(addr)) {
            workingAddr = addr;
            break;
        }
    }

    if (workingAddr == 0) {
        Serial.println(F("\nNo candidate address produced a valid wake response."));
        Serial.println(F("Stopping here - fix wiring/power/address before re-running."));
        Serial.println(F("\nIf you know the chip's actual I2C address (it may have been"));
        Serial.println(F("reconfigured during provisioning), add it to CANDIDATE_ADDRS in"));
        Serial.println(F("this file and re-flash."));
        return;
    }

    Serial.println(F("\n=== Step 3: Info command ==="));
    sendInfoCommand(workingAddr);

    Serial.println(F("\nDone. Loop will re-run the wake+Info check every 5s so you can"));
    Serial.println(F("wiggle wires / check for intermittent faults."));
}

void loop() {
    delay(5000);
    Serial.println(F("\n--- re-running wake + Info ---"));
    for (uint8_t addr : CANDIDATE_ADDRS) {
        if (wakeAndCheck(addr)) {
            sendInfoCommand(addr);
            break;
        }
    }
}
