#pragma once

#include <Arduino.h>
#include <esp_system.h>
#include "USBHID.h"
#include "CborEngine.h"
#include <EEPROM.h>
#include "mbedtls/md.h"

#define CTAPHID_PING  0x81
#define CTAPHID_MSG   0x83
#define CTAPHID_INIT  0x86
#define CTAPHID_WINK  0x88
#define CTAPHID_CBOR  0x90
#define CTAPHID_CANCEL 0x91
#define CTAPHID_ERROR 0xBF
#define CTAPHID_KEEPALIVE 0xBB

#define SIGN_COUNT_ADDR 0 

uint32_t loadPersistedSignCount();
void savePersistedSignCount(uint32_t count);
bool fidoVerifyFingerprint();

extern const uint8_t fido_report_descriptor[34];

class FIDO2HIDDevice : public USBHIDDevice {
private:
    USBHID hid;

    uint32_t activeChannelID = 0;
    uint8_t* ctapBuffer = nullptr;
    uint16_t ctapBufferCapacity = 0;
    uint16_t ctapExpectedLen = 0;
    uint16_t ctapReceivedLen = 0;
    uint8_t  ctapExpectedSeq = 0;
    uint8_t  ctapCurrentCmd = 0;
    uint32_t ctapCurrentChannel = 0;
    unsigned long lastPacketTime = 0;

public:
    volatile bool hasPendingCommand = false;
    uint32_t pendingChannel = 0;
    uint8_t pendingCmd = 0;
    uint8_t* pendingData = nullptr;
    uint16_t pendingLen = 0;
    uint16_t pendingDataCapacity = 0;

    FIDO2HIDDevice();
    ~FIDO2HIDDevice();

    void begin();
    uint16_t _onGetDescriptor(uint8_t* dst) override;
    void sendCtapResponse(uint32_t channel, uint8_t cmd, const uint8_t* data, uint16_t len);
    void processCtapCommand(uint32_t channel, uint8_t cmd, uint8_t* data, uint16_t len);
    void processCborCommand(uint32_t channel, uint8_t* data, uint16_t len);
    void poll();
    void _onOutput(uint8_t report_id, const uint8_t* buffer, uint16_t len) override;
    void processU2fCommand(uint32_t channel, uint8_t* data, uint16_t len);
};

extern FIDO2HIDDevice FidoHID;