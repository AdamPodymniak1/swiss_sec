#ifndef GLOBALS_H
#define GLOBALS_H

#include <Arduino.h>
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>
#include <freertos/queue.h>

#define USE_FINGERPRINT_SIMULATOR 1
#define SIMULATOR_BUTTON_PIN 4

// CLI states model prompts that span more than one serial command.
enum SystemState {
    STATE_READY,
    STATE_AWAITING_CREATE_NAME,
    STATE_AWAITING_AUTOGEN_CHOICE,
    STATE_AWAITING_CREATE_VAL,
    STATE_AWAITING_GET_NAME,
    STATE_AWAITING_DELETE_NAME,
    STATE_AWAITING_FINGERPRINT,
    STATE_AWAITING_FIDO_GET_NAME,
    STATE_AWAITING_FIDO_DELETE_NAME,
    STATE_AWAITING_TOTP_NAME,
    STATE_AWAITING_TOTP_SECRET,
    STATE_AWAITING_TOTP_GET
};

struct CryptoRequest {
    uint32_t channel;
    uint8_t cmd;
    uint16_t len;
    uint8_t data[1024];
};

extern SystemState currentCommandState;
extern String pendingName;
extern bool authenticated;
extern String pendingPasswordToTransmit;

extern SemaphoreHandle_t displayMutex;
extern SemaphoreHandle_t fingerprintMutex;
extern SemaphoreHandle_t storageMutex;

extern QueueHandle_t cryptoQueue;

#endif
