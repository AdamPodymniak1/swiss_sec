#ifndef GLOBALS_H
#define GLOBALS_H

#include <Arduino.h>
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>

#define USE_FINGERPRINT_SIMULATOR 1
#define SIMULATOR_BUTTON_PIN 4

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

extern SystemState currentCommandState;
extern String pendingName;
extern bool authenticated;
extern String pendingPasswordToTransmit;

extern SemaphoreHandle_t displayMutex;
extern SemaphoreHandle_t fingerprintMutex;
extern SemaphoreHandle_t storageMutex;

#endif