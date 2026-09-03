#ifndef GLOBALS_H
#define GLOBALS_H

#include <Arduino.h>
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>
#include <freertos/queue.h>

#define USE_FINGERPRINT_SIMULATOR 0
#define SIMULATOR_BUTTON_PIN 4

enum SystemState {
    STATE_READY,
    STATE_AWAITING_CREATE_WEBSITE,
    STATE_AWAITING_CREATE_LOGIN,
    STATE_AWAITING_AUTOGEN_CHOICE,
    STATE_AWAITING_CREATE_VAL,
    STATE_AWAITING_GET_WEBSITE,
    STATE_AWAITING_GET_LOGIN,
    STATE_AWAITING_DELETE_WEBSITE,
    STATE_AWAITING_DELETE_LOGIN,
    STATE_AWAITING_FINGERPRINT,
    STATE_AWAITING_FIDO_GET_NAME,
    STATE_AWAITING_FIDO_DELETE_NAME,
    STATE_AWAITING_TOTP_NAME,
    STATE_AWAITING_TOTP_SECRET,
    STATE_AWAITING_TOTP_GET,
    STATE_AWAITING_TOTP_DELETE_NAME,
    STATE_AWAITING_CRYPTO_ALG
};

struct CryptoRequest {
    uint32_t channel;
    uint8_t cmd;
    uint16_t len;
    uint8_t data[1024];
};

extern SystemState currentCommandState;
extern String pendingWebsite;
extern String pendingLogin;
extern bool authenticated;
extern String pendingPasswordToTransmit;

extern SemaphoreHandle_t displayMutex;
extern SemaphoreHandle_t fingerprintMutex;
extern SemaphoreHandle_t storageMutex;
extern QueueHandle_t cryptoQueue;

extern int defaultCryptoAlg;
extern uint16_t lastConfidenceScore;

#endif