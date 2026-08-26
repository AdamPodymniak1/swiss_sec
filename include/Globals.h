#pragma once
#include <Arduino.h>

#define USE_FINGERPRINT_SIMULATOR 1
#define SIMULATOR_BUTTON_PIN 4

// Define clean system states for our non-blocking flow
enum SystemState {
    STATE_READY,
    STATE_AWAITING_MASTER_PIN_SETUP,
    STATE_AWAITING_CREATE_NAME,
    STATE_AWAITING_AUTOGEN_CHOICE,
    STATE_AWAITING_CREATE_VAL,
    STATE_AWAITING_GET_NAME,
    STATE_AWAITING_DELETE_NAME,
    STATE_AWAITING_FINGERPRINT,
    STATE_AWAITING_FIDO_GET_NAME,
    STATE_AWAITING_FIDO_DELETE_NAME
};

// Global State Flags (Shared across main and managers)
extern SystemState currentCommandState;
extern String pendingName;
extern bool authenticated;
extern String pendingPasswordToTransmit;