#include "Globals.h"

SystemState currentCommandState = STATE_READY;
String pendingWebsite = "";
String pendingLogin = "";
bool authenticated = false;
String pendingPasswordToTransmit = "";
String pendingPasswordToSave = "";

SemaphoreHandle_t displayMutex = NULL;
SemaphoreHandle_t fingerprintMutex = NULL;
SemaphoreHandle_t storageMutex = NULL;

QueueHandle_t cryptoQueue = NULL;

int defaultCryptoAlg = -7;
uint16_t lastConfidenceScore = 0;