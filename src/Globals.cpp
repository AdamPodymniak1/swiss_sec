#include "Globals.h"

SystemState currentCommandState = STATE_READY;
String pendingName = "";
bool authenticated = false;
String pendingPasswordToTransmit = "";

SemaphoreHandle_t displayMutex = NULL;
SemaphoreHandle_t fingerprintMutex = NULL;
SemaphoreHandle_t storageMutex = NULL;

QueueHandle_t cryptoQueue = NULL;

int defaultCryptoAlg = -7;