#include "Globals.h"

SystemState currentCommandState = STATE_READY;
String pendingName = "";
bool authenticated = false;
String pendingPasswordToTransmit = "";