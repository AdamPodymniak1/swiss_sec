#pragma once
#include <Arduino.h>

bool backupExport(const String &passphrase, String &errorOut);

bool backupImportBegin(uint32_t totalHexLen, const String &expectedSha256Hex, String &errorOut);
bool backupImportChunk(const String &hexData, String &errorOut);
bool backupImportCommit(const String &passphrase, bool overwrite, String &errorOut);
void backupImportAbort();