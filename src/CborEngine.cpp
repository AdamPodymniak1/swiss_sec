#include "CborEngine.h"

// Encodes definite-length CBOR primitives used in CTAP2 request and response maps.
bool CborEncoder::writeUnsignedInt(uint64_t val) {
    if (offset >= capacity) return false;

    if (val < 24) {
        buffer[offset++] = (0 << 5) | val;
    } else if (val <= 0xFF) {
        if (offset + 1 >= capacity) return false;
        buffer[offset++] = (0 << 5) | 24;
        buffer[offset++] = (uint8_t)val;
    } else if (val <= 0xFFFF) {
        if (offset + 2 >= capacity) return false;
        buffer[offset++] = (0 << 5) | 25;
        buffer[offset++] = (val >> 8) & 0xFF;
        buffer[offset++] = val & 0xFF;
    } else if (val <= 0xFFFFFFFF) {
        if (offset + 4 >= capacity) return false;
        buffer[offset++] = (0 << 5) | 26;
        buffer[offset++] = (val >> 24) & 0xFF;
        buffer[offset++] = (val >> 16) & 0xFF;
        buffer[offset++] = (val >> 8) & 0xFF;
        buffer[offset++] = val & 0xFF;
    } else {
        if (offset + 8 >= capacity) return false;
        buffer[offset++] = (0 << 5) | 27;
        buffer[offset++] = (val >> 56) & 0xFF;
        buffer[offset++] = (val >> 48) & 0xFF;
        buffer[offset++] = (val >> 40) & 0xFF;
        buffer[offset++] = (val >> 32) & 0xFF;
        buffer[offset++] = (val >> 24) & 0xFF;
        buffer[offset++] = (val >> 16) & 0xFF;
        buffer[offset++] = (val >> 8) & 0xFF;
        buffer[offset++] = val & 0xFF;
    }
    return true;
}

bool CborEncoder::writeMapHeader(size_t elements) {
    if (offset >= capacity) return false;

    if (elements < 24) {
        buffer[offset++] = (5 << 5) | (elements & 0x1F);
        return true;
    } 
    else if (elements <= 0xFF) {
        if (offset + 1 >= capacity) return false;
        buffer[offset++] = (5 << 5) | 24;
        buffer[offset++] = (uint8_t)elements;
        return true;
    } 
    else if (elements <= 0xFFFF) {
        if (offset + 2 >= capacity) return false;
        buffer[offset++] = (5 << 5) | 25;
        buffer[offset++] = (elements >> 8) & 0xFF;
        buffer[offset++] = elements & 0xFF;
        return true;
    }

    return false;
}

bool CborEncoder::writeByteString(const uint8_t *data, size_t len) {
    if (offset + len + 3 >= capacity) return false;

    if (len < 24) {
        buffer[offset++] = (2 << 5) | (len & 0x1F);
    } 
    else if (len <= 0xFF) {
        buffer[offset++] = (2 << 5) | 24;
        buffer[offset++] = (uint8_t)len;
    } 
    else if (len <= 0xFFFF) {
        buffer[offset++] = (2 << 5) | 25;
        buffer[offset++] = (len >> 8) & 0xFF;
        buffer[offset++] = len & 0xFF;
    } 
    else {
        return false;
    }

    memcpy(&buffer[offset], data, len);
    offset += len;
    return true;
}

bool CborEncoder::writeTextString(const char *text) {
    size_t len = strlen(text);
    if (offset + 1 + len + 2 >= capacity) return false;

    if (len < 24) {
        buffer[offset++] = (3 << 5) | (len & 0x1F);
    } 
    else if (len <= 0xFF) {
        buffer[offset++] = (3 << 5) | 24;
        buffer[offset++] = (uint8_t)len;
    } 
    else {
        return false; 
    }

    memcpy(&buffer[offset], text, len);
    offset += len;
    return true;
}

// Parser methods revert to the saved offset when a field shape does not match.
bool CborParser::readTypeAndValue(uint8_t &majorType, uint64_t &value) {
    if (offset >= length) return false;

    uint8_t initialByte = buffer[offset++];
    majorType = (initialByte >> 5) & 0x07;
    uint8_t additionalInfo = initialByte & 0x1F;

    if (additionalInfo < 24) {
        value = additionalInfo;
        return true;
    } else if (additionalInfo == 24) {
        if (offset >= length) return false;
        value = buffer[offset++];
        return true;
    } else if (additionalInfo == 25) {
        if (offset + 1 >= length) return false;
        value = ((uint64_t)buffer[offset] << 8) | buffer[offset + 1];
        offset += 2;
        return true;
    } else if (additionalInfo == 26) { 
        if (offset + 3 >= length) return false;
        value = ((uint64_t)buffer[offset] << 24) | ((uint64_t)buffer[offset + 1] << 16) | 
                ((uint64_t)buffer[offset + 2] << 8) | buffer[offset + 3];
        offset += 4;
        return true;
    } else if (additionalInfo == 27) { 
        if (offset + 7 >= length) return false;
        value = 0;
        for (int i = 0; i < 8; i++) {
            value = (value << 8) | buffer[offset++];
        }
        return true;
    } else if (additionalInfo == 0x1F) { 
        value = 0xFFFFFFFFFFFFFFFFULL; 
        return true;
    }
    return false;
}

bool CborParser::readByteString(uint8_t *destBuffer, size_t maxLen, size_t &actualLen) {
    uint8_t majorType;
    uint64_t strLen;
    size_t savedOffset = offset;

    if (!readTypeAndValue(majorType, strLen) || majorType != 2) {
        offset = savedOffset;
        return false;
    }

    if (strLen > maxLen || offset + strLen > length) {
        offset = savedOffset;
        return false;
    }

    memcpy(destBuffer, &buffer[offset], strLen);
    actualLen = strLen;
    offset += strLen;
    return true;
}

bool CborParser::readTextString(char *destBuffer, size_t maxLen) {
    uint8_t majorType;
    uint64_t strLen;
    size_t savedOffset = offset;

    if (!readTypeAndValue(majorType, strLen) || majorType != 3) {
        offset = savedOffset;
        return false;
    }

    if (strLen >= maxLen || offset + strLen > length) {
        offset = savedOffset;
        return false;
    }

    memcpy(destBuffer, &buffer[offset], strLen);
    destBuffer[strLen] = '\0'; 
    offset += strLen;
    return true;
}

// Unknown values are skipped recursively to tolerate optional browser-provided fields.
bool CborParser::skipValue() {
    if (offset >= length) return false;

    if (buffer[offset] == 0xFF) {
        offset++;
        return true;
    }

    uint8_t majorType;
    uint64_t value;
    if (!readTypeAndValue(majorType, value)) return false;

    switch (majorType) {
        case 0: 
        case 1: 
        case 7: 
            return true; 
        case 2: 
        case 3: 
            if (value == 0xFFFFFFFFFFFFFFFFULL) { 
                while (offset < length && buffer[offset] != 0xFF) {
                    if (!skipValue()) return false;
                }
                if (offset >= length) return false;
                offset++; 
                return true;
            }
            if (offset + value > length) return false;
            offset += value;
            return true;
        case 4: 
            if (value == 0xFFFFFFFFFFFFFFFFULL) { 
                while (offset < length && buffer[offset] != 0xFF) {
                    if (!skipValue()) return false;
                }
                if (offset >= length) return false;
                offset++; 
                return true;
            }
            for (uint64_t i = 0; i < value; i++) {
                if (!skipValue()) return false;
            }
            return true;
        case 5: 
            if (value == 0xFFFFFFFFFFFFFFFFULL) { 
                while (offset < length && buffer[offset] != 0xFF) {
                    if (!skipValue()) return false; 
                    if (!skipValue()) return false; 
                }
                if (offset >= length) return false;
                offset++; 
                return true;
            }
            for (uint64_t i = 0; i < value * 2; i++) {
                if (!skipValue()) return false;
            }
            return true;
        default:
            return false;
    }
}

bool CborEncoder::writeArrayHeader(size_t elements) {
    if (offset >= capacity) return false;

    if (elements < 24) {
        buffer[offset++] = (4 << 5) | elements;
        return true;
    } else if (elements <= 0xFF) {
        if (offset + 1 >= capacity) return false;
        buffer[offset++] = (4 << 5) | 24;
        buffer[offset++] = (uint8_t)elements;
        return true;
    }

    return false;
}

bool CborEncoder::writeBoolean(bool value) {
    if (offset >= capacity) return false;

    buffer[offset++] = (7 << 5) | (value ? 21 : 20);
    return true;
}

size_t CborEncoder::getOffset() const {
    return offset;
}

bool CborEncoder::writeNegativeInt(int64_t val) {
    if (val >= 0) return false;

    uint64_t uval = -1 - val;

    if (offset >= capacity) return false;

    if (uval < 24) {
        buffer[offset++] = (1 << 5) | uval;
    } 
    else if (uval <= 0xFF) {
        if (offset + 1 >= capacity) return false; 
        buffer[offset++] = (1 << 5) | 24;
        buffer[offset++] = (uint8_t)uval;
    } 
    else if (uval <= 0xFFFF) {
        if (offset + 2 >= capacity) return false; 
        buffer[offset++] = (1 << 5) | 25;
        buffer[offset++] = (uval >> 8) & 0xFF;
        buffer[offset++] = uval & 0xFF;
    } 
    else if (uval <= 0xFFFFFFFF) {
        if (offset + 4 >= capacity) return false; 
        buffer[offset++] = (1 << 5) | 26;
        buffer[offset++] = (uval >> 24) & 0xFF;
        buffer[offset++] = (uval >> 16) & 0xFF;
        buffer[offset++] = (uval >> 8) & 0xFF;
        buffer[offset++] = uval & 0xFF;
    }
    else {
        if (offset + 8 >= capacity) return false; 
        buffer[offset++] = (1 << 5) | 27;
        buffer[offset++] = (uval >> 56) & 0xFF;
        buffer[offset++] = (uval >> 48) & 0xFF;
        buffer[offset++] = (uval >> 40) & 0xFF;
        buffer[offset++] = (uval >> 32) & 0xFF;
        buffer[offset++] = (uval >> 24) & 0xFF;
        buffer[offset++] = (uval >> 16) & 0xFF;
        buffer[offset++] = (uval >> 8) & 0xFF;
        buffer[offset++] = uval & 0xFF;
    }

    return true;
}

bool CborEncoder::writeNull() {
    if (offset >= capacity) return false;

    buffer[offset++] = (7 << 5) | 22;
    return true;
}
