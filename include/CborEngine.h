#ifndef CBOR_ENGINE_H
#define CBOR_ENGINE_H

#include <Arduino.h>

// Small CBOR encoder/decoder tailored to the CTAP2 structures this firmware uses.
class CborEncoder {
private:
    uint8_t *buffer;
    size_t capacity;
    size_t offset;

public:
    CborEncoder(uint8_t *targetBuffer, size_t bufferCapacity) {
        buffer = targetBuffer;
        capacity = bufferCapacity;
        offset = 0;
    }

    size_t getLength() const { return offset; }
    void reset() { offset = 0; }

    bool writeUnsignedInt(uint64_t val);
    bool writeNegativeInt(int64_t val);
    bool writeByteString(const uint8_t *data, size_t len);
    bool writeTextString(const char *text);
    bool writeMapHeader(size_t elements);
    bool writeArrayHeader(size_t elements);
    bool writeBoolean(bool value);
    size_t getOffset() const;
    bool writeNull();
};

class CborParser {
public:
    const uint8_t *buffer;
    size_t length;
    size_t offset;

    CborParser(const uint8_t *srcBuffer, size_t srcLen) {
        buffer = srcBuffer;
        length = srcLen;
        offset = 0;
    }

    size_t getOffset() const { return offset; }
    bool isFinished() const { return offset >= length; }

    uint8_t peekMajorType() const {
        if (offset >= length) return 0xFF;
        return (buffer[offset] >> 5) & 0x07;
    }

    bool readTypeAndValue(uint8_t &majorType, uint64_t &value);
    bool readByteString(uint8_t *destBuffer, size_t maxLen, size_t &actualLen);
    bool readTextString(char *destBuffer, size_t maxLen);
    bool skipValue();
};

#endif
