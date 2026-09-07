#ifdef ALLOW_ATTESTATION_PROVISIONING_CMD

#include <Arduino.h>

bool eraseAttestationProvisioning();
bool saveAttestationPrivateKey(const uint8_t privKey[32]);
bool saveAttestationCertChain(const uint8_t* buf, size_t len);
bool isAttestationProvisioned();

static int hexNibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static bool hexDecode(const String &src, uint8_t *dst, size_t len) {
    if ((size_t)src.length() != len * 2) return false;
    for (size_t i = 0; i < len; i++) {
        int hi = hexNibble(src[i * 2]);
        int lo = hexNibble(src[i * 2 + 1]);
        if (hi < 0 || lo < 0) return false;
        dst[i] = (uint8_t)((hi << 4) | lo);
    }
    return true;
}

bool provisionAttestationFromHex(const String &privHex, const String &certHex, String &errorOut) {
    if (privHex.length() != 64) {
        errorOut = "BAD_PRIVKEY_LENGTH";
        return false;
    }

    uint8_t privKey[32];
    if (!hexDecode(privHex, privKey, 32)) {
        errorOut = "BAD_PRIVKEY_HEX";
        return false;
    }

    size_t certLen = certHex.length() / 2;
    static const size_t MAX_CERT_LEN = 2000;
    if (certHex.length() % 2 != 0 || certLen == 0 || certLen > MAX_CERT_LEN) {
        memset(privKey, 0, sizeof(privKey));
        errorOut = "BAD_CERT_LENGTH";
        return false;
    }

    uint8_t *certDer = (uint8_t *)malloc(certLen);
    if (!certDer || !hexDecode(certHex, certDer, certLen)) {
        memset(privKey, 0, sizeof(privKey));
        if (certDer) free(certDer);
        errorOut = "BAD_CERT_HEX";
        return false;
    }

    size_t chainLen = 3 + certLen;
    uint8_t *chainBlob = (uint8_t *)malloc(chainLen);
    if (!chainBlob) {
        memset(privKey, 0, sizeof(privKey));
        free(certDer);
        errorOut = "OOM";
        return false;
    }
    chainBlob[0] = 1;
    chainBlob[1] = (uint8_t)((certLen >> 8) & 0xFF);
    chainBlob[2] = (uint8_t)(certLen & 0xFF);
    memcpy(chainBlob + 3, certDer, certLen);
    free(certDer);

    eraseAttestationProvisioning();
    bool keyOk = saveAttestationPrivateKey(privKey);
    bool chainOk = saveAttestationCertChain(chainBlob, chainLen);

    memset(privKey, 0, sizeof(privKey));
    memset(chainBlob, 0, chainLen);
    free(chainBlob);

    if (keyOk && chainOk && isAttestationProvisioned()) {
        return true;
    }
    errorOut = "NVS_WRITE";
    return false;
}

#endif