#ifdef ALLOW_ATTESTATION_PROVISIONING_CMD

#include <Arduino.h>
#include "mbedtls/x509_crt.h"
#include "mbedtls/pk.h"
#include "mbedtls/ecp.h"
#include "mbedtls/error.h"

bool eraseAttestationProvisioning();
bool saveAttestationPrivateKey(const uint8_t privKey[32]);
bool saveAttestationCertChain(const uint8_t* buf, size_t len);
bool isAttestationProvisioned();

#if MBEDTLS_VERSION_NUMBER >= 0x03000000
    #define ATTPROV_GRP MBEDTLS_PRIVATE(grp)
    #define ATTPROV_D   MBEDTLS_PRIVATE(d)
    #define ATTPROV_Q   MBEDTLS_PRIVATE(Q)
#else
    #define ATTPROV_GRP grp
    #define ATTPROV_D   d
    #define ATTPROV_Q   Q
#endif

static int attProvRng(void *p_rng, unsigned char *output, size_t output_len) {
    (void)p_rng;
    esp_fill_random(output, output_len);
    return 0;
}

static String toHexLocal(const uint8_t* buf, size_t len) {
    String s;
    s.reserve(len * 2);
    for (size_t i = 0; i < len; i++) {
        char b[3];
        sprintf(b, "%02x", buf[i]);
        s += b;
    }
    return s;
}

static bool attestationKeyMatchesCert(const uint8_t privKey[32], const uint8_t* certDer, size_t certLen, String &reasonOut) {
    mbedtls_x509_crt crt;
    mbedtls_x509_crt_init(&crt);
    int parseRet = mbedtls_x509_crt_parse_der(&crt, certDer, certLen);
    if (parseRet != 0) {
#if defined(MBEDTLS_ERROR_C)
        char errbuf[80];
        mbedtls_strerror(parseRet, errbuf, sizeof(errbuf));
        reasonOut = "CERT_PARSE_FAILED: " + String(errbuf) + " (certLen=" + String((unsigned)certLen) + ")";
#else
        reasonOut = "CERT_PARSE_FAILED: code=-0x" + String((unsigned)(-parseRet), HEX) +
                    " (certLen=" + String((unsigned)certLen) + ")";
#endif
        mbedtls_x509_crt_free(&crt);
        return false;
    }

    mbedtls_pk_type_t certKeyType = mbedtls_pk_get_type(&crt.pk);
    if (certKeyType != MBEDTLS_PK_ECKEY && certKeyType != MBEDTLS_PK_ECDSA) {
        reasonOut = "CERT_PUBKEY_NOT_EC (pk_type=" + String((int)certKeyType) + ")";
        mbedtls_x509_crt_free(&crt);
        return false;
    }

    mbedtls_ecp_group grp;
    mbedtls_mpi d;
    mbedtls_ecp_point Q;
    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_ecp_point_init(&Q);

    uint8_t ourPub[65];
    uint8_t certPub[65];
    size_t ourPubLen = 0;
    size_t certPubLen = 0;
    bool matched = false;

    bool derivedOk =
        mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1) == 0 &&
        mbedtls_mpi_read_binary(&d, privKey, 32) == 0 &&
        mbedtls_ecp_check_privkey(&grp, &d) == 0 &&
        mbedtls_ecp_mul(&grp, &Q, &d, &grp.G, attProvRng, NULL) == 0 &&
        mbedtls_ecp_point_write_binary(&grp, &Q, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                        &ourPubLen, ourPub, sizeof(ourPub)) == 0;

    if (!derivedOk) {
        reasonOut = "PRIVKEY_DERIVE_FAILED (bad scalar?)";
    } else {
        mbedtls_ecp_keypair *certKp = mbedtls_pk_ec(crt.pk);
        bool certOk = certKp != nullptr &&
            mbedtls_ecp_point_write_binary(&certKp->ATTPROV_GRP, &certKp->ATTPROV_Q,
                                            MBEDTLS_ECP_PF_UNCOMPRESSED,
                                            &certPubLen, certPub, sizeof(certPub)) == 0;

        if (!certOk) {
            reasonOut = "CERT_PUBKEY_READ_FAILED";
        } else {
            matched = (ourPubLen == certPubLen) && (memcmp(ourPub, certPub, ourPubLen) == 0);
            if (!matched) {
                reasonOut = "POINT_MISMATCH derived=" + toHexLocal(ourPub, ourPubLen) +
                            " cert=" + toHexLocal(certPub, certPubLen);
            }
        }
    }

    mbedtls_ecp_point_free(&Q);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_group_free(&grp);
    mbedtls_x509_crt_free(&crt);
    return matched;
}

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

    String mismatchReason;
    if (!attestationKeyMatchesCert(privKey, certDer, certLen, mismatchReason)) {
        memset(privKey, 0, sizeof(privKey));
        free(certDer);
        errorOut = "KEY_CERT_MISMATCH: " + mismatchReason;
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