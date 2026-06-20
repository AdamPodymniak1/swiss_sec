

#include <Arduino.h>
#include "USB.h"
#include "USBHID.h"

// --- Twoje własne biblioteki nagłówkowe ---
#include "CborEngine.h"
#include "CryptoManager.h"
#include "mbedtls/md.h"
#include "FingerprintManager.h"
#include "DisplayManager.h"
#include "Globals.h"

// =========================================================================
// KONFIGURACJA FIDO2 USB HID
// =========================================================================

static const uint8_t fido_report_descriptor[] = {
    0x06, 0xD0, 0xF1, 0x09, 0x01, 0xA1, 0x01, 0x09, 0x20, 0x15, 0x00, 
    0x26, 0xFF, 0x00, 0x75, 0x08, 0x95, 0x40, 0x81, 0x02, 0x09, 0x21, 
    0x15, 0x00, 0x26, 0xFF, 0x00, 0x75, 0x08, 0x95, 0x40, 0x91, 0x02, 0xC0
};

USBHID HID;

// Struktury do przechowywania parametrów bieżącej operacji FIDO2
struct FidoContext {
    uint8_t cmd;
    uint32_t channel;
    uint8_t clientDataHash[32];
    uint8_t rpIdHash[32];
} fidoCtx;

// Dedykowane flagi stanowe i timery
bool fido2_awaiting_finger = false;
unsigned long last_keepalive_ms = 0;
unsigned long last_finger_sample_ms = 0;
bool finger_was_on = false; // Zapobiega wielokrotnym odczytom bez używania pętli while!

// =========================================================================
// BUFOROWANY LOG DIAGNOSTYCZNY
// Otwarcie Serial Monitora w trakcie ceremonii WebAuthn powoduje re-enumerację
// złożonego urządzenia USB (CDC+HID) i odpadanie klucza FIDO2 w Windows.
// Dlatego logi trzymamy w pamięci i wypisujemy je dopiero, gdy port faktycznie
// zostanie podłączony PO zakończeniu testu - bez przeszkadzania ceremonii.
// =========================================================================
String debugLog;
bool wasSerialConnected = false;

String hexStr(const uint8_t* buf, size_t len) {
    String out;
    for (size_t i = 0; i < len; i++) {
        if (buf[i] < 0x10) out += "0";
        out += String(buf[i], HEX);
    }
    return out;
}

void dbg(const String& line) {
    debugLog += String(millis()) + " " + line + "\n";
    if (debugLog.length() > 6000) {
        debugLog.remove(0, debugLog.length() - 6000);
    }
}

void flushDebugLogIfConnected() {
    bool isConnected = (bool)Serial;
    if (isConnected && !wasSerialConnected) {
        delay(300); // dać hostowi chwilę po enumeracji CDC
        Serial.println("\n===== BUFOROWANY LOG (od ostatniego flusha) =====");
        Serial.print(debugLog);
        Serial.println("===== KONIEC LOGU =====");
        debugLog = "";
    }
    wasSerialConnected = isConnected;
}

// Klucze kryptograficzne P-256
const uint8_t PRIVATE_KEY[32] = {
    0x73, 0x58, 0x21, 0x74, 0xda, 0x8b, 0xc4, 0x44, 0x51, 0xb8, 0x36, 0x84, 0xba, 0xad, 0xcf, 0xdb, 
    0xb1, 0xd7, 0xf1, 0x65, 0x19, 0x84, 0x69, 0x93, 0x6d, 0x6e, 0xa5, 0x75, 0x9b, 0xeb, 0x4c, 0xbd
};

const uint8_t PUB_X[32] = {
    0x59, 0x96, 0x76, 0xf7, 0x89, 0x00, 0x9b, 0x84, 0xbf, 0xb8, 0xa3, 0x12, 0x6d, 0x55, 0x76, 0x88, 
    0x83, 0x14, 0xde, 0x9d, 0xe2, 0x12, 0xbd, 0x18, 0xa8, 0xc6, 0x1e, 0x8f, 0x8d, 0x13, 0x73, 0xc4
};
const uint8_t PUB_Y[32] = {
    0x41, 0xd8, 0x8c, 0xd4, 0xb1, 0xbf, 0xe1, 0x0e, 0x27, 0x78, 0x42, 0xd8, 0x79, 0x78, 0x5f, 0x3c, 
    0x9b, 0x9c, 0x65, 0x0e, 0xd4, 0xb0, 0xe3, 0xeb, 0xa6, 0x4f, 0xbb, 0xd9, 0x7a, 0x16, 0x40, 0xd6
};

const uint8_t CREDENTIAL_ID[16] = { 
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F 
};

// =========================================================================
// FUNKCJE NISKIEGO POZIOMU (USB / CBOR)
// =========================================================================

void send_ctaphid_response(uint32_t channel, uint8_t cmd, const uint8_t* data, uint16_t len) {
    uint8_t packet[64] = {0};
    uint16_t offset = 0;
    uint8_t seq = 0;

    packet[0] = (channel >> 24) & 0xFF; packet[1] = (channel >> 16) & 0xFF;
    packet[2] = (channel >> 8) & 0xFF;  packet[3] = channel & 0xFF;
    packet[4] = cmd;
    packet[5] = (len >> 8) & 0xFF;      packet[6] = len & 0xFF;

    uint16_t chunk = (len > 57) ? 57 : len;
    memcpy(&packet[7], data, chunk);
    offset += chunk;
    HID.SendReport(0, packet, 64);

    while (offset < len) {
        memset(packet, 0, 64);
        packet[0] = (channel >> 24) & 0xFF; packet[1] = (channel >> 16) & 0xFF;
        packet[2] = (channel >> 8) & 0xFF;  packet[3] = channel & 0xFF;
        packet[4] = seq++; 
        chunk = (len - offset > 59) ? 59 : (len - offset);
        memcpy(&packet[5], &data[offset], chunk);
        offset += chunk;
        HID.SendReport(0, packet, 64);
    }
}

size_t sign_data(const uint8_t* data, size_t data_len, uint8_t* sig_out) {
    uint8_t hash[32];
    mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), data, data_len, hash);
    
    size_t sig_len = 128;
    if (signECDSA_P256(PRIVATE_KEY, hash, 32, sig_out, &sig_len)) {
        return sig_len;
    }
    return 0;
}

bool get_cbor_string(const uint8_t* payload, uint16_t offset, uint16_t max_len, uint16_t* str_start, uint16_t* str_len) {
    if (offset >= max_len) return false;
    uint8_t marker = payload[offset];
    if (marker >= 0x60 && marker <= 0x77) {
        *str_len = marker - 0x60;
        *str_start = offset + 1;
        return (*str_start + *str_len <= max_len);
    } else if (marker == 0x78) {
        if (offset + 1 >= max_len) return false;
        *str_len = payload[offset + 1];
        *str_start = offset + 2;
        return (*str_start + *str_len <= max_len);
    }
    return false;
}

bool extract_rp_id_hash(uint8_t cmd, const uint8_t* buf, uint16_t len, uint8_t* out_hash) {
    if (cmd == 0x01) {
        for (uint16_t i = 1; i < len - 3; i++) {
            if (buf[i] == 0x62 && buf[i+1] == 'i' && buf[i+2] == 'd') {
                uint16_t str_start, str_len;
                if (get_cbor_string(buf, i + 3, len, &str_start, &str_len)) {
                    mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), &buf[str_start], str_len, out_hash);
                    return true; 
                }
            }
        }
    } else if (cmd == 0x02) {
        if (len > 3 && buf[2] == 0x01) {
            uint16_t str_start, str_len;
            if (get_cbor_string(buf, 3, len, &str_start, &str_len)) {
                mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), &buf[str_start], str_len, out_hash);
                return true;
            }
        }
    }
    return false;
}

bool find_client_data_hash(const uint8_t* buf, uint16_t len, uint8_t* out_hash) {
    for(uint16_t i = 0; i < len - 34; i++) {
        if(buf[i] == 0x58 && buf[i+1] == 0x20) {
            memcpy(out_hash, &buf[i+2], 32);
            return true;
        }
    }
    return false;
}

// =========================================================================
// WYSYŁANIE FINALEJ ODPOWIEDZI DO PC PO POZYTYWNEJ WERYFIKACJI PALCA
// =========================================================================

void send_get_assertion_response(uint8_t flags);

void finalize_fido2_response() {
    dbg("[FIDO2] finalize_fido2_response cmd=0x" + String(fidoCtx.cmd, HEX));
    if (fidoCtx.cmd == 0x01) {
        uint8_t authData[256] = {0}; 
        uint16_t ad_idx = 0;
        
        memcpy(&authData[ad_idx], fidoCtx.rpIdHash, 32); ad_idx += 32; 
        authData[ad_idx++] = 0x41; 
        
        uint8_t sc_bytes[4] = {0x00, 0x00, 0x00, 0x01};
        memcpy(&authData[ad_idx], sc_bytes, 4); ad_idx += 4;   
        
        uint8_t aaguid[16] = {0}; 
        memcpy(&authData[ad_idx], aaguid, 16); ad_idx += 16;     
        
        authData[ad_idx++] = 0x00; authData[ad_idx++] = 0x10;    
        memcpy(&authData[ad_idx], CREDENTIAL_ID, 16); ad_idx += 16;
        
        uint8_t coseBuf[128];
        CborEncoder cose(coseBuf, sizeof(coseBuf));
        cose.writeMapHeader(5);
        cose.writeUnsignedInt(1); cose.writeUnsignedInt(2);          
        cose.writeUnsignedInt(3); cose.writeNegativeInt(-7);         
        cose.writeNegativeInt(-1); cose.writeUnsignedInt(1);         
        cose.writeNegativeInt(-2); cose.writeByteString(PUB_X, 32);  
        cose.writeNegativeInt(-3); cose.writeByteString(PUB_Y, 32);  
        
        memcpy(&authData[ad_idx], coseBuf, cose.getOffset());
        ad_idx += cose.getOffset();

        uint8_t cborBuf[256];
        CborEncoder cbor(cborBuf, sizeof(cborBuf));
        cbor.writeMapHeader(3);
        
        cbor.writeUnsignedInt(1); 
        cbor.writeTextString("none");
        
        cbor.writeUnsignedInt(2); 
        cbor.writeByteString(authData, ad_idx);
        
        cbor.writeUnsignedInt(3); 
        cbor.writeMapHeader(0);   

        uint8_t resp[256];
        resp[0] = 0x00; 
        memcpy(&resp[1], cborBuf, cbor.getOffset());
        send_ctaphid_response(fidoCtx.channel, 0x90, resp, 1 + cbor.getOffset());
        
    } else if (fidoCtx.cmd == 0x02) {
        send_get_assertion_response(0x05); // UP=1, UV=1 - dotyk już potwierdzony
    }
}

// GetAssertion z konkretną wartością flags (UP/UV), żeby ten sam kod obsłużył
// zarówno "ciche" zapytanie (up:false -> flags 0x00, odpowiedź natychmiastowa,
// bez czekania na palec) jak i prawdziwe, potwierdzone dotykiem (flags 0x05).
void send_get_assertion_response(uint8_t flags) {
    uint8_t authData[37] = {0};
    memcpy(&authData[0], fidoCtx.rpIdHash, 32);
    authData[32] = flags;
    uint8_t sc_bytes[4] = {0x00, 0x00, 0x00, 0x02};
    memcpy(&authData[33], sc_bytes, 4);

    uint8_t to_sign[69];
    memcpy(&to_sign[0], authData, 37);
    memcpy(&to_sign[37], fidoCtx.clientDataHash, 32);

    uint8_t signature[80] = {0};
    size_t sig_len = sign_data(to_sign, 69, signature);

    dbg("[FIDO2] GetAssertion flags=0x" + String(flags, HEX) + " sig_len=" + String(sig_len));

    uint8_t cborBuf[256];
    CborEncoder cbor(cborBuf, sizeof(cborBuf));
    cbor.writeMapHeader(3);

    cbor.writeUnsignedInt(1);
    cbor.writeMapHeader(2);
    cbor.writeTextString("id");
    cbor.writeByteString(CREDENTIAL_ID, 16);
    cbor.writeTextString("type");
    cbor.writeTextString("public-key");

    cbor.writeUnsignedInt(2);
    cbor.writeByteString(authData, 37);

    cbor.writeUnsignedInt(3);
    cbor.writeByteString(signature, sig_len);

    uint8_t resp[256];
    resp[0] = 0x00;
    memcpy(&resp[1], cborBuf, cbor.getOffset());
    send_ctaphid_response(fidoCtx.channel, 0x90, resp, 1 + cbor.getOffset());
}

// =========================================================================
// KLASA URZĄDZENIA FIDO2 USB (PARSER STRUMIENIA USB)
// =========================================================================

class FIDO2Device : public USBHIDDevice {
public:
    uint32_t channel_id = 0xFFFFFFFF;
    uint8_t msg_buf[2048];
    uint16_t expected_len = 0;
    uint16_t current_len = 0;
    uint8_t current_cmd = 0;

    FIDO2Device() { HID.addDevice(this, sizeof(fido_report_descriptor)); }
    void begin() { HID.begin(); }
    uint16_t _onGetDescriptor(uint8_t* buffer) { memcpy(buffer, fido_report_descriptor, sizeof(fido_report_descriptor)); return sizeof(fido_report_descriptor); }

    void _onOutput(uint8_t report_id, const uint8_t* buffer, uint16_t len) {
        if (len < 7) return;
        uint32_t req_channel = (buffer[0] << 24) | (buffer[1] << 16) | (buffer[2] << 8) | buffer[3];

        if (buffer[4] >= 0x80) {
            current_cmd = buffer[4];
            expected_len = (buffer[5] << 8) | buffer[6];
            current_len = (len - 7 > expected_len) ? expected_len : len - 7;
            memcpy(msg_buf, &buffer[7], current_len);
        } else {
            uint16_t chunk = len - 5;
            if (current_len + chunk > expected_len) chunk = expected_len - current_len;
            memcpy(&msg_buf[current_len], &buffer[5], chunk);
            current_len += chunk;
        }

        if (current_len >= expected_len && expected_len > 0) {
            if (current_cmd == 0x86) {
                uint8_t response[17] = {0};
                memcpy(&response[0], msg_buf, 8); 
                channel_id = 0x01020304;          
                response[8] = 0x01; response[9] = 0x02; response[10] = 0x03; response[11] = 0x04;
                response[12] = 0x02; response[13] = 0x01; response[14] = 0x04;
                send_ctaphid_response(req_channel, 0x86, response, 17);
            }
            else if (current_cmd == 0x90 && req_channel == channel_id) {
                uint8_t ctap2_cmd = msg_buf[0];
                dbg("[CTAP2] cmd=0x" + String(ctap2_cmd, HEX) + " len=" + String(current_len) + " fido2_awaiting_finger=" + String(fido2_awaiting_finger));
                if (ctap2_cmd == 0x01 || ctap2_cmd == 0x02) {
                    dbg("[CTAP2] raw=" + hexStr(msg_buf, current_len));
                }

                if (ctap2_cmd == 0x04) {
                    uint8_t cborBuf[128];
                    CborEncoder cbor(cborBuf, sizeof(cborBuf));
                    cbor.writeMapHeader(3);
                    cbor.writeUnsignedInt(1);
                    cbor.writeArrayHeader(1);
                    cbor.writeTextString("FIDO_2_0");
                    cbor.writeUnsignedInt(3);
                    uint8_t empty_aaguid[16] = {0};
                    cbor.writeByteString(empty_aaguid, 16);
                    // Deklarujemy rk/up/uv - bez tego Windows traktuje urządzenie
                    // jako "nie-resident-key-capable" i przy logowaniu passkey
                    // (discoverable credential) robi dodatkową rundę
                    // discover-potwierdź, każda wymagająca dotyku.
                    cbor.writeUnsignedInt(4);
                    cbor.writeMapHeader(3);
                    cbor.writeTextString("rk");
                    cbor.writeBoolean(true);
                    cbor.writeTextString("up");
                    cbor.writeBoolean(true);
                    cbor.writeTextString("uv");
                    cbor.writeBoolean(true);

                    uint8_t resp[128];
                    resp[0] = 0x00; 
                    memcpy(&resp[1], cborBuf, cbor.getOffset());
                    send_ctaphid_response(channel_id, 0x90, resp, 1 + cbor.getOffset());
                } 
                else if (ctap2_cmd == 0x01 || ctap2_cmd == 0x02) {
                    fidoCtx.cmd = ctap2_cmd;
                    fidoCtx.channel = channel_id;
                    extract_rp_id_hash(ctap2_cmd, msg_buf, current_len, fidoCtx.rpIdHash);
                    if (ctap2_cmd == 0x02) {
                        find_client_data_hash(msg_buf, current_len, fidoCtx.clientDataHash);
                    }

                    fido2_awaiting_finger = true;
                    last_keepalive_ms = millis();
                    dbg("[FIDO2] Zadanie autoryzacji biometrycznej. Czekam na palec...");
                }
            }
            expected_len = 0; current_len = 0;
        }
    }
};

FIDO2Device fidoKey;

// =========================================================================
// SETUP
// =========================================================================

void setup() {
    Serial.begin(115200);
    
    initCrypto();
    initFingerprintSensor();
    
    fidoKey.begin();
    USB.begin();

    Serial.println("[SYS] KLUCZ FIDO2 GOTOWY DO PRACY");
}

// =========================================================================
// MAIN LOOP
// =========================================================================

void loop() {
    flushDebugLogIfConnected();

    // 1. FIDO2 Keep-Alive (wymagane przez specyfikację CTAPHID)
    if (fido2_awaiting_finger) {
        if (millis() - last_keepalive_ms > 300) {
            uint8_t status = 0x02; 
            send_ctaphid_response(fidoCtx.channel, 0xBB, &status, 1);
            last_keepalive_ms = millis();
        }
    }

    // 2. Obsługa Async dla FIDO2 (jeśli wisi w menu)
    if (currentCommandState == STATE_AWAITING_FINGERPRINT) {
        updateFingerprintAsync();
    } 
    else {
        // Główna logika odczytu z wbudowanym mechanizmem wybudzania
        if (millis() - last_finger_sample_ms > 150) {
            last_finger_sample_ms = millis();

            // POBIERANIE OBRAZU:
            // Jeśli czytnik był w uśpieniu, pierwszy getImage() często zwraca błąd 
            // komunikacji lub "IMAGE_FAIL", ale WYBUDZA sensor.
            uint8_t img = finger.getImage();

            if (img == FINGERPRINT_OK) {
                // Mamy obraz - czy to nowy dotyk?
                if (!finger_was_on) {
                    finger_was_on = true;

                    if (finger.image2Tz() == FINGERPRINT_OK) {
                        uint8_t search = finger.fingerSearch();
                        dbg("[FP] fingerSearch=0x" + String(search, HEX) + " id=" + String(finger.fingerID) + " confidence=" + String(finger.confidence) + " fido2_awaiting_finger=" + String(fido2_awaiting_finger));

                        if (search == FINGERPRINT_OK && finger.confidence > 50) {
                            // SUKCES:
                            tft.fillScreen(TFT_DARKGREEN);
                            tft.setCursor(20, 50);
                            tft.println("Weryfikacja OK!");

                            if (fido2_awaiting_finger) {
                                finalize_fido2_response();
                                fido2_awaiting_finger = false;
                            }

                            delay(800);
                            tft.fillScreen(TFT_BLACK);
                        } else {
                            // NIEPOWODZENIE (np. inny palec):
                            tft.fillScreen(TFT_RED);
                            tft.setCursor(20, 50);
                            tft.println("Zly palec!");
                            delay(800);
                            tft.fillScreen(TFT_BLACK);
                        }
                    } else {
                        // Słaby/nieudany odczyt cech (częste tuż po wybudzeniu
                        // czujnika) - zwalniamy flagę, żeby kolejny obrót loop()
                        // spróbował ponownie BEZ konieczności zdejmowania palca.
                        finger_was_on = false;
                    }
                }
            } 
            else if (img == FINGERPRINT_NOFINGER) {
                // Czysty stan - zwalniamy flagę
                finger_was_on = false;
            }
            else {
                // Czujnik bywa "uśpiony" po dłuższej bezczynności: pierwszy getImage()
                // po przyłożeniu palca budzi UART, ale zwraca błąd komunikacji, a nie
                // FINGERPRINT_OK. Czekanie na kolejny obrót loop() (150ms) jest zbyt
                // wolne - palec zwykle jest już zdjęty zanim sensor zdąży odpowiedzieć
                // poprawnie. Dlatego dobijamy odczyt od razu, w tej samej klatce.
                finger_was_on = false;

                for (uint8_t retry = 0; retry < 3 && img != FINGERPRINT_OK; retry++) {
                    delay(50);
                    img = finger.getImage();
                }

                if (img == FINGERPRINT_OK && !finger_was_on) {
                    finger_was_on = true;

                    if (finger.image2Tz() == FINGERPRINT_OK) {
                        uint8_t search = finger.fingerSearch();
                        dbg("[FP] fingerSearch=0x" + String(search, HEX) + " id=" + String(finger.fingerID) + " confidence=" + String(finger.confidence) + " fido2_awaiting_finger=" + String(fido2_awaiting_finger));

                        if (search == FINGERPRINT_OK && finger.confidence > 50) {
                            tft.fillScreen(TFT_DARKGREEN);
                            tft.setCursor(20, 50);
                            tft.println("Weryfikacja OK!");

                            if (fido2_awaiting_finger) {
                                finalize_fido2_response();
                                fido2_awaiting_finger = false;
                            }

                            delay(800);
                            tft.fillScreen(TFT_BLACK);
                        } else {
                            tft.fillScreen(TFT_RED);
                            tft.setCursor(20, 50);
                            tft.println("Zly palec!");
                            delay(800);
                            tft.fillScreen(TFT_BLACK);
                        }
                    } else {
                        finger_was_on = false;
                    }
                }
            }
        }
    }

    delay(10);
}