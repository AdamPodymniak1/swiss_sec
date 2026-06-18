#include <Arduino.h>
#include "USB.h"
#include "USBHID.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/sha256.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

static const uint8_t fido_report_descriptor[] = {
    0x06, 0xD0, 0xF1, 0x09, 0x01, 0xA1, 0x01, 0x09, 0x20, 0x15, 0x00, 
    0x26, 0xFF, 0x00, 0x75, 0x08, 0x95, 0x40, 0x81, 0x02, 0x09, 0x21, 
    0x15, 0x00, 0x26, 0xFF, 0x00, 0x75, 0x08, 0x95, 0x40, 0x91, 0x02, 0xC0
};

USBHID HID;

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
    mbedtls_sha256(data, data_len, hash, 0);

    mbedtls_ecdsa_context ctx;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    mbedtls_ecdsa_init(&ctx);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, nullptr, 0);

    mbedtls_ecp_read_key(MBEDTLS_ECP_DP_SECP256R1, &ctx, PRIVATE_KEY, 32);

    size_t sig_len = 0;
    mbedtls_ecdsa_write_signature(&ctx, MBEDTLS_MD_SHA256, hash, 32, sig_out, 128, &sig_len, mbedtls_ctr_drbg_random, &ctr_drbg);

    mbedtls_ecdsa_free(&ctx);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);

    return sig_len;
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
                    mbedtls_sha256(&buf[str_start], str_len, out_hash, 0);
                    return true; 
                }
            }
        }
    } else if (cmd == 0x02) {
        if (len > 3 && buf[2] == 0x01) {
            uint16_t str_start, str_len;
            if (get_cbor_string(buf, 3, len, &str_start, &str_len)) {
                mbedtls_sha256(&buf[str_start], str_len, out_hash, 0);
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

class FIDO2Device : public USBHIDDevice {
public:
    uint32_t channel_id = 0xFFFFFFFF;
    uint8_t msg_buf[2048];
    uint16_t expected_len = 0;
    uint16_t current_len = 0;
    uint8_t current_cmd = 0;

    volatile bool has_pending_ctap2_msg = false;
    uint8_t ctap2_msg_buf[2048];
    uint16_t ctap2_msg_len = 0;

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
                response[12] = 0x02;              
                response[13] = 0x01;              
                response[14] = 0x04;
                send_ctaphid_response(req_channel, 0x86, response, 17);
            }
            else if (current_cmd == 0x90 && req_channel == channel_id) {
                memcpy(ctap2_msg_buf, msg_buf, current_len);
                ctap2_msg_len = current_len;
                has_pending_ctap2_msg = true;
            }
            expected_len = 0; current_len = 0;
        }
    }
};

FIDO2Device fidoKey;

void setup() {
    fidoKey.begin();
    USB.begin();
}

void loop() {
    if (fidoKey.has_pending_ctap2_msg) {
        uint8_t ctap2_cmd = fidoKey.ctap2_msg_buf[0]; 
        
        if (ctap2_cmd == 0x04) { 
            const uint8_t getInfo_cbor[] = {
                0x00, 
                0xA2, 
                0x01, 0x81, 0x68, 0x46, 0x49, 0x44, 0x4F, 0x5F, 0x32, 0x5F, 0x30, 
                0x03, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 
            };
            send_ctaphid_response(fidoKey.channel_id, 0x90, getInfo_cbor, sizeof(getInfo_cbor));
        } 
        else if (ctap2_cmd == 0x01) {
            uint8_t dynamic_rp_id_hash[32] = {0};
            
            if(!extract_rp_id_hash(0x01, fidoKey.ctap2_msg_buf, fidoKey.ctap2_msg_len, dynamic_rp_id_hash)) {
                uint8_t err_resp[1] = { 0x01 }; 
                send_ctaphid_response(fidoKey.channel_id, 0x90, err_resp, 1);
            } else {
                uint8_t authData[256] = {0}; 
                uint16_t ad_idx = 0;
                
                memcpy(&authData[ad_idx], dynamic_rp_id_hash, 32); ad_idx += 32; 
                authData[ad_idx++] = 0x41;                               
                
                uint8_t sc_bytes[4] = {0x00, 0x00, 0x00, 0x01};
                memcpy(&authData[ad_idx], sc_bytes, 4); ad_idx += 4;   
                
                uint8_t aaguid[16] = {0}; 
                memcpy(&authData[ad_idx], aaguid, 16); ad_idx += 16;     
                
                authData[ad_idx++] = 0x00; authData[ad_idx++] = 0x10;    
                memcpy(&authData[ad_idx], CREDENTIAL_ID, 16); ad_idx += 16;
                
                const uint8_t cose_header[] = { 0xA5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20 };
                memcpy(&authData[ad_idx], cose_header, 10); ad_idx += 10;
                memcpy(&authData[ad_idx], PUB_X, 32); ad_idx += 32;
                const uint8_t cose_y_header[] = { 0x22, 0x58, 0x20 };
                memcpy(&authData[ad_idx], cose_y_header, 3); ad_idx += 3;
                memcpy(&authData[ad_idx], PUB_Y, 32); ad_idx += 32;

                uint8_t resp[256] = {0}; 
                uint16_t r_idx = 0;
                resp[r_idx++] = 0x00; 
                resp[r_idx++] = 0xA3; 
                resp[r_idx++] = 0x01; resp[r_idx++] = 0x64; resp[r_idx++] = 'n'; resp[r_idx++] = 'o'; resp[r_idx++] = 'n'; resp[r_idx++] = 'e'; 
                
                resp[r_idx++] = 0x02; resp[r_idx++] = 0x58; resp[r_idx++] = ad_idx; 
                memcpy(&resp[r_idx], authData, ad_idx); r_idx += ad_idx;
                
                resp[r_idx++] = 0x03; resp[r_idx++] = 0xA0; 

                send_ctaphid_response(fidoKey.channel_id, 0x90, resp, r_idx);
            }
        }
        else if (ctap2_cmd == 0x02) {
            uint8_t clientDataHash[32] = {0};
            uint8_t dynamic_rp_id_hash[32] = {0};

            if(!extract_rp_id_hash(0x02, fidoKey.ctap2_msg_buf, fidoKey.ctap2_msg_len, dynamic_rp_id_hash) || 
               !find_client_data_hash(fidoKey.ctap2_msg_buf, fidoKey.ctap2_msg_len, clientDataHash)) {
                uint8_t err_resp[1] = { 0x01 }; 
                send_ctaphid_response(fidoKey.channel_id, 0x90, err_resp, 1);
            } else {
                uint8_t authData[37] = {0};
                memcpy(&authData[0], dynamic_rp_id_hash, 32);
                authData[32] = 0x01; 
                uint8_t sc_bytes[4] = {0x00, 0x00, 0x00, 0x02};
                memcpy(&authData[33], sc_bytes, 4);

                uint8_t to_sign[69];
                memcpy(&to_sign[0], authData, 37);
                memcpy(&to_sign[37], clientDataHash, 32);

                uint8_t signature[80] = {0};
                size_t sig_len = sign_data(to_sign, 69, signature);

                uint8_t resp[256] = {0};
                uint16_t r_idx = 0;
                resp[r_idx++] = 0x00; 
                resp[r_idx++] = 0xA3; 
                
                resp[r_idx++] = 0x01; resp[r_idx++] = 0xA2;
                resp[r_idx++] = 0x62; resp[r_idx++] = 'i'; resp[r_idx++] = 'd'; resp[r_idx++] = 0x50; 
                memcpy(&resp[r_idx], CREDENTIAL_ID, 16); r_idx += 16;
                resp[r_idx++] = 0x64; resp[r_idx++] = 't'; resp[r_idx++] = 'y'; resp[r_idx++] = 'p'; resp[r_idx++] = 'e';
                resp[r_idx++] = 0x6A; memcpy(&resp[r_idx], "public-key", 10); r_idx += 10;
                
                resp[r_idx++] = 0x02; resp[r_idx++] = 0x58; resp[r_idx++] = 37;
                memcpy(&resp[r_idx], authData, 37); r_idx += 37;
                
                resp[r_idx++] = 0x03; resp[r_idx++] = 0x58; resp[r_idx++] = sig_len;
                memcpy(&resp[r_idx], signature, sig_len); r_idx += sig_len;

                send_ctaphid_response(fidoKey.channel_id, 0x90, resp, r_idx);
            }
        }
        else {
            uint8_t err_resp[1] = { 0x01 }; 
            send_ctaphid_response(fidoKey.channel_id, 0x90, err_resp, 1);
        }
        fidoKey.has_pending_ctap2_msg = false;
    }
    delay(10);
}