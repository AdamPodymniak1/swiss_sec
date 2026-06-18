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

const uint8_t PUBLIC_KEY[65] = {
    0x04, 0x59, 0x96, 0x76, 0xf7, 0x89, 0x00, 0x9b, 0x84, 0xbf, 0xb8, 0xa3, 0x12, 0x6d, 0x55, 0x76, 
    0x88, 0x83, 0x14, 0xde, 0x9d, 0xe2, 0x12, 0xbd, 0x18, 0xa8, 0xc6, 0x1e, 0x8f, 0x8d, 0x13, 0x73, 
    0xc4, 0x41, 0xd8, 0x8c, 0xd4, 0xb1, 0xbf, 0xe1, 0x0e, 0x27, 0x78, 0x42, 0xd8, 0x79, 0x78, 0x5f, 
    0x3c, 0x9b, 0x9c, 0x65, 0x0e, 0xd4, 0xb0, 0xe3, 0xeb, 0xa6, 0x4f, 0xbb, 0xd9, 0x7a, 0x16, 0x40, 0xd6
};

const uint8_t KEY_HANDLE[32] = { 
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20 
};

const uint8_t DUMMY_CERT[] = { 0x30, 0x00 }; 

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

    int ret = mbedtls_ecp_read_key(MBEDTLS_ECP_DP_SECP256R1, &ctx, PRIVATE_KEY, 32);

    size_t sig_len = 0;
    mbedtls_ecdsa_write_signature(&ctx, MBEDTLS_MD_SHA256, hash, 32, 
                                  sig_out, 128, &sig_len, 
                                  mbedtls_ctr_drbg_random, &ctr_drbg);

    mbedtls_ecdsa_free(&ctx);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);

    return sig_len;
}

class FIDO2Device : public USBHIDDevice {
public:
    uint32_t channel_id = 0xFFFFFFFF;
    
    uint8_t msg_buf[1024];
    uint16_t expected_len = 0;
    uint16_t current_len = 0;
    uint8_t current_cmd = 0;

    volatile bool has_pending_u2f_msg = false;
    uint8_t u2f_msg_buf[1024];
    uint32_t pending_req_channel = 0;

    FIDO2Device() { HID.addDevice(this, sizeof(fido_report_descriptor)); }
    void begin() { HID.begin(); }
    
    uint16_t _onGetDescriptor(uint8_t* buffer) {
        memcpy(buffer, fido_report_descriptor, sizeof(fido_report_descriptor));
        return sizeof(fido_report_descriptor);
    }

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
                uint8_t response[64] = {0};
                memcpy(&response[0], msg_buf, 8);
                channel_id = 0x01020304;
                response[8] = 0x01; response[9] = 0x02; response[10] = 0x03; response[11] = 0x04;
                response[12] = 0x02;
                response[13] = 0x01;
                send_ctaphid_response(req_channel, 0x86, response, 17);
            }
            else if (current_cmd == 0x90 && req_channel == channel_id) {
                uint8_t err_resp[1] = { 0x01 };
                send_ctaphid_response(channel_id, 0xBF, err_resp, 1);
            }
            else if (current_cmd == 0x83 && req_channel == channel_id) {
                memcpy(u2f_msg_buf, msg_buf, current_len);
                pending_req_channel = req_channel;
                has_pending_u2f_msg = true;
            }
            
            expected_len = 0;
            current_len = 0;
        }
    }
};

FIDO2Device fidoKey;

void setup() {
    fidoKey.begin();
    USB.begin();
}

void loop() {
    if (fidoKey.has_pending_u2f_msg) {
        uint8_t u2f_ins = fidoKey.u2f_msg_buf[1]; 
        
        if (u2f_ins == 0x01) {
            
            const uint8_t* challenge = &fidoKey.u2f_msg_buf[7];
            const uint8_t* app_id = &fidoKey.u2f_msg_buf[39];
            
            uint8_t to_sign[162] = {0};
            to_sign[0] = 0x00;
            memcpy(&to_sign[1], app_id, 32);
            memcpy(&to_sign[33], challenge, 32);
            memcpy(&to_sign[65], KEY_HANDLE, 32);
            memcpy(&to_sign[97], PUBLIC_KEY, 65);

            uint8_t signature[75] = {0};
            size_t sig_len = sign_data(to_sign, 162, signature);

            uint8_t resp[300] = {0};
            size_t r_idx = 0;
            resp[r_idx++] = 0x05; 
            memcpy(&resp[r_idx], PUBLIC_KEY, 65); r_idx += 65;
            resp[r_idx++] = 32;   
            memcpy(&resp[r_idx], KEY_HANDLE, 32); r_idx += 32;
            memcpy(&resp[r_idx], DUMMY_CERT, sizeof(DUMMY_CERT)); r_idx += sizeof(DUMMY_CERT);
            memcpy(&resp[r_idx], signature, sig_len); r_idx += sig_len;
            
            resp[r_idx++] = 0x90; 
            resp[r_idx++] = 0x00;

            send_ctaphid_response(fidoKey.channel_id, 0x83, resp, r_idx);
        } 
        else if (u2f_ins == 0x02) {
            
            uint8_t control_byte = fidoKey.u2f_msg_buf[2]; 
            
            if (control_byte == 0x07) {
                 uint8_t resp[2] = {0x69, 0x85}; 
                 send_ctaphid_response(fidoKey.channel_id, 0x83, resp, 2);
            } 
            else if (control_byte == 0x03 || control_byte == 0x08) {
                
                const uint8_t* challenge = &fidoKey.u2f_msg_buf[7];
                const uint8_t* app_id = &fidoKey.u2f_msg_buf[39];

                uint8_t user_presence = 0x01;
                uint8_t counter[4] = {0x00, 0x00, 0x00, 0x01};

                uint8_t to_sign[69] = {0};
                memcpy(&to_sign[0], app_id, 32);
                to_sign[32] = user_presence;
                memcpy(&to_sign[33], counter, 4);
                memcpy(&to_sign[37], challenge, 32);

                uint8_t signature[75] = {0};
                size_t sig_len = sign_data(to_sign, 69, signature);

                uint8_t resp[100] = {0};
                size_t r_idx = 0;
                resp[r_idx++] = user_presence;
                memcpy(&resp[r_idx], counter, 4); r_idx += 4;
                memcpy(&resp[r_idx], signature, sig_len); r_idx += sig_len;
                
                resp[r_idx++] = 0x90; 
                resp[r_idx++] = 0x00;

                send_ctaphid_response(fidoKey.channel_id, 0x83, resp, r_idx);
            }
        }
        
        fidoKey.has_pending_u2f_msg = false;
    }

    delay(10);
}