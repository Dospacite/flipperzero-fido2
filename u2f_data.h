#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <furi.h>

#define U2F_RESIDENT_MAX_CREDENTIALS 8
#define U2F_RESIDENT_RP_ID_MAX       253
#define U2F_RESIDENT_USER_ID_MAX     64
#define U2F_RESIDENT_CREDENTIAL_ID_SIZE 64

typedef struct {
    uint8_t rp_id_len;
    uint8_t user_id_len;
    uint8_t rp_id[U2F_RESIDENT_RP_ID_MAX];
    uint8_t user_id[U2F_RESIDENT_USER_ID_MAX];
    uint8_t credential_id[U2F_RESIDENT_CREDENTIAL_ID_SIZE];
} FURI_PACKED U2fResidentCredential;

typedef struct {
    uint32_t magic;
    uint8_t count;
    U2fResidentCredential credential[U2F_RESIDENT_MAX_CREDENTIALS];
} FURI_PACKED U2fResidentCredentials;

bool u2f_data_check(bool cert_only);

bool u2f_data_cert_check(void);

uint32_t u2f_data_cert_load(uint8_t* cert);

bool u2f_data_cert_key_load(uint8_t* cert_key);

bool u2f_data_key_load(uint8_t* device_key);

bool u2f_data_key_generate(uint8_t* device_key);

bool u2f_data_cnt_read(uint32_t* cnt);

bool u2f_data_cnt_write(uint32_t cnt);

/** Load/save discoverable WebAuthn credentials.  A missing store is empty. */
bool u2f_data_resident_load(U2fResidentCredentials* credentials);
bool u2f_data_resident_save(const U2fResidentCredentials* credentials);

#ifdef __cplusplus
}
#endif
