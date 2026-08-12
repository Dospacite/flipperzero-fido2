#include "ctap2.h"
#include "u2f_data.h"

#include <furi.h>
#include <furi_hal_random.h>

#include <mbedtls/aes.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/md.h>
#include <mbedtls/sha256.h>

#define TAG "Ctap2"

#define CTAP2_CMD_MAKE_CREDENTIAL 0x01
#define CTAP2_CMD_GET_ASSERTION   0x02
#define CTAP2_CMD_GET_INFO        0x04
#define CTAP2_CMD_CLIENT_PIN      0x06

#define CTAP2_OK                       0x00
#define CTAP2_ERR_INVALID_COMMAND      0x01
#define CTAP2_ERR_INVALID_PARAMETER    0x02
#define CTAP2_ERR_INVALID_LENGTH       0x03
#define CTAP2_ERR_CBOR_UNEXPECTED_TYPE 0x11
#define CTAP2_ERR_INVALID_CBOR         0x12
#define CTAP2_ERR_MISSING_PARAMETER    0x14
#define CTAP2_ERR_CREDENTIAL_EXCLUDED  0x19
#define CTAP2_ERR_OPERATION_DENIED     0x27
#define CTAP2_ERR_KEY_STORE_FULL       0x28
#define CTAP2_ERR_NO_CREDENTIALS       0x2E
#define CTAP2_ERR_INTEGRITY_FAILURE    0x3D
#define CTAP2_ERR_UNSUPPORTED_OPTION   0x2B

#define CTAP2_CREDENTIAL_ID_SIZE 64
#define CTAP2_MAX_RP_ID_SIZE     253

/* Stable, project-specific AAGUID. This authenticator intentionally has no attestation key. */
static const uint8_t ctap2_aaguid[16] = {
    0x8d,
    0xfe,
    0x12,
    0x6c,
    0x41,
    0xd4,
    0x4b,
    0xd4,
    0x9c,
    0x07,
    0x21,
    0x1e,
    0x6f,
    0x51,
    0x64,
    0x5a,
};

typedef struct {
    const uint8_t* ptr;
    const uint8_t* end;
    bool error;
} CborReader;

typedef struct {
    uint8_t* ptr;
    uint8_t* end;
    bool error;
} CborWriter;

typedef struct {
    const uint8_t* rp_id;
    size_t rp_id_len;
    const uint8_t* user_id;
    size_t user_id_len;
    bool hmac_secret;
    bool user_presence;
    bool resident_key;
} MakeCredentialRequest;

typedef struct {
    const uint8_t* rp_id;
    size_t rp_id_len;
    const uint8_t* client_data_hash;
    size_t client_data_hash_len;
    const uint8_t* credential_id;
    size_t credential_id_len;
    bool allow_list_present;
    uint8_t key_x[32];
    uint8_t key_y[32];
    const uint8_t* salt_enc;
    size_t salt_enc_len;
    const uint8_t* salt_auth;
    size_t salt_auth_len;
    uint64_t pin_protocol;
    bool hmac_secret;
    bool user_presence;
} GetAssertionRequest;

struct Ctap2 {
    uint8_t device_key[32];
    uint8_t key_agreement_private[32];
    uint8_t key_agreement_x[32];
    uint8_t key_agreement_y[32];
    mbedtls_ecp_group group;
    Ctap2UserPresenceRequest request_user_presence;
    Ctap2UserPresenceConsume consume_user_presence;
    Ctap2Keepalive send_keepalive;
    void* user_presence_context;
};

/* Browser CTAP transactions normally have a 30-second timeout. */
#define CTAP2_USER_PRESENCE_TIMEOUT_MS 15000
#define CTAP2_USER_PRESENCE_POLL_MS    50
#define CTAP2_KEEPALIVE_INTERVAL_MS    500

static bool ctap2_random(void* context, uint8_t* output, size_t size) {
    UNUSED(context);
    furi_hal_random_fill_buf(output, size);
    return true;
}

static int ctap2_mbedtls_random(void* context, unsigned char* output, size_t size) {
    return ctap2_random(context, output, size) ? 0 : -1;
}

static bool ctap2_ct_equal(const uint8_t* left, const uint8_t* right, size_t length) {
    uint8_t difference = 0;
    for(size_t i = 0; i < length; ++i)
        difference |= left[i] ^ right[i];
    return difference == 0;
}

static bool ctap2_wait_for_user_presence(Ctap2* ctap2, bool registration) {
    if(!ctap2->request_user_presence || !ctap2->consume_user_presence) return false;

    ctap2->request_user_presence(ctap2->user_presence_context, registration);
    for(uint32_t waited = 0; waited < CTAP2_USER_PRESENCE_TIMEOUT_MS;
        waited += CTAP2_USER_PRESENCE_POLL_MS) {
        if(ctap2->consume_user_presence(ctap2->user_presence_context)) return true;
        if(ctap2->send_keepalive && waited % CTAP2_KEEPALIVE_INTERVAL_MS == 0) {
            ctap2->send_keepalive(ctap2->user_presence_context);
        }
        furi_delay_ms(CTAP2_USER_PRESENCE_POLL_MS);
    }
    return false;
}

static bool cbor_read_head(CborReader* reader, uint8_t* major, uint64_t* value) {
    if(reader->error || reader->ptr >= reader->end) {
        reader->error = true;
        return false;
    }

    uint8_t initial = *reader->ptr++;
    *major = initial >> 5;
    uint8_t additional = initial & 0x1f;
    if(additional < 24) {
        *value = additional;
        return true;
    }

    size_t count;
    if(additional == 24)
        count = 1;
    else if(additional == 25)
        count = 2;
    else if(additional == 26)
        count = 4;
    else if(additional == 27)
        count = 8;
    else {
        reader->error = true;
        return false;
    }

    if((size_t)(reader->end - reader->ptr) < count) {
        reader->error = true;
        return false;
    }
    *value = 0;
    for(size_t i = 0; i < count; ++i)
        *value = (*value << 8) | *reader->ptr++;
    return true;
}

static bool cbor_read_uint(CborReader* reader, uint64_t* value) {
    uint8_t major;
    return cbor_read_head(reader, &major, value) && major == 0;
}

static bool cbor_read_int(CborReader* reader, int64_t* value) {
    uint8_t major;
    uint64_t encoded;
    if(!cbor_read_head(reader, &major, &encoded) || (major != 0 && major != 1)) {
        reader->error = true;
        return false;
    }
    *value = major == 0 ? (int64_t)encoded : -(int64_t)encoded - 1;
    return true;
}

static bool cbor_read_bytes(
    CborReader* reader,
    uint8_t expected_major,
    const uint8_t** bytes,
    size_t* length) {
    uint8_t major;
    uint64_t encoded_length;
    if(!cbor_read_head(reader, &major, &encoded_length) || major != expected_major ||
       encoded_length > (uint64_t)(reader->end - reader->ptr)) {
        reader->error = true;
        return false;
    }
    *bytes = reader->ptr;
    *length = encoded_length;
    reader->ptr += encoded_length;
    return true;
}

static bool cbor_enter(CborReader* reader, uint8_t expected_major, size_t* count) {
    uint8_t major;
    uint64_t encoded_count;
    if(!cbor_read_head(reader, &major, &encoded_count) || major != expected_major ||
       encoded_count > SIZE_MAX) {
        reader->error = true;
        return false;
    }
    *count = encoded_count;
    return true;
}

static bool cbor_read_bool(CborReader* reader, bool* value) {
    uint8_t major;
    uint64_t simple;
    if(!cbor_read_head(reader, &major, &simple) || major != 7 || (simple != 20 && simple != 21)) {
        reader->error = true;
        return false;
    }
    *value = simple == 21;
    return true;
}

static bool cbor_skip(CborReader* reader) {
    uint8_t major;
    uint64_t value;
    if(!cbor_read_head(reader, &major, &value)) return false;
    if(major == 2 || major == 3) {
        if(value > (uint64_t)(reader->end - reader->ptr)) {
            reader->error = true;
            return false;
        }
        reader->ptr += value;
    } else if(major == 4) {
        for(uint64_t i = 0; i < value; ++i)
            if(!cbor_skip(reader)) return false;
    } else if(major == 5) {
        for(uint64_t i = 0; i < value * 2; ++i)
            if(!cbor_skip(reader)) return false;
    } else if(major == 6) {
        return cbor_skip(reader);
    }
    return true;
}

static bool cbor_text_equals(const uint8_t* text, size_t length, const char* expected) {
    size_t expected_length = strlen(expected);
    return length == expected_length && memcmp(text, expected, length) == 0;
}

static void cbor_write_head(CborWriter* writer, uint8_t major, uint64_t value) {
    if(writer->error) return;
    size_t extra = value < 24 ? 0 : value <= UINT8_MAX ? 1 : value <= UINT16_MAX ? 2 : 4;
    if((size_t)(writer->end - writer->ptr) < extra + 1) {
        writer->error = true;
        return;
    }
    if(extra == 0) {
        *writer->ptr++ = (major << 5) | value;
    } else {
        *writer->ptr++ = (major << 5) | (extra == 1 ? 24 : extra == 2 ? 25 : 26);
        for(size_t i = extra; i > 0; --i)
            *writer->ptr++ = value >> ((i - 1) * 8);
    }
}

static void cbor_write_uint(CborWriter* writer, uint64_t value) {
    cbor_write_head(writer, 0, value);
}

static void cbor_write_int(CborWriter* writer, int64_t value) {
    if(value >= 0)
        cbor_write_head(writer, 0, value);
    else
        cbor_write_head(writer, 1, -value - 1);
}

static void cbor_write_raw(CborWriter* writer, const uint8_t* data, size_t length) {
    if(writer->error || (size_t)(writer->end - writer->ptr) < length) {
        writer->error = true;
        return;
    }
    memcpy(writer->ptr, data, length);
    writer->ptr += length;
}

static void cbor_write_bytes(CborWriter* writer, const uint8_t* data, size_t length) {
    cbor_write_head(writer, 2, length);
    cbor_write_raw(writer, data, length);
}

static void cbor_write_text(CborWriter* writer, const char* text) {
    size_t length = strlen(text);
    cbor_write_head(writer, 3, length);
    cbor_write_raw(writer, (const uint8_t*)text, length);
}

static void cbor_write_array(CborWriter* writer, size_t count) {
    cbor_write_head(writer, 4, count);
}

static void cbor_write_map(CborWriter* writer, size_t count) {
    cbor_write_head(writer, 5, count);
}

static void cbor_write_bool(CborWriter* writer, bool value) {
    cbor_write_head(writer, 7, value ? 21 : 20);
}

static bool ctap2_sha256(const uint8_t* input, size_t length, uint8_t output[32]) {
    return mbedtls_sha256(input, length, output, 0) == 0;
}

static bool ctap2_hmac_parts(
    const uint8_t key[32],
    const uint8_t* first,
    size_t first_length,
    const uint8_t* second,
    size_t second_length,
    const uint8_t* third,
    size_t third_length,
    uint8_t output[32]) {
    bool success = false;
    mbedtls_md_context_t context;
    mbedtls_md_init(&context);
    do {
        const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
        if(!info || mbedtls_md_setup(&context, info, 1) != 0 ||
           mbedtls_md_hmac_starts(&context, key, 32) != 0 ||
           (first_length && mbedtls_md_hmac_update(&context, first, first_length) != 0) ||
           (second_length && mbedtls_md_hmac_update(&context, second, second_length) != 0) ||
           (third_length && mbedtls_md_hmac_update(&context, third, third_length) != 0) ||
           mbedtls_md_hmac_finish(&context, output) != 0)
            break;
        success = true;
    } while(false);
    mbedtls_md_free(&context);
    return success;
}

static bool ctap2_make_valid_private(
    Ctap2* ctap2,
    const char* label,
    const uint8_t rp_hash[32],
    const uint8_t nonce[32],
    uint8_t private_key[32]) {
    uint8_t suffix = 0;
    mbedtls_mpi scalar;
    mbedtls_mpi_init(&scalar);
    bool success = false;
    while(suffix != UINT8_MAX) {
        if(!ctap2_hmac_parts(
               ctap2->device_key,
               (const uint8_t*)label,
               strlen(label),
               rp_hash,
               32,
               nonce,
               32,
               private_key))
            break;
        private_key[31] ^= suffix;
        if(mbedtls_mpi_read_binary(&scalar, private_key, 32) == 0 &&
           mbedtls_ecp_check_privkey(&ctap2->group, &scalar) == 0) {
            success = true;
            break;
        }
        suffix++;
    }
    mbedtls_mpi_free(&scalar);
    return success;
}

static bool
    ctap2_public_key(Ctap2* ctap2, const uint8_t private_key[32], uint8_t x[32], uint8_t y[32]) {
    bool success = false;
    mbedtls_mpi scalar;
    mbedtls_ecp_point point;
    uint8_t encoded[65];
    size_t encoded_length = 0;
    mbedtls_mpi_init(&scalar);
    mbedtls_ecp_point_init(&point);
    do {
        if(mbedtls_mpi_read_binary(&scalar, private_key, 32) != 0 ||
           mbedtls_ecp_mul(
               &ctap2->group, &point, &scalar, &ctap2->group.G, ctap2_mbedtls_random, NULL) != 0 ||
           mbedtls_ecp_point_write_binary(
               &ctap2->group,
               &point,
               MBEDTLS_ECP_PF_UNCOMPRESSED,
               &encoded_length,
               encoded,
               sizeof(encoded)) != 0 ||
           encoded_length != sizeof(encoded))
            break;
        memcpy(x, encoded + 1, 32);
        memcpy(y, encoded + 33, 32);
        success = true;
    } while(false);
    mbedtls_ecp_point_free(&point);
    mbedtls_mpi_free(&scalar);
    return success;
}

static bool ctap2_der_sign(
    Ctap2* ctap2,
    const uint8_t private_key[32],
    const uint8_t hash[32],
    uint8_t* output,
    size_t output_size,
    size_t* output_length) {
    bool success = false;
    mbedtls_mpi scalar;
    mbedtls_mpi r;
    mbedtls_mpi s;
    mbedtls_mpi_init(&scalar);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);
    do {
        if(mbedtls_mpi_read_binary(&scalar, private_key, 32) != 0 ||
           mbedtls_ecdsa_sign(
               &ctap2->group, &r, &s, &scalar, hash, 32, ctap2_mbedtls_random, NULL) != 0)
            break;

        uint8_t raw[64];
        if(mbedtls_mpi_write_binary(&r, raw, 32) != 0 ||
           mbedtls_mpi_write_binary(&s, raw + 32, 32) != 0)
            break;
        size_t position = 2;
        for(size_t half = 0; half < 2; ++half) {
            const uint8_t* integer = raw + half * 32;
            size_t length = 32;
            while(length > 1 && *integer == 0) {
                integer++;
                length--;
            }
            bool leading_zero = (*integer & 0x80) != 0;
            if(position + 2 + length + leading_zero > output_size) break;
            output[position++] = 0x02;
            output[position++] = length + leading_zero;
            if(leading_zero) output[position++] = 0;
            memcpy(output + position, integer, length);
            position += length;
            if(half == 1) {
                output[0] = 0x30;
                output[1] = position - 2;
                *output_length = position;
                success = true;
            }
        }
    } while(false);
    mbedtls_mpi_free(&s);
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&scalar);
    return success;
}

static void ctap2_write_cose_key(
    CborWriter* writer,
    int64_t algorithm,
    const uint8_t x[32],
    const uint8_t y[32]) {
    cbor_write_map(writer, 5);
    cbor_write_int(writer, 1);
    cbor_write_int(writer, 2); /* EC2 */
    cbor_write_int(writer, 3);
    cbor_write_int(writer, algorithm);
    cbor_write_int(writer, -1);
    cbor_write_int(writer, 1); /* P-256 */
    cbor_write_int(writer, -2);
    cbor_write_bytes(writer, x, 32);
    cbor_write_int(writer, -3);
    cbor_write_bytes(writer, y, 32);
}

static bool ctap2_parse_rp(CborReader* reader, const uint8_t** rp_id, size_t* rp_id_len) {
    size_t count;
    if(!cbor_enter(reader, 5, &count)) return false;
    for(size_t i = 0; i < count; ++i) {
        const uint8_t* key;
        size_t key_length;
        if(!cbor_read_bytes(reader, 3, &key, &key_length)) return false;
        if(cbor_text_equals(key, key_length, "id")) {
            if(!cbor_read_bytes(reader, 3, rp_id, rp_id_len)) return false;
        } else if(!cbor_skip(reader)) {
            return false;
        }
    }
    return *rp_id != NULL;
}

static bool ctap2_parse_make_extensions(CborReader* reader, bool* hmac_secret) {
    size_t count;
    if(!cbor_enter(reader, 5, &count)) return false;
    for(size_t i = 0; i < count; ++i) {
        const uint8_t* key;
        size_t key_length;
        if(!cbor_read_bytes(reader, 3, &key, &key_length)) return false;
        if(cbor_text_equals(key, key_length, "hmac-secret")) {
            if(!cbor_read_bool(reader, hmac_secret)) return false;
        } else if(!cbor_skip(reader)) {
            return false;
        }
    }
    return true;
}

static bool ctap2_parse_user(CborReader* reader, const uint8_t** user_id, size_t* user_id_len) {
    size_t count;
    if(!cbor_enter(reader, 5, &count)) return false;
    for(size_t i = 0; i < count; ++i) {
        const uint8_t* key;
        size_t key_len;
        if(!cbor_read_bytes(reader, 3, &key, &key_len)) return false;
        if(cbor_text_equals(key, key_len, "id")) {
            if(!cbor_read_bytes(reader, 2, user_id, user_id_len)) return false;
        } else if(!cbor_skip(reader)) return false;
    }
    return *user_id != NULL;
}

static bool ctap2_parse_make_options(CborReader* reader, MakeCredentialRequest* request) {
    size_t count;
    if(!cbor_enter(reader, 5, &count)) return false;
    for(size_t i = 0; i < count; ++i) {
        const uint8_t* key;
        size_t key_length;
        if(!cbor_read_bytes(reader, 3, &key, &key_length)) return false;
        if(cbor_text_equals(key, key_length, "up")) {
            if(!cbor_read_bool(reader, &request->user_presence)) return false;
        } else if(cbor_text_equals(key, key_length, "rk")) {
            if(!cbor_read_bool(reader, &request->resident_key)) return false;
        } else if(!cbor_skip(reader)) {
            return false;
        }
    }
    return true;
}

static bool ctap2_parse_user_presence_option(CborReader* reader, bool* user_presence) {
    MakeCredentialRequest options = {.user_presence = *user_presence};
    if(!ctap2_parse_make_options(reader, &options)) return false;
    *user_presence = options.user_presence;
    return true;
}

static bool ctap2_parse_make_credential(
    const uint8_t* input,
    size_t input_length,
    MakeCredentialRequest* request) {
    memset(request, 0, sizeof(*request));
    request->user_presence = true;
    CborReader reader = {.ptr = input, .end = input + input_length};
    size_t count;
    if(!cbor_enter(&reader, 5, &count)) return false;
    for(size_t i = 0; i < count; ++i) {
        uint64_t key;
        if(!cbor_read_uint(&reader, &key)) return false;
        if(key == 2) {
            if(!ctap2_parse_rp(&reader, &request->rp_id, &request->rp_id_len)) return false;
        } else if(key == 3) {
            if(!ctap2_parse_user(&reader, &request->user_id, &request->user_id_len)) return false;
        } else if(key == 6) {
            if(!ctap2_parse_make_extensions(&reader, &request->hmac_secret)) return false;
        } else if(key == 7) {
            if(!ctap2_parse_make_options(&reader, request)) return false;
        } else if(!cbor_skip(&reader)) {
            return false;
        }
    }
    return !reader.error && reader.ptr == reader.end && request->rp_id &&
           request->rp_id_len <= CTAP2_MAX_RP_ID_SIZE &&
           (!request->resident_key || (request->user_id && request->user_id_len <= U2F_RESIDENT_USER_ID_MAX));
}

static bool ctap2_parse_credential_list(
    CborReader* reader,
    const uint8_t** credential_id,
    size_t* credential_id_len) {
    size_t array_count;
    if(!cbor_enter(reader, 4, &array_count) || array_count == 0) return false;
    for(size_t item = 0; item < array_count; ++item) {
        size_t map_count;
        if(!cbor_enter(reader, 5, &map_count)) return false;
        for(size_t i = 0; i < map_count; ++i) {
            const uint8_t* key;
            size_t key_length;
            if(!cbor_read_bytes(reader, 3, &key, &key_length)) return false;
            if(item == 0 && cbor_text_equals(key, key_length, "id")) {
                if(!cbor_read_bytes(reader, 2, credential_id, credential_id_len)) return false;
            } else if(!cbor_skip(reader)) {
                return false;
            }
        }
    }
    return *credential_id != NULL;
}

static bool ctap2_parse_cose_key(CborReader* reader, uint8_t x[32], uint8_t y[32]) {
    size_t count;
    bool got_x = false;
    bool got_y = false;
    if(!cbor_enter(reader, 5, &count)) return false;
    for(size_t i = 0; i < count; ++i) {
        int64_t key;
        if(!cbor_read_int(reader, &key)) return false;
        if(key == -2 || key == -3) {
            const uint8_t* coordinate;
            size_t coordinate_length;
            if(!cbor_read_bytes(reader, 2, &coordinate, &coordinate_length) ||
               coordinate_length != 32)
                return false;
            memcpy(key == -2 ? x : y, coordinate, 32);
            if(key == -2)
                got_x = true;
            else
                got_y = true;
        } else if(!cbor_skip(reader)) {
            return false;
        }
    }
    return got_x && got_y;
}

static bool ctap2_parse_hmac_secret(CborReader* reader, GetAssertionRequest* request) {
    size_t count;
    if(!cbor_enter(reader, 5, &count)) return false;
    for(size_t i = 0; i < count; ++i) {
        uint64_t key;
        if(!cbor_read_uint(reader, &key)) return false;
        if(key == 1) {
            if(!ctap2_parse_cose_key(reader, request->key_x, request->key_y)) return false;
        } else if(key == 2) {
            if(!cbor_read_bytes(reader, 2, &request->salt_enc, &request->salt_enc_len))
                return false;
        } else if(key == 3) {
            if(!cbor_read_bytes(reader, 2, &request->salt_auth, &request->salt_auth_len))
                return false;
        } else if(key == 4) {
            if(!cbor_read_uint(reader, &request->pin_protocol)) return false;
        } else if(!cbor_skip(reader)) {
            return false;
        }
    }
    request->hmac_secret = true;
    return true;
}

static bool ctap2_parse_get_extensions(CborReader* reader, GetAssertionRequest* request) {
    size_t count;
    if(!cbor_enter(reader, 5, &count)) return false;
    for(size_t i = 0; i < count; ++i) {
        const uint8_t* key;
        size_t key_length;
        if(!cbor_read_bytes(reader, 3, &key, &key_length)) return false;
        if(cbor_text_equals(key, key_length, "hmac-secret")) {
            if(!ctap2_parse_hmac_secret(reader, request)) return false;
        } else if(!cbor_skip(reader)) {
            return false;
        }
    }
    return true;
}

static bool ctap2_parse_get_assertion(
    const uint8_t* input,
    size_t input_length,
    GetAssertionRequest* request) {
    memset(request, 0, sizeof(*request));
    request->pin_protocol = 1;
    request->user_presence = true;
    CborReader reader = {.ptr = input, .end = input + input_length};
    size_t count;
    if(!cbor_enter(&reader, 5, &count)) return false;
    for(size_t i = 0; i < count; ++i) {
        uint64_t key;
        if(!cbor_read_uint(&reader, &key)) return false;
        if(key == 1) {
            if(!cbor_read_bytes(&reader, 3, &request->rp_id, &request->rp_id_len)) return false;
        } else if(key == 2) {
            if(!cbor_read_bytes(
                   &reader, 2, &request->client_data_hash, &request->client_data_hash_len))
                return false;
        } else if(key == 3) {
            if(!ctap2_parse_credential_list(
                   &reader, &request->credential_id, &request->credential_id_len))
                return false;
            request->allow_list_present = true;
        } else if(key == 4) {
            if(!ctap2_parse_get_extensions(&reader, request)) return false;
        } else if(key == 5) {
            if(!ctap2_parse_user_presence_option(&reader, &request->user_presence)) return false;
        } else if(!cbor_skip(&reader)) {
            return false;
        }
    }
    return !reader.error && reader.ptr == reader.end && request->rp_id &&
           request->rp_id_len <= CTAP2_MAX_RP_ID_SIZE && request->client_data_hash_len == 32 &&
           request->credential_id_len == CTAP2_CREDENTIAL_ID_SIZE;
}

static bool ctap2_credential_tag(
    Ctap2* ctap2,
    const uint8_t rp_hash[32],
    const uint8_t nonce[32],
    uint8_t tag[32]) {
    static const uint8_t label[] = "FIDO2 credential";
    return ctap2_hmac_parts(
        ctap2->device_key, label, sizeof(label) - 1, rp_hash, 32, nonce, 32, tag);
}

static bool ctap2_store_resident_credential(
    const MakeCredentialRequest* request, const uint8_t credential_id[CTAP2_CREDENTIAL_ID_SIZE]) {
    U2fResidentCredentials credentials;
    if(!u2f_data_resident_load(&credentials)) return false;

    size_t slot = credentials.count;
    for(size_t i = 0; i < credentials.count; ++i) {
        U2fResidentCredential* existing = &credentials.credential[i];
        if(existing->rp_id_len == request->rp_id_len && existing->user_id_len == request->user_id_len &&
           memcmp(existing->rp_id, request->rp_id, request->rp_id_len) == 0 &&
           memcmp(existing->user_id, request->user_id, request->user_id_len) == 0) {
            slot = i;
            break;
        }
    }
    if(slot == credentials.count) {
        if(credentials.count == U2F_RESIDENT_MAX_CREDENTIALS) return false;
        credentials.count++;
    }
    U2fResidentCredential* record = &credentials.credential[slot];
    memset(record, 0, sizeof(*record));
    record->rp_id_len = request->rp_id_len;
    record->user_id_len = request->user_id_len;
    memcpy(record->rp_id, request->rp_id, request->rp_id_len);
    memcpy(record->user_id, request->user_id, request->user_id_len);
    memcpy(record->credential_id, credential_id, CTAP2_CREDENTIAL_ID_SIZE);
    return u2f_data_resident_save(&credentials);
}

static const U2fResidentCredential* ctap2_find_resident_credential(
    const uint8_t* rp_id, size_t rp_id_len, U2fResidentCredentials* credentials) {
    if(!u2f_data_resident_load(credentials)) return NULL;
    for(size_t i = 0; i < credentials->count; ++i) {
        const U2fResidentCredential* record = &credentials->credential[i];
        if(record->rp_id_len == rp_id_len && memcmp(record->rp_id, rp_id, rp_id_len) == 0)
            return record;
    }
    return NULL;
}

static uint16_t ctap2_get_info(uint8_t* output, size_t output_size) {
    CborWriter writer = {.ptr = output + 1, .end = output + output_size};
    output[0] = CTAP2_OK;
    cbor_write_map(&writer, 9);

    cbor_write_uint(&writer, 1); /* versions */
    cbor_write_array(&writer, 2);
    cbor_write_text(&writer, "FIDO_2_0");
    cbor_write_text(&writer, "U2F_V2");

    cbor_write_uint(&writer, 2); /* extensions */
    cbor_write_array(&writer, 1);
    cbor_write_text(&writer, "hmac-secret");

    cbor_write_uint(&writer, 3); /* aaguid */
    cbor_write_bytes(&writer, ctap2_aaguid, sizeof(ctap2_aaguid));

    cbor_write_uint(&writer, 4); /* options */
    cbor_write_map(&writer, 4);
    cbor_write_text(&writer, "rk");
    cbor_write_bool(&writer, true);
    cbor_write_text(&writer, "up");
    cbor_write_bool(&writer, true);
    cbor_write_text(&writer, "plat");
    cbor_write_bool(&writer, false);
    cbor_write_text(&writer, "clientPin");
    cbor_write_bool(&writer, false);

    cbor_write_uint(&writer, 5); /* maxMsgSize */
    cbor_write_uint(&writer, 7609);
    cbor_write_uint(&writer, 6); /* pinUvAuthProtocols */
    cbor_write_array(&writer, 1);
    cbor_write_uint(&writer, 1);
    cbor_write_uint(&writer, 7); /* maxCredentialCountInList */
    cbor_write_uint(&writer, 8);
    cbor_write_uint(&writer, 8); /* maxCredentialIdLength */
    cbor_write_uint(&writer, CTAP2_CREDENTIAL_ID_SIZE);
    cbor_write_uint(&writer, 10); /* algorithms */
    cbor_write_array(&writer, 1);
    cbor_write_map(&writer, 2);
    cbor_write_text(&writer, "alg");
    cbor_write_int(&writer, -7);
    cbor_write_text(&writer, "type");
    cbor_write_text(&writer, "public-key");

    return writer.error ? 0 : writer.ptr - output;
}

static uint16_t ctap2_client_pin(
    Ctap2* ctap2,
    const uint8_t* input,
    size_t input_length,
    uint8_t* output,
    size_t output_size) {
    CborReader reader = {.ptr = input, .end = input + input_length};
    size_t count;
    uint64_t protocol = 0;
    uint64_t subcommand = 0;
    if(!cbor_enter(&reader, 5, &count)) return CTAP2_ERR_INVALID_CBOR;
    for(size_t i = 0; i < count; ++i) {
        uint64_t key;
        if(!cbor_read_uint(&reader, &key)) return CTAP2_ERR_INVALID_CBOR;
        if(key == 1) {
            if(!cbor_read_uint(&reader, &protocol)) return CTAP2_ERR_INVALID_CBOR;
        } else if(key == 2) {
            if(!cbor_read_uint(&reader, &subcommand)) return CTAP2_ERR_INVALID_CBOR;
        } else if(!cbor_skip(&reader)) {
            return CTAP2_ERR_INVALID_CBOR;
        }
    }
    if(protocol != 1 || subcommand != 2) return CTAP2_ERR_INVALID_PARAMETER;

    CborWriter writer = {.ptr = output + 1, .end = output + output_size};
    output[0] = CTAP2_OK;
    cbor_write_map(&writer, 1);
    cbor_write_uint(&writer, 1);
    ctap2_write_cose_key(
        &writer, -25, ctap2->key_agreement_x, ctap2->key_agreement_y); /* ECDH-ES + HKDF-256 */
    return writer.error ? 0 : writer.ptr - output;
}

static uint16_t ctap2_make_credential(
    Ctap2* ctap2,
    const uint8_t* input,
    size_t input_length,
    uint8_t* output,
    size_t output_size,
    uint32_t counter) {
    MakeCredentialRequest request;
    if(!ctap2_parse_make_credential(input, input_length, &request)) return CTAP2_ERR_INVALID_CBOR;

    /* hmac-secret is optional for WebAuthn.  Explicit up=false preserves LUKS. */
    bool webauthn_user_present = false;
    if(request.user_presence) {
        webauthn_user_present = ctap2_wait_for_user_presence(ctap2, true);
        if(!webauthn_user_present) return CTAP2_ERR_OPERATION_DENIED;
    }

    uint8_t rp_hash[32];
    uint8_t credential_id[CTAP2_CREDENTIAL_ID_SIZE];
    uint8_t private_key[32];
    uint8_t public_x[32];
    uint8_t public_y[32];
    if(!ctap2_sha256(request.rp_id, request.rp_id_len, rp_hash)) return 0;
    furi_hal_random_fill_buf(credential_id, 32);
    if(!ctap2_credential_tag(ctap2, rp_hash, credential_id, credential_id + 32) ||
       !ctap2_make_valid_private(ctap2, "FIDO2 signing", rp_hash, credential_id, private_key) ||
       !ctap2_public_key(ctap2, private_key, public_x, public_y))
        return 0;

    if(request.resident_key && !ctap2_store_resident_credential(&request, credential_id))
        return CTAP2_ERR_KEY_STORE_FULL;

    /* The ED flag and trailing extension map must always be emitted together. */
    const bool has_extension_data = request.hmac_secret;

    uint8_t auth_data[256];
    uint8_t* cursor = auth_data;
    memcpy(cursor, rp_hash, 32);
    cursor += 32;
    *cursor++ = 0x40 | (webauthn_user_present ? 0x01 : 0) |
                (has_extension_data ? 0x80 : 0);
    *cursor++ = counter >> 24;
    *cursor++ = counter >> 16;
    *cursor++ = counter >> 8;
    *cursor++ = counter;
    memcpy(cursor, ctap2_aaguid, sizeof(ctap2_aaguid));
    cursor += sizeof(ctap2_aaguid);
    *cursor++ = 0;
    *cursor++ = sizeof(credential_id);
    memcpy(cursor, credential_id, sizeof(credential_id));
    cursor += sizeof(credential_id);

    CborWriter auth_writer = {.ptr = cursor, .end = auth_data + sizeof(auth_data)};
    ctap2_write_cose_key(&auth_writer, -7, public_x, public_y);
    if(has_extension_data) {
        cbor_write_map(&auth_writer, 1);
        cbor_write_text(&auth_writer, "hmac-secret");
        cbor_write_bool(&auth_writer, true);
    }
    if(auth_writer.error) return 0;
    cursor = auth_writer.ptr;

    CborWriter writer = {.ptr = output + 1, .end = output + output_size};
    output[0] = CTAP2_OK;
    cbor_write_map(&writer, 3);
    cbor_write_uint(&writer, 1);
    cbor_write_text(&writer, "none");
    cbor_write_uint(&writer, 2);
    cbor_write_bytes(&writer, auth_data, cursor - auth_data);
    cbor_write_uint(&writer, 3);
    cbor_write_map(&writer, 0);
    memset(private_key, 0, sizeof(private_key));
    return writer.error ? 0 : writer.ptr - output;
}

static bool ctap2_shared_secret(
    Ctap2* ctap2,
    const uint8_t peer_x[32],
    const uint8_t peer_y[32],
    uint8_t shared_secret[32]) {
    bool success = false;
    mbedtls_mpi private_key;
    mbedtls_ecp_point peer;
    mbedtls_ecp_point shared_point;
    mbedtls_mpi_init(&private_key);
    mbedtls_ecp_point_init(&peer);
    mbedtls_ecp_point_init(&shared_point);
    do {
        if(mbedtls_mpi_read_binary(&private_key, ctap2->key_agreement_private, 32) != 0 ||
           mbedtls_mpi_read_binary(&peer.MBEDTLS_PRIVATE(X), peer_x, 32) != 0 ||
           mbedtls_mpi_read_binary(&peer.MBEDTLS_PRIVATE(Y), peer_y, 32) != 0 ||
           mbedtls_mpi_lset(&peer.MBEDTLS_PRIVATE(Z), 1) != 0 ||
           mbedtls_ecp_check_pubkey(&ctap2->group, &peer) != 0 ||
           mbedtls_ecp_mul(
               &ctap2->group, &shared_point, &private_key, &peer, ctap2_mbedtls_random, NULL) != 0)
            break;
        uint8_t raw_x[32];
        if(mbedtls_mpi_write_binary(&shared_point.MBEDTLS_PRIVATE(X), raw_x, sizeof(raw_x)) != 0 ||
           !ctap2_sha256(raw_x, sizeof(raw_x), shared_secret))
            break;
        success = true;
    } while(false);
    mbedtls_ecp_point_free(&shared_point);
    mbedtls_ecp_point_free(&peer);
    mbedtls_mpi_free(&private_key);
    return success;
}

static bool ctap2_aes_cbc(
    const uint8_t key[32],
    bool encrypt,
    const uint8_t* input,
    size_t length,
    uint8_t* output) {
    if(length == 0 || length % 16 != 0) return false;
    uint8_t iv[16] = {0};
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    int result = encrypt ? mbedtls_aes_setkey_enc(&aes, key, 256) :
                           mbedtls_aes_setkey_dec(&aes, key, 256);
    if(result == 0)
        result = mbedtls_aes_crypt_cbc(
            &aes, encrypt ? MBEDTLS_AES_ENCRYPT : MBEDTLS_AES_DECRYPT, length, iv, input, output);
    mbedtls_aes_free(&aes);
    return result == 0;
}

static uint16_t ctap2_get_assertion(
    Ctap2* ctap2,
    const uint8_t* input,
    size_t input_length,
    uint8_t* output,
    size_t output_size,
    uint32_t counter) {
    GetAssertionRequest request;
    if(!ctap2_parse_get_assertion(input, input_length, &request)) return CTAP2_ERR_INVALID_CBOR;
    if(request.hmac_secret &&
       (request.pin_protocol != 1 || (request.salt_enc_len != 32 && request.salt_enc_len != 64) ||
        request.salt_auth_len != 16))
        return CTAP2_ERR_INVALID_PARAMETER;

    U2fResidentCredentials resident_credentials;
    const U2fResidentCredential* resident_credential = NULL;
    if(!request.allow_list_present) {
        resident_credential =
            ctap2_find_resident_credential(request.rp_id, request.rp_id_len, &resident_credentials);
        if(!resident_credential) return CTAP2_ERR_NO_CREDENTIALS;
        request.credential_id = resident_credential->credential_id;
        request.credential_id_len = CTAP2_CREDENTIAL_ID_SIZE;
    }

    /*
     * Ordinary WebAuthn assertions require a physical confirmation.  Preserve
     * the existing explicit up=false path used by unattended disk unlock.
    */
    bool user_present = request.user_presence;
    if(user_present && !ctap2_wait_for_user_presence(ctap2, false))
        return CTAP2_ERR_OPERATION_DENIED;

    uint8_t rp_hash[32];
    uint8_t expected_tag[32];
    if(!ctap2_sha256(request.rp_id, request.rp_id_len, rp_hash) ||
       !ctap2_credential_tag(ctap2, rp_hash, request.credential_id, expected_tag))
        return 0;
    if(!ctap2_ct_equal(expected_tag, request.credential_id + 32, 32))
        return CTAP2_ERR_NO_CREDENTIALS;

    uint8_t shared_secret[32] = {0};
    uint8_t salts[64];
    uint8_t hmac_output[64];
    uint8_t encrypted_output[64];
    uint8_t credential_secret[32] = {0};
    if(request.hmac_secret) {
        uint8_t expected_auth[32];
        if(!ctap2_shared_secret(ctap2, request.key_x, request.key_y, shared_secret) ||
           !ctap2_hmac_parts(
               shared_secret,
               request.salt_enc,
               request.salt_enc_len,
               NULL,
               0,
               NULL,
               0,
               expected_auth) ||
           !ctap2_ct_equal(expected_auth, request.salt_auth, 16))
            return CTAP2_ERR_INTEGRITY_FAILURE;
        if(!ctap2_aes_cbc(shared_secret, false, request.salt_enc, request.salt_enc_len, salts) ||
           !ctap2_hmac_parts(
               ctap2->device_key,
               (const uint8_t*)"FIDO2 hmac-secret",
               sizeof("FIDO2 hmac-secret") - 1,
               rp_hash,
               32,
               request.credential_id,
               32,
               credential_secret))
            return 0;
        for(size_t offset = 0; offset < request.salt_enc_len; offset += 32) {
            if(!ctap2_hmac_parts(
                   credential_secret, salts + offset, 32, NULL, 0, NULL, 0, hmac_output + offset))
                return 0;
        }
        if(!ctap2_aes_cbc(shared_secret, true, hmac_output, request.salt_enc_len, encrypted_output))
            return 0;
    }

    uint8_t auth_data[128];
    uint8_t* cursor = auth_data;
    memcpy(cursor, rp_hash, 32);
    cursor += 32;
    *cursor++ = (user_present ? 0x01 : 0) | (request.hmac_secret ? 0x80 : 0);
    *cursor++ = counter >> 24;
    *cursor++ = counter >> 16;
    *cursor++ = counter >> 8;
    *cursor++ = counter;
    if(request.hmac_secret) {
        CborWriter auth_writer = {.ptr = cursor, .end = auth_data + sizeof(auth_data)};
        cbor_write_map(&auth_writer, 1);
        cbor_write_text(&auth_writer, "hmac-secret");
        cbor_write_bytes(&auth_writer, encrypted_output, request.salt_enc_len);
        if(auth_writer.error) return 0;
        cursor = auth_writer.ptr;
    }

    uint8_t private_key[32];
    uint8_t signature_hash[32];
    uint8_t signature_input[sizeof(auth_data) + 32];
    uint8_t signature[72];
    size_t signature_length;
    size_t auth_data_length = cursor - auth_data;
    memcpy(signature_input, auth_data, auth_data_length);
    memcpy(signature_input + auth_data_length, request.client_data_hash, 32);
    if(!ctap2_make_valid_private(
           ctap2, "FIDO2 signing", rp_hash, request.credential_id, private_key) ||
       !ctap2_sha256(signature_input, auth_data_length + 32, signature_hash) ||
       !ctap2_der_sign(
           ctap2, private_key, signature_hash, signature, sizeof(signature), &signature_length))
        return 0;

    CborWriter writer = {.ptr = output + 1, .end = output + output_size};
    output[0] = CTAP2_OK;
    cbor_write_map(&writer, resident_credential ? 4 : 3);
    cbor_write_uint(&writer, 1);
    cbor_write_map(&writer, 2);
    cbor_write_text(&writer, "id");
    cbor_write_bytes(&writer, request.credential_id, request.credential_id_len);
    cbor_write_text(&writer, "type");
    cbor_write_text(&writer, "public-key");
    cbor_write_uint(&writer, 2);
    cbor_write_bytes(&writer, auth_data, auth_data_length);
    cbor_write_uint(&writer, 3);
    cbor_write_bytes(&writer, signature, signature_length);
    if(resident_credential) {
        cbor_write_uint(&writer, 4); /* user */
        cbor_write_map(&writer, 1);
        cbor_write_text(&writer, "id");
        cbor_write_bytes(&writer, resident_credential->user_id, resident_credential->user_id_len);
    }

    memset(private_key, 0, sizeof(private_key));
    memset(credential_secret, 0, sizeof(credential_secret));
    memset(shared_secret, 0, sizeof(shared_secret));
    return writer.error ? 0 : writer.ptr - output;
}

Ctap2* ctap2_alloc(
    const uint8_t device_key[32],
    Ctap2UserPresenceRequest request_user_presence,
    Ctap2UserPresenceConsume consume_user_presence,
    Ctap2Keepalive send_keepalive,
    void* user_presence_context) {
    Ctap2* ctap2 = malloc(sizeof(Ctap2));
    if(!ctap2) return NULL;
    memset(ctap2, 0, sizeof(*ctap2));
    memcpy(ctap2->device_key, device_key, 32);
    ctap2->request_user_presence = request_user_presence;
    ctap2->consume_user_presence = consume_user_presence;
    ctap2->send_keepalive = send_keepalive;
    ctap2->user_presence_context = user_presence_context;
    mbedtls_ecp_group_init(&ctap2->group);
    if(mbedtls_ecp_group_load(&ctap2->group, MBEDTLS_ECP_DP_SECP256R1) != 0) {
        ctap2_free(ctap2);
        return NULL;
    }

    mbedtls_mpi scalar;
    mbedtls_mpi_init(&scalar);
    do {
        furi_hal_random_fill_buf(ctap2->key_agreement_private, 32);
        if(mbedtls_mpi_read_binary(&scalar, ctap2->key_agreement_private, 32) != 0) continue;
    } while(mbedtls_ecp_check_privkey(&ctap2->group, &scalar) != 0);
    mbedtls_mpi_free(&scalar);
    if(!ctap2_public_key(
           ctap2, ctap2->key_agreement_private, ctap2->key_agreement_x, ctap2->key_agreement_y)) {
        ctap2_free(ctap2);
        return NULL;
    }
    return ctap2;
}

void ctap2_free(Ctap2* ctap2) {
    if(!ctap2) return;
    mbedtls_ecp_group_free(&ctap2->group);
    memset(ctap2, 0, sizeof(*ctap2));
    free(ctap2);
}

uint16_t ctap2_handle(Ctap2* ctap2, uint8_t* buffer, uint16_t length, uint32_t counter) {
    if(!ctap2 || !buffer || length == 0) return 0;
    uint8_t command = buffer[0];
    const uint8_t* input = buffer + 1;
    size_t input_length = length - 1;
    uint16_t response_length = 0;
    if(command == CTAP2_CMD_GET_INFO) {
        response_length = ctap2_get_info(buffer, 7609);
    } else if(command == CTAP2_CMD_CLIENT_PIN) {
        response_length = ctap2_client_pin(ctap2, input, input_length, buffer, 7609);
    } else if(command == CTAP2_CMD_MAKE_CREDENTIAL) {
        response_length = ctap2_make_credential(ctap2, input, input_length, buffer, 7609, counter);
    } else if(command == CTAP2_CMD_GET_ASSERTION) {
        response_length = ctap2_get_assertion(ctap2, input, input_length, buffer, 7609, counter);
    } else {
        buffer[0] = CTAP2_ERR_INVALID_COMMAND;
        response_length = 1;
    }

    /* Command helpers return an error code until they begin a successful response. */
    if(response_length > 0 && buffer[0] != CTAP2_OK) {
        buffer[0] = response_length;
        response_length = 1;
    }
    if(response_length == 0) {
        buffer[0] = CTAP2_ERR_INVALID_PARAMETER;
        response_length = 1;
    }
    return response_length;
}
