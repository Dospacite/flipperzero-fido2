#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <furi.h>

typedef enum {
    U2fNotifyRegister,
    U2fNotifyAuth,
    U2fNotifyAuthSuccess,
    U2fNotifyWink,
    U2fNotifyConnect,
    U2fNotifyDisconnect,
    U2fNotifyError,
} U2fNotifyEvent;

typedef struct U2fData U2fData;

typedef void (*U2fEvtCallback)(U2fNotifyEvent evt, void* context);

U2fData* u2f_alloc(void);

bool u2f_init(U2fData* instance);

void u2f_free(U2fData* instance);

void u2f_set_event_callback(U2fData* instance, U2fEvtCallback callback, void* context);

void u2f_confirm_user_present(U2fData* instance);

/** Ask the UI to display a user-presence prompt for a CTAP2 operation. */
void u2f_request_user_presence(U2fData* instance, bool registration);

/** Return and clear a confirmation made with the Flipper's OK button. */
bool u2f_consume_user_presence(U2fData* instance);

uint16_t u2f_msg_parse(U2fData* instance, uint8_t* buf, uint16_t len);

/** Device-unique secret used by the CTAP2 credential derivation code. */
const uint8_t* u2f_get_device_key(const U2fData* instance);

uint32_t u2f_get_counter(const U2fData* instance);

/** Advance and persist the shared authenticator signature counter. */
uint32_t u2f_advance_counter(U2fData* instance);

void u2f_wink(U2fData* instance);

void u2f_set_state(U2fData* instance, uint8_t state);

#ifdef __cplusplus
}
#endif
