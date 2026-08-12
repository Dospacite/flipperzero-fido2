#pragma once

#include <stdbool.h>
#include <stdint.h>

#include <furi.h>

typedef struct Ctap2 Ctap2;

/**
 * CTAP2 operations used for WebAuthn require an explicit user-presence check.
 * The callbacks are supplied by the HID transport so the core does not depend
 * on the UI implementation.
 */
typedef void (*Ctap2UserPresenceRequest)(void* context, bool registration);
typedef bool (*Ctap2UserPresenceConsume)(void* context);
typedef void (*Ctap2Keepalive)(void* context);

Ctap2* ctap2_alloc(
    const uint8_t device_key[32],
    Ctap2UserPresenceRequest request_user_presence,
    Ctap2UserPresenceConsume consume_user_presence,
    Ctap2Keepalive send_keepalive,
    void* user_presence_context);
void ctap2_free(Ctap2* ctap2);

/** Process a CTAP2 CBOR request in-place. The returned length includes the status byte. */
uint16_t ctap2_handle(Ctap2* ctap2, uint8_t* buffer, uint16_t length, uint32_t counter);
