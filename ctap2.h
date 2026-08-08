#pragma once

#include <furi.h>

typedef struct Ctap2 Ctap2;

Ctap2* ctap2_alloc(const uint8_t device_key[32]);
void ctap2_free(Ctap2* ctap2);

/** Process a CTAP2 CBOR request in-place. The returned length includes the status byte. */
uint16_t ctap2_handle(Ctap2* ctap2, uint8_t* buffer, uint16_t length, uint32_t counter);
