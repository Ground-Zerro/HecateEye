#ifndef _WIRE_H_
#define _WIRE_H_

#include <stdint.h>

#define WIRE_HEADER_LEN 8
#define WIRE_MAX_PAYLOAD 4096
#define WIRE_MAX_ENC (WIRE_HEADER_LEN + WIRE_MAX_PAYLOAD)
#define WIRE_KEYSTREAM_SLACK 2048
#define WIRE_KEYSTREAM_ALIGN 8
#define WIRE_KEYSTREAM_LEN (WIRE_MAX_PAYLOAD + WIRE_KEYSTREAM_SLACK)
#define WIRE_CTR_FRESH 1024
#define WIRE_REORDER_WINDOW 256

typedef struct {
    uint32_t sid;
    uint32_t ctr;
} wire_head_t;

int wire_keystream_init(const char *key, int key_len, int obfuscate_bytes);

uint32_t wire_session_id(const char *name);

int wire_seal(uint8_t *buf, int payload_len, uint32_t sid, uint32_t ctr);

int wire_open(uint8_t *buf, int len, wire_head_t *head);

static inline int wire_ctr_advanced(uint32_t *seen, uint32_t ctr) {
    if ((int32_t)(ctr - *seen) > 0 ||
        (ctr < WIRE_CTR_FRESH && *seen - ctr > WIRE_REORDER_WINDOW)) {
        *seen = ctr;
        return 1;
    }
    return 0;
}

#endif
