#ifndef _PPP_HDLC_H_
#define _PPP_HDLC_H_

#include <stdint.h>
#include <stddef.h>

#define HDLC_FLAG   0x7E
#define HDLC_ESCAPE 0x7D
#define HDLC_MAX_FRAME 4096

typedef struct {
    uint8_t buf[HDLC_MAX_FRAME];
    size_t len;
    int escape_pending;
} hdlc_deframer_t;

static inline void hdlc_deframer_init(hdlc_deframer_t *d) {
    d->len = 0;
    d->escape_pending = 0;
}

static inline void hdlc_deframer_feed(hdlc_deframer_t *d, const uint8_t *in, size_t in_len,
                                       void (*on_frame)(const uint8_t *frame, size_t frame_len, void *ctx),
                                       void *ctx) {
    for (size_t i = 0; i < in_len; i++) {
        uint8_t byte = in[i];
        if (byte == HDLC_FLAG) {
            if (d->len > 0) {
                on_frame(d->buf, d->len, ctx);
            }
            d->len = 0;
            d->escape_pending = 0;
            continue;
        }
        if (byte == HDLC_ESCAPE) {
            d->escape_pending = 1;
            continue;
        }
        if (d->escape_pending) {
            byte ^= 0x20;
            d->escape_pending = 0;
        }
        if (d->len < sizeof(d->buf)) {
            d->buf[d->len++] = byte;
        }
    }
}

static inline int hdlc_needs_escape(uint8_t byte) {
    return byte == HDLC_FLAG || byte == HDLC_ESCAPE || byte < 0x20;
}

static inline int hdlc_frame_encode(const uint8_t *in, size_t in_len, uint8_t *out, size_t out_cap) {
    size_t o = 0;
    if (o >= out_cap) return -1;
    out[o++] = HDLC_FLAG;
    for (size_t i = 0; i < in_len; i++) {
        uint8_t byte = in[i];
        if (hdlc_needs_escape(byte)) {
            if (o + 2 > out_cap) return -1;
            out[o++] = HDLC_ESCAPE;
            out[o++] = byte ^ 0x20;
        } else {
            if (o + 1 > out_cap) return -1;
            out[o++] = byte;
        }
    }
    if (o >= out_cap) return -1;
    out[o++] = HDLC_FLAG;
    return (int)o;
}

#endif
