#include "wire.h"

#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "log.h"

#define WIRE_ROUNDS 4

_Static_assert(WIRE_KEYSTREAM_ALIGN % sizeof(size_t) == 0, "keystream offset breaks word alignment");
_Static_assert((WIRE_KEYSTREAM_SLACK & (WIRE_KEYSTREAM_SLACK - 1)) == 0, "keystream slack must be a power of two");
_Static_assert(WIRE_KEYSTREAM_SLACK == 2048, "offset derivation splits the nonce into two 11-bit fields");
_Static_assert(WIRE_KEYSTREAM_LEN % 8 == 0, "keystream is drawn in 64-bit words");

static uint8_t g_keystream[WIRE_KEYSTREAM_LEN] __attribute__((aligned(WIRE_KEYSTREAM_ALIGN)));
static uint32_t g_nonce_key[WIRE_ROUNDS];
static uint32_t g_sid_key[WIRE_ROUNDS];
static uint64_t g_pad_key;
static uint32_t g_name_salt;
static int g_obfuscate_bytes = 0;

static inline void put32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static inline uint32_t get32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline uint16_t round_f(uint16_t x, uint32_t k) {
    uint32_t v = ((uint32_t)x + k) * 0x9E3779B1u;
    v ^= v >> 15;
    v *= 0x85EBCA6Bu;
    return (uint16_t)(v >> 16);
}

static inline uint32_t feistel(uint32_t v, const uint32_t k[WIRE_ROUNDS], uint32_t tweak) {
    uint16_t l = (uint16_t)(v >> 16), r = (uint16_t)v;
    for (int i = 0; i < WIRE_ROUNDS; i++) {
        uint16_t t = (uint16_t)(l ^ round_f(r, k[i] + tweak));
        l = r;
        r = t;
    }
    return ((uint32_t)l << 16) | r;
}

static inline uint32_t feistel_inv(uint32_t v, const uint32_t k[WIRE_ROUNDS], uint32_t tweak) {
    uint16_t l = (uint16_t)(v >> 16), r = (uint16_t)v;
    for (int i = WIRE_ROUNDS - 1; i >= 0; i--) {
        uint16_t t = (uint16_t)(r ^ round_f(l, k[i] + tweak));
        r = l;
        l = t;
    }
    return ((uint32_t)l << 16) | r;
}

static inline const uint8_t *payload_mask(uint32_t nonce) {
    return g_keystream + (nonce & (WIRE_KEYSTREAM_SLACK - 1) & ~(uint32_t)(WIRE_KEYSTREAM_ALIGN - 1));
}

static void xor_payload(uint8_t *buf, int len, uint32_t nonce) {
    const uint8_t *mask = payload_mask(nonce);
    uint64_t v = ((uint64_t)nonce << 32 | nonce) ^ g_pad_key;
    v *= 0xD6E8FEB86659FD93ull;
    v ^= v >> 32;
    v *= 0xD6E8FEB86659FD93ull;

    uint8_t pad[8];
    for (int b = 0; b < 8; b++) pad[b] = (uint8_t)(v >> (8 * b));
    uint64_t tw;
    memcpy(&tw, pad, sizeof(tw));

    if (g_obfuscate_bytes > 0 && g_obfuscate_bytes < len) len = g_obfuscate_bytes;
    int i = 0;
    for (; i + 8 <= len; i += 8) {
        uint64_t b, m;
        memcpy(&b, buf + i, sizeof(b));
        memcpy(&m, mask + i, sizeof(m));
        b ^= m ^ tw;
        memcpy(buf + i, &b, sizeof(b));
    }
    for (; i < len; i++) buf[i] ^= mask[i] ^ pad[i & 7];
}

static uint64_t splitmix64(uint64_t *state) {
    uint64_t z = (*state += 0x9E3779B97F4A7C15ull);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
    return z ^ (z >> 31);
}

int wire_keystream_init(const char *key, int key_len, int obfuscate_bytes) {
    if (key_len < 1) {
        log(LL_ERROR, "key must not be empty");
        return -1;
    }
    if (obfuscate_bytes < 0) {
        log(LL_ERROR, "obfuscate-bytes must not be negative");
        return -1;
    }
    g_obfuscate_bytes = obfuscate_bytes;
    if (obfuscate_bytes > 0)
        log(LL_INFO, "obfuscating first %d payload bytes of each packet", obfuscate_bytes);

    uint64_t state = 0xCBF29CE484222325ull;
    for (int i = 0; i < key_len; i++) {
        state ^= (uint8_t)key[i];
        state *= 0x100000001B3ull;
    }

    for (size_t i = 0; i < sizeof(g_keystream); i += 8) {
        uint64_t v = splitmix64(&state);
        for (int b = 0; b < 8; b++) g_keystream[i + b] = (uint8_t)(v >> (8 * b));
    }
    for (int i = 0; i < WIRE_ROUNDS; i++) g_nonce_key[i] = (uint32_t)splitmix64(&state);
    for (int i = 0; i < WIRE_ROUNDS; i++) g_sid_key[i] = (uint32_t)splitmix64(&state);
    g_pad_key = splitmix64(&state);
    g_name_salt = (uint32_t)splitmix64(&state);
    return 0;
}

uint32_t wire_session_id(const char *name) {
    if (name && *name) {
        uint32_t h = g_name_salt;
        for (const uint8_t *p = (const uint8_t *)name; *p; p++) {
            h ^= *p;
            h *= 0x01000193u;
        }
        return h;
    }

    uint32_t v = 0;
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        ssize_t n = read(fd, &v, sizeof(v));
        close(fd);
        if (n == (ssize_t)sizeof(v)) return v;
    }
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return ((uint32_t)ts.tv_nsec * 2654435761u) ^ ((uint32_t)getpid() << 16) ^ g_name_salt;
}

int wire_seal(uint8_t *buf, int payload_len, uint32_t sid, uint32_t ctr) {
    uint32_t nonce = feistel(ctr, g_nonce_key, 0);
    put32(buf, nonce);
    put32(buf + 4, feistel(sid, g_sid_key, nonce));
    xor_payload(buf + WIRE_HEADER_LEN, payload_len, nonce);
    return WIRE_HEADER_LEN + payload_len;
}

int wire_open(uint8_t *buf, int len, wire_head_t *head) {
    if (len < WIRE_HEADER_LEN || len > WIRE_MAX_ENC) return -1;
    uint32_t nonce = get32(buf);
    head->ctr = feistel_inv(nonce, g_nonce_key, 0);
    head->sid = feistel_inv(get32(buf + 4), g_sid_key, nonce);
    xor_payload(buf + WIRE_HEADER_LEN, len - WIRE_HEADER_LEN, nonce);
    return len - WIRE_HEADER_LEN;
}
