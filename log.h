#ifndef _LOG_H_
#define _LOG_H_

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <stdlib.h>

#define LL_ERROR 0
#define LL_WARN  1
#define LL_INFO  2
#define LL_DEBUG 3
#define LL_TRACE 4
#define LL_DEFAULT LL_INFO

extern int g_verbose;
extern const char *g_log_tag;

static inline char log_level_char(int level) {
    switch (level) {
        case LL_ERROR: return 'E';
        case LL_WARN:  return 'W';
        case LL_INFO:  return 'I';
        case LL_DEBUG: return 'D';
        case LL_TRACE: return 'T';
        default: return '?';
    }
}

#define log(level, fmt, ...) do { \
    if (g_verbose >= (level)) \
        fprintf(stderr, "[%s][%c] " fmt "\n", g_log_tag, log_level_char(level), ##__VA_ARGS__); \
} while (0)

#define serror(fmt, ...) log(LL_ERROR, fmt " - %s (%d)", ##__VA_ARGS__, strerror(errno), errno)

static inline int log_parse_level(const char *s) {
    if (strcasecmp(s, "error") == 0) return LL_ERROR;
    if (strcasecmp(s, "warn") == 0) return LL_WARN;
    if (strcasecmp(s, "info") == 0) return LL_INFO;
    if (strcasecmp(s, "debug") == 0) return LL_DEBUG;
    if (strcasecmp(s, "trace") == 0) return LL_TRACE;
    char *end;
    long v = strtol(s, &end, 10);
    if (*s == '\0' || *end != '\0' || v < LL_ERROR || v > LL_TRACE) return -1;
    return (int)v;
}

#endif
