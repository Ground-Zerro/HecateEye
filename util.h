#ifndef _UTIL_H_
#define _UTIL_H_

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netdb.h>

#include "log.h"

#define UDP_SOCKET_BUF (4 * 1024 * 1024)

static inline void set_socket_buf(int fd, int opt, int force_opt, const char *name) {
    int want = UDP_SOCKET_BUF;
    if (setsockopt(fd, SOL_SOCKET, force_opt, &want, sizeof(want)) != 0)
        setsockopt(fd, SOL_SOCKET, opt, &want, sizeof(want));
    int got = 0;
    socklen_t len = sizeof(got);
    if (getsockopt(fd, SOL_SOCKET, opt, &got, &len) == 0 && got / 2 < want)
        log(LL_WARN, "%s clamped to %d of %d requested - raise net.core.%cmem_max",
            name, got / 2, want, name[3] == 'R' ? 'r' : 'w');
}

static inline void configure_udp_socket(int fd) {
    set_socket_buf(fd, SO_RCVBUF, SO_RCVBUFFORCE, "SO_RCVBUF");
    set_socket_buf(fd, SO_SNDBUF, SO_SNDBUFFORCE, "SO_SNDBUF");
    int pmtu = IP_PMTUDISC_DONT;
    setsockopt(fd, IPPROTO_IP, IP_MTU_DISCOVER, &pmtu, sizeof(pmtu));
}

static inline void warn_small_tcp_buffers(void) {
    static const char *paths[] = { "/proc/sys/net/ipv4/tcp_wmem", "/proc/sys/net/ipv4/tcp_rmem" };
    static const char *names[] = { "tcp_wmem", "tcp_rmem" };
    for (int i = 0; i < 2; i++) {
        FILE *f = fopen(paths[i], "r");
        if (!f) return;
        long lo, def, max;
        int n = fscanf(f, "%ld %ld %ld", &lo, &def, &max);
        fclose(f);
        if (n == 3 && max < 4 * 1024 * 1024)
            log(LL_WARN, "net.ipv4.%s max is %ld - TCP that terminates on this host and "
                "crosses the tunnel will be window-limited well below link speed, because "
                "ppp interfaces carry no segmentation offload and socket buffers are "
                "charged per skb; raise it if this host is a tunnel endpoint", names[i], max);
    }
}

static inline int addr_equal(const struct sockaddr_in *a, const struct sockaddr_in *b) {
    return a->sin_addr.s_addr == b->sin_addr.s_addr && a->sin_port == b->sin_port;
}

static inline long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static inline int parse_hostport(const char *s, char *host_out, size_t host_cap, int *port_out) {
    const char *colon = strrchr(s, ':');
    if (!colon || colon == s) return -1;
    size_t hlen = (size_t)(colon - s);
    if (hlen >= host_cap) return -1;
    memcpy(host_out, s, hlen);
    host_out[hlen] = '\0';
    *port_out = atoi(colon + 1);
    if (*port_out <= 0 || *port_out > 65535) return -1;
    return 0;
}

static inline int resolve_udp_addr(const char *host, int port, struct sockaddr_in *out) {
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    char portstr[16];
    snprintf(portstr, sizeof(portstr), "%d", port);
    if (getaddrinfo(host, portstr, &hints, &res) != 0 || !res) return -1;
    memcpy(out, res->ai_addr, sizeof(*out));
    freeaddrinfo(res);
    return 0;
}

#endif
