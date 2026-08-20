#include "ppp_mode.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "session.h"
#include "wire.h"
#include "util.h"
#include "log.h"

#define MAX_UDP_PACKET WIRE_MAX_ENC
#define MAX_EPOLL_EVENTS 32
#define SWEEP_INTERVAL_MS 1000

_Static_assert(HDLC_MAX_FRAME <= WIRE_MAX_PAYLOAD, "ppp frame exceeds keystream span");

extern volatile sig_atomic_t g_stop;

static ppp_session_t *g_sessions = NULL;
static int g_session_count = 0;
static int g_epfd = -1;

static ppp_session_t *find_session_by_sid(uint32_t sid) {
    for (ppp_session_t *s = g_sessions; s; s = s->next) {
        if (s->sid == sid) return s;
    }
    return NULL;
}

static ppp_session_t *add_session(const config_t *cfg, const struct sockaddr_in *peer,
                                  uint32_t sid, uint32_t ctr) {
    ppp_session_t *s = session_create(cfg->pppd_path, cfg->pppd_extra_argv, peer, sid, ctr);
    if (!s) return NULL;
    s->last_rx_ms = now_ms();
    s->next = g_sessions;
    g_sessions = s;
    g_session_count++;

    struct epoll_event ev = { .events = EPOLLIN, .data = { .ptr = s } };
    if (epoll_ctl(g_epfd, EPOLL_CTL_ADD, s->pty_fd, &ev) != 0) {
        serror("epoll_ctl add pty");
    }
    log(LL_INFO, "new session %08x for %s:%d (pppd pid %d, %d active)",
        sid, inet_ntoa(peer->sin_addr), ntohs(peer->sin_port), s->pppd_pid, g_session_count);
    return s;
}

static void remove_session(ppp_session_t *target) {
    log(LL_DEBUG, "removing session %08x for %s:%d", target->sid,
        inet_ntoa(target->peer.sin_addr), ntohs(target->peer.sin_port));
    epoll_ctl(g_epfd, EPOLL_CTL_DEL, target->pty_fd, NULL);
    ppp_session_t **pp = &g_sessions;
    while (*pp) {
        if (*pp == target) {
            *pp = target->next;
            session_destroy(target);
            g_session_count--;
            return;
        }
        pp = &(*pp)->next;
    }
}

struct pty_frame_ctx {
    int udp_fd;
    ppp_session_t *s;
};

static void on_pty_frame(const uint8_t *frame, size_t frame_len, void *ctx_) {
    struct pty_frame_ctx *ctx = ctx_;
    ppp_session_t *s = ctx->s;
    if (frame_len > HDLC_MAX_FRAME) return;
    uint8_t wire[WIRE_MAX_ENC] __attribute__((aligned(WIRE_KEYSTREAM_ALIGN)));
    memcpy(wire + WIRE_HEADER_LEN, frame, frame_len);
    int wire_len = wire_seal(wire, (int)frame_len, s->sid, s->tx_ctr++);
    sendto(ctx->udp_fd, wire, (size_t)wire_len, 0, (struct sockaddr *)&s->peer, sizeof(s->peer));
}

static void pump_pty_to_udp(int udp_fd, ppp_session_t *s) {
    uint8_t buf[4096];
    ssize_t n = read(s->pty_fd, buf, sizeof(buf));
    if (n <= 0) return;
    log(LL_TRACE, "%zd bytes pty->udp for %s:%d", n, inet_ntoa(s->peer.sin_addr), ntohs(s->peer.sin_port));
    struct pty_frame_ctx ctx = { .udp_fd = udp_fd, .s = s };
    hdlc_deframer_feed(&s->deframer, buf, (size_t)n, on_pty_frame, &ctx);
}

static void pump_udp_to_pty(ppp_session_t *s, const uint8_t *payload, size_t len) {
    log(LL_TRACE, "%zu bytes udp->pty for %s:%d", len, inet_ntoa(s->peer.sin_addr), ntohs(s->peer.sin_port));
    s->last_rx_ms = now_ms();
    uint8_t framed[2 * HDLC_MAX_FRAME + 4];
    int flen = hdlc_frame_encode(payload, len, framed, sizeof(framed));
    if (flen < 0) return;
    ssize_t w = write(s->pty_fd, framed, (size_t)flen);
    (void)w;
}

static void handle_udp_readable(int udp_fd, const config_t *cfg) {
    uint8_t buf[MAX_UDP_PACKET] __attribute__((aligned(WIRE_KEYSTREAM_ALIGN)));
    struct sockaddr_in src;
    socklen_t slen = sizeof(src);
    ssize_t n = recvfrom(udp_fd, buf, sizeof(buf), 0, (struct sockaddr *)&src, &slen);
    if (n <= 0) return;

    wire_head_t head;
    int plen = wire_open(buf, (int)n, &head);
    if (plen < 0) return;

    ppp_session_t *s = find_session_by_sid(head.sid);
    if (!s) {
        if (cfg->role == ROLE_CLIENT || head.ctr >= WIRE_CTR_FRESH) return;
        if (g_session_count >= cfg->max_clients) return;
        s = add_session(cfg, &src, head.sid, head.ctr);
        if (!s) return;
    } else if (!addr_equal(&s->peer, &src)) {
        if (!wire_ctr_advanced(&s->rx_ctr, head.ctr)) return;
        char from[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &s->peer.sin_addr, from, sizeof(from));
        log(LL_INFO, "session %08x moved from %s:%d to %s:%d", head.sid,
            from, ntohs(s->peer.sin_port), inet_ntoa(src.sin_addr), ntohs(src.sin_port));
        s->peer = src;
    } else {
        wire_ctr_advanced(&s->rx_ctr, head.ctr);
    }
    pump_udp_to_pty(s, buf + WIRE_HEADER_LEN, (size_t)plen);
}

static void sweep_sessions(int idle_timeout_s) {
    long now = now_ms();
    ppp_session_t *s = g_sessions;
    while (s) {
        ppp_session_t *next = s->next;
        if (session_reap_if_dead(s)) {
            log(LL_INFO, "session %08x pppd exited, tearing down", s->sid);
            remove_session(s);
        } else if (now - s->last_rx_ms >= (long)idle_timeout_s * 1000) {
            log(LL_INFO, "session %08x idle for %ds, tearing down", s->sid, idle_timeout_s);
            remove_session(s);
        }
        s = next;
    }
}

int ppp_mode_run(const config_t *cfg) {
    int udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_fd < 0) { serror("socket"); return 1; }
    configure_udp_socket(udp_fd);

    struct sockaddr_in local_addr;
    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    if (cfg->role == ROLE_SERVER) {
        struct sockaddr_in bind_addr;
        if (resolve_udp_addr(cfg->bind_host, cfg->bind_port, &bind_addr) != 0) {
            log(LL_ERROR, "cannot resolve listen %s", cfg->bind_host); return 1;
        }
        if (bind(udp_fd, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) != 0) {
            serror("bind %s:%d", cfg->bind_host, cfg->bind_port); return 1;
        }
        log(LL_INFO, "listen=%s:%d, max_clients=%d, idle_timeout=%ds",
            cfg->bind_host, cfg->bind_port, cfg->max_clients, cfg->idle_timeout_s);
    } else {
        local_addr.sin_addr.s_addr = INADDR_ANY;
        local_addr.sin_port = 0;
        if (bind(udp_fd, (struct sockaddr *)&local_addr, sizeof(local_addr)) != 0) {
            serror("bind"); return 1;
        }
    }

    g_epfd = epoll_create1(0);
    if (g_epfd < 0) { serror("epoll_create1"); return 1; }

    struct epoll_event ev = { .events = EPOLLIN, .data = { .ptr = NULL } };
    epoll_ctl(g_epfd, EPOLL_CTL_ADD, udp_fd, &ev);

    if (cfg->role == ROLE_CLIENT) {
        struct sockaddr_in peer;
        if (resolve_udp_addr(cfg->peer_host, cfg->peer_port, &peer) != 0) {
            log(LL_ERROR, "cannot resolve peer %s", cfg->peer_host); return 1;
        }
        uint32_t sid = wire_session_id(cfg->session_id);
        log(LL_INFO, "peer=%s:%d, pppd=%s, session=%08x%s", cfg->peer_host, cfg->peer_port,
            cfg->pppd_path, sid,
            cfg->session_id[0] ? "" : " (random, set session-id to keep it across restarts)");
        if (!add_session(cfg, &peer, sid, 0)) {
            log(LL_ERROR, "failed to start client session");
            return 1;
        }
    }

    long last_sweep = now_ms();
    while (!g_stop) {
        struct epoll_event events[MAX_EPOLL_EVENTS];
        int n = epoll_wait(g_epfd, events, MAX_EPOLL_EVENTS, SWEEP_INTERVAL_MS);
        for (int i = 0; i < n; i++) {
            if (events[i].data.ptr == NULL) {
                handle_udp_readable(udp_fd, cfg);
            } else {
                pump_pty_to_udp(udp_fd, (ppp_session_t *)events[i].data.ptr);
            }
        }

        long now = now_ms();
        if (now - last_sweep >= SWEEP_INTERVAL_MS) {
            sweep_sessions(cfg->idle_timeout_s);
            last_sweep = now;
            if (cfg->role == ROLE_CLIENT && g_sessions == NULL) {
                log(LL_INFO, "client session ended, exiting");
                break;
            }
        }
    }

    while (g_sessions) remove_session(g_sessions);
    close(udp_fd);
    close(g_epfd);
    return 0;
}
