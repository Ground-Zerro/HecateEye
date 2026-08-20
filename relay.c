#define _GNU_SOURCE
#include "relay.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "wire.h"
#include "util.h"
#include "log.h"

#define RELAY_MAX_PACKET 2048
#define MAX_EPOLL_EVENTS 32
#define SWEEP_INTERVAL_MS 1000
#define DROPS_REPORT_MS 5000
#define IOPROF_REPORT_S 2.0
#define RX_TIMEOUT_MS 500
#define RX_BATCH 32

_Static_assert(RELAY_MAX_PACKET - WIRE_HEADER_LEN <= WIRE_MAX_PAYLOAD, "relay packet exceeds keystream span");

extern volatile sig_atomic_t g_stop;

typedef struct {
    uint8_t buf[RX_BATCH][RELAY_MAX_PACKET];
    struct mmsghdr rxh[RX_BATCH];
    struct iovec rxi[RX_BATCH];
    struct mmsghdr txh[RX_BATCH];
    struct iovec txi[RX_BATCH];
    struct sockaddr_in addr[RX_BATCH];
    char ctl[RX_BATCH][CMSG_SPACE(sizeof(uint32_t))];
    socklen_t addr_len;
    uint32_t ovfl_seen;
    int txn;
} batch_ctx_t;

typedef struct {
    const char *tag;
    const char *dir;
    batch_ctx_t *bc;
    double recv_s, work_s, prof_last;
    long batches, pkts;
    long runt, oversize, undecodable, replayed, tx_partial, tx_error, rx_overflow;
    long drops_last;
} worker_t;

static inline double prof_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static void worker_report(worker_t *w) {
    long now = now_ms();
    if (w->drops_last == 0) w->drops_last = now;
    else if (now - w->drops_last >= DROPS_REPORT_MS) {
        w->drops_last = now;
        if (w->runt | w->oversize | w->undecodable | w->replayed | w->tx_partial | w->tx_error | w->rx_overflow) {
            log(LL_WARN, "%s/%s drops: rx_overflow=%ld runt=%ld oversize=%ld undecodable=%ld "
                "replayed=%ld tx_partial=%ld tx_error=%ld", w->tag, w->dir, w->rx_overflow, w->runt,
                w->oversize, w->undecodable, w->replayed, w->tx_partial, w->tx_error);
            w->runt = w->oversize = w->undecodable = w->replayed = 0;
            w->tx_partial = w->tx_error = w->rx_overflow = 0;
        }
    }

    if (g_verbose < LL_DEBUG) { w->prof_last = 0; w->recv_s = w->work_s = 0; w->batches = w->pkts = 0; return; }
    double t = prof_now();
    if (w->prof_last == 0) { w->prof_last = t; return; }
    double elapsed = t - w->prof_last;
    if (elapsed < IOPROF_REPORT_S) return;
    if (w->pkts > 0) {
        double other = elapsed - w->recv_s - w->work_s;
        if (other < 0) other = 0;
        log(LL_DEBUG, "%s/%s ioprof: pkts=%ld batches=%ld recv_wall=%.0fms work_wall=%.0fms other_wall=%.0fms "
            "/ %.0fms wall (%.0f pkts/s, %.0f pkt/batch)", w->tag, w->dir, w->pkts, w->batches,
            w->recv_s * 1000, w->work_s * 1000, other * 1000, elapsed * 1000,
            w->pkts / elapsed, (double)w->pkts / (double)w->batches);
    }
    w->prof_last = t;
    w->recv_s = w->work_s = 0;
    w->batches = w->pkts = 0;
}

static void batch_init(batch_ctx_t *bc, int headroom, int want_addr) {
    memset(bc, 0, sizeof(*bc));
    bc->addr_len = want_addr ? (socklen_t)sizeof(bc->addr[0]) : 0;
    for (int b = 0; b < RX_BATCH; b++) {
        bc->rxi[b].iov_base = bc->buf[b] + headroom;
        bc->rxi[b].iov_len = sizeof(bc->buf[b]) - (size_t)headroom;
        bc->rxh[b].msg_hdr.msg_iov = &bc->rxi[b];
        bc->rxh[b].msg_hdr.msg_iovlen = 1;
        bc->rxh[b].msg_hdr.msg_name = want_addr ? (void *)&bc->addr[b] : NULL;
        bc->rxh[b].msg_hdr.msg_control = bc->ctl[b];
        bc->txh[b].msg_hdr.msg_iov = &bc->txi[b];
        bc->txh[b].msg_hdr.msg_iovlen = 1;
    }
}

static batch_ctx_t *batch_create(int headroom, int want_addr) {
    batch_ctx_t *bc = malloc(sizeof(*bc));
    if (!bc) { log(LL_ERROR, "out of memory for batch buffers"); return NULL; }
    batch_init(bc, headroom, want_addr);
    return bc;
}

static void enable_rxq_overflow_report(int fd) {
    int on = 1;
    setsockopt(fd, SOL_SOCKET, SO_RXQ_OVFL, &on, sizeof(on));
}

static void set_rx_timeout(int fd) {
    struct timeval tv = { .tv_sec = RX_TIMEOUT_MS / 1000, .tv_usec = (RX_TIMEOUT_MS % 1000) * 1000 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}

static void collect_rxq_overflow(worker_t *w, int rxn) {
    batch_ctx_t *bc = w->bc;
    for (int b = rxn - 1; b >= 0; b--) {
        for (struct cmsghdr *c = CMSG_FIRSTHDR(&bc->rxh[b].msg_hdr); c;
             c = CMSG_NXTHDR(&bc->rxh[b].msg_hdr, c)) {
            if (c->cmsg_level != SOL_SOCKET || c->cmsg_type != SO_RXQ_OVFL) continue;
            uint32_t total;
            memcpy(&total, CMSG_DATA(c), sizeof(total));
            w->rx_overflow += (long)(uint32_t)(total - bc->ovfl_seen);
            bc->ovfl_seen = total;
            return;
        }
    }
}

static int batch_recv(worker_t *w, int fd, int flags) {
    batch_ctx_t *bc = w->bc;
    for (int b = 0; b < RX_BATCH; b++) {
        bc->rxh[b].msg_hdr.msg_namelen = bc->addr_len;
        bc->rxh[b].msg_hdr.msg_controllen = sizeof(bc->ctl[b]);
    }
    bc->txn = 0;
    int rxn = recvmmsg(fd, bc->rxh, RX_BATCH, flags, NULL);
    if (rxn > 0) collect_rxq_overflow(w, rxn);
    return rxn;
}

static void batch_queue(batch_ctx_t *bc, uint8_t *payload, int len, struct sockaddr_in *dst) {
    int j = bc->txn++;
    bc->txi[j].iov_base = payload;
    bc->txi[j].iov_len = (size_t)len;
    bc->txh[j].msg_hdr.msg_name = dst;
    bc->txh[j].msg_hdr.msg_namelen = dst ? (socklen_t)sizeof(*dst) : 0;
}

static void batch_flush(worker_t *w, int fd) {
    batch_ctx_t *bc = w->bc;
    if (bc->txn <= 0) return;
    int sent = sendmmsg(fd, bc->txh, (unsigned)bc->txn, MSG_DONTWAIT);
    if (sent < 0) w->tx_error += bc->txn;
    else if (sent < bc->txn) w->tx_partial += bc->txn - sent;
    bc->txn = 0;
}

static int batch_truncated(worker_t *w, int b) {
    if (!(w->bc->rxh[b].msg_hdr.msg_flags & MSG_TRUNC)) return 0;
    w->oversize++;
    return 1;
}

static int wire_wrap(worker_t *w, int b, uint32_t sid, uint32_t ctr) {
    if (batch_truncated(w, b)) return -1;
    return wire_seal(w->bc->buf[b], (int)w->bc->rxh[b].msg_len, sid, ctr);
}

static int wire_unwrap(worker_t *w, int b, wire_head_t *head) {
    if (batch_truncated(w, b)) return -1;
    int plen = wire_open(w->bc->buf[b], (int)w->bc->rxh[b].msg_len, head);
    if (plen < 0) { w->runt++; return -1; }
    return plen;
}

typedef struct {
    int local_fd;
    int outer_fd;
    uint32_t sid;
    uint32_t tx_ctr;
    pthread_mutex_t lock;
    struct sockaddr_in local_peer;
    int have_local_peer;
} client_ctx_t;

static void *client_encode_main(void *arg) {
    client_ctx_t *c = arg;
    worker_t w = { .tag = "client", .dir = "enc", .bc = batch_create(WIRE_HEADER_LEN, 1) };
    if (!w.bc) return NULL;

    while (!g_stop) {
        double t0 = prof_now();
        int rxn = batch_recv(&w, c->local_fd, MSG_WAITFORONE);
        double t1 = prof_now();
        worker_report(&w);
        if (rxn <= 0) continue;

        pthread_mutex_lock(&c->lock);
        c->local_peer = w.bc->addr[rxn - 1];
        c->have_local_peer = 1;
        pthread_mutex_unlock(&c->lock);

        for (int b = 0; b < rxn; b++) {
            int wlen = wire_wrap(&w, b, c->sid, c->tx_ctr);
            if (wlen < 0) continue;
            c->tx_ctr++;
            log(LL_TRACE, "client: %u bytes local->peer", w.bc->rxh[b].msg_len);
            batch_queue(w.bc, w.bc->buf[b], wlen, NULL);
        }
        batch_flush(&w, c->outer_fd);

        w.recv_s += t1 - t0;
        w.work_s += prof_now() - t1;
        w.batches++;
        w.pkts += rxn;
    }
    free(w.bc);
    return NULL;
}

static void *client_decode_main(void *arg) {
    client_ctx_t *c = arg;
    worker_t w = { .tag = "client", .dir = "dec", .bc = batch_create(0, 0) };
    if (!w.bc) return NULL;

    while (!g_stop) {
        double t0 = prof_now();
        int rxn = batch_recv(&w, c->outer_fd, MSG_WAITFORONE);
        double t1 = prof_now();
        worker_report(&w);
        if (rxn <= 0) continue;

        struct sockaddr_in dst;
        pthread_mutex_lock(&c->lock);
        int have = c->have_local_peer;
        dst = c->local_peer;
        pthread_mutex_unlock(&c->lock);
        if (!have) continue;

        for (int b = 0; b < rxn; b++) {
            wire_head_t head;
            int plen = wire_unwrap(&w, b, &head);
            if (plen < 0) continue;
            if (head.sid != c->sid) { w.undecodable++; continue; }
            log(LL_TRACE, "client: %d bytes peer->local", plen);
            batch_queue(w.bc, w.bc->buf[b] + WIRE_HEADER_LEN, plen, &dst);
        }
        batch_flush(&w, c->local_fd);

        w.recv_s += t1 - t0;
        w.work_s += prof_now() - t1;
        w.batches++;
        w.pkts += rxn;
    }
    free(w.bc);
    return NULL;
}

static int relay_client_run(const config_t *cfg) {
    struct sockaddr_in local_bind, peer_addr;
    if (resolve_udp_addr(cfg->local_host, cfg->local_port, &local_bind) != 0) {
        log(LL_ERROR, "cannot resolve local %s", cfg->local_host); return 1;
    }
    if (resolve_udp_addr(cfg->peer_host, cfg->peer_port, &peer_addr) != 0) {
        log(LL_ERROR, "cannot resolve peer %s", cfg->peer_host); return 1;
    }

    client_ctx_t c;
    memset(&c, 0, sizeof(c));
    c.sid = wire_session_id(cfg->session_id);
    pthread_mutex_init(&c.lock, NULL);
    c.local_fd = socket(AF_INET, SOCK_DGRAM, 0);
    c.outer_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (c.local_fd < 0 || c.outer_fd < 0) { serror("socket"); return 1; }
    configure_udp_socket(c.local_fd);
    configure_udp_socket(c.outer_fd);
    enable_rxq_overflow_report(c.local_fd);
    enable_rxq_overflow_report(c.outer_fd);
    set_rx_timeout(c.local_fd);
    set_rx_timeout(c.outer_fd);
    if (bind(c.local_fd, (struct sockaddr *)&local_bind, sizeof(local_bind)) != 0) {
        serror("bind local %s:%d", cfg->local_host, cfg->local_port); return 1;
    }
    if (connect(c.outer_fd, (struct sockaddr *)&peer_addr, sizeof(peer_addr)) != 0) {
        serror("connect peer %s:%d", cfg->peer_host, cfg->peer_port); return 1;
    }

    log(LL_INFO, "client: local=%s:%d peer=%s:%d session=%08x%s", cfg->local_host, cfg->local_port,
        cfg->peer_host, cfg->peer_port, c.sid, cfg->session_id[0] ? "" : " (random, set session-id to keep it across restarts)");

    pthread_t enc, dec;
    if (pthread_create(&enc, NULL, client_encode_main, &c) != 0) { serror("pthread_create"); return 1; }
    if (pthread_create(&dec, NULL, client_decode_main, &c) != 0) {
        serror("pthread_create");
        g_stop = 1;
        pthread_join(enc, NULL);
        return 1;
    }
    pthread_join(enc, NULL);
    pthread_join(dec, NULL);

    close(c.local_fd);
    close(c.outer_fd);
    pthread_mutex_destroy(&c.lock);
    return 0;
}

typedef struct {
    struct sockaddr_in remote;
    int target_fd;
    long last_rx_ms;
    uint32_t sid;
    uint32_t rx_ctr;
    uint32_t tx_ctr;
    int in_use;
} relay_peer_t;

typedef struct {
    int listen_fd;
    int epfd;
    struct sockaddr_in target;
    relay_peer_t *peers;
    int cap;
    int count;
    int idle_timeout_s;
    pthread_mutex_t lock;
} server_ctx_t;

static int server_find_peer(server_ctx_t *s, uint32_t sid) {
    for (int i = 0; i < s->cap; i++) {
        if (s->peers[i].in_use && s->peers[i].sid == sid) return i;
    }
    return -1;
}

static int server_add_peer(server_ctx_t *s, const struct sockaddr_in *remote, uint32_t sid, uint32_t ctr) {
    int slot = -1;
    for (int i = 0; i < s->cap; i++) {
        if (!s->peers[i].in_use) { slot = i; break; }
    }
    if (slot < 0) return -1;

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { serror("server: socket"); return -1; }
    configure_udp_socket(fd);
    enable_rxq_overflow_report(fd);
    if (connect(fd, (struct sockaddr *)&s->target, sizeof(s->target)) != 0) {
        serror("server: connect to target");
        close(fd);
        return -1;
    }

    relay_peer_t *p = &s->peers[slot];
    p->remote = *remote;
    p->target_fd = fd;
    p->last_rx_ms = now_ms();
    p->sid = sid;
    p->rx_ctr = ctr;
    p->tx_ctr = 0;
    p->in_use = 1;
    s->count++;

    struct epoll_event ev = { .events = EPOLLIN, .data = { .u32 = (uint32_t)slot } };
    epoll_ctl(s->epfd, EPOLL_CTL_ADD, fd, &ev);
    log(LL_INFO, "server: new session %08x from %s:%d (%d active)",
        sid, inet_ntoa(remote->sin_addr), ntohs(remote->sin_port), s->count);
    return slot;
}

static void server_sweep(server_ctx_t *s) {
    long now = now_ms();
    pthread_mutex_lock(&s->lock);
    for (int i = 0; i < s->cap; i++) {
        relay_peer_t *p = &s->peers[i];
        if (!p->in_use) continue;
        if (now - p->last_rx_ms < (long)s->idle_timeout_s * 1000) continue;
        log(LL_INFO, "server: session %08x idle for %ds, releasing slot (%d active)",
            p->sid, s->idle_timeout_s, s->count - 1);
        epoll_ctl(s->epfd, EPOLL_CTL_DEL, p->target_fd, NULL);
        close(p->target_fd);
        p->in_use = 0;
        s->count--;
    }
    pthread_mutex_unlock(&s->lock);
}

static void *server_decode_main(void *arg) {
    server_ctx_t *s = arg;
    worker_t w = { .tag = "server", .dir = "dec", .bc = batch_create(0, 1) };
    if (!w.bc) return NULL;

    while (!g_stop) {
        double t0 = prof_now();
        int rxn = batch_recv(&w, s->listen_fd, MSG_WAITFORONE);
        double t1 = prof_now();
        worker_report(&w);
        if (rxn <= 0) continue;

        int txfd = -1;
        for (int b = 0; b < rxn; b++) {
            wire_head_t head;
            int plen = wire_unwrap(&w, b, &head);
            if (plen < 0) continue;

            struct sockaddr_in *src = &w.bc->addr[b];
            int fd = -1;
            pthread_mutex_lock(&s->lock);
            int slot = server_find_peer(s, head.sid);
            if (slot < 0) {
                if (head.ctr >= WIRE_CTR_FRESH) {
                    pthread_mutex_unlock(&s->lock);
                    w.undecodable++;
                    continue;
                }
                slot = server_add_peer(s, src, head.sid, head.ctr);
            } else {
                relay_peer_t *p = &s->peers[slot];
                int advanced = wire_ctr_advanced(&p->rx_ctr, head.ctr);
                if (!addr_equal(&p->remote, src)) {
                    if (!advanced) {
                        pthread_mutex_unlock(&s->lock);
                        w.replayed++;
                        continue;
                    }
                    char from[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &p->remote.sin_addr, from, sizeof(from));
                    log(LL_INFO, "server: session %08x moved from %s:%d to %s:%d", head.sid,
                        from, ntohs(p->remote.sin_port),
                        inet_ntoa(src->sin_addr), ntohs(src->sin_port));
                    p->remote = *src;
                }
            }
            if (slot >= 0) {
                s->peers[slot].last_rx_ms = now_ms();
                fd = s->peers[slot].target_fd;
            }
            pthread_mutex_unlock(&s->lock);

            if (fd < 0) {
                log(LL_WARN, "server: no slot for session %08x from %s:%d (max_clients reached)",
                    head.sid, inet_ntoa(src->sin_addr), ntohs(src->sin_port));
                continue;
            }
            log(LL_TRACE, "server: %d bytes %s:%d->target", plen,
                inet_ntoa(src->sin_addr), ntohs(src->sin_port));

            if (txfd != fd) batch_flush(&w, txfd);
            txfd = fd;
            batch_queue(w.bc, w.bc->buf[b] + WIRE_HEADER_LEN, plen, NULL);
        }
        batch_flush(&w, txfd);

        w.recv_s += t1 - t0;
        w.work_s += prof_now() - t1;
        w.batches++;
        w.pkts += rxn;
    }
    free(w.bc);
    return NULL;
}

static void *server_encode_main(void *arg) {
    server_ctx_t *s = arg;
    worker_t w = { .tag = "server", .dir = "enc", .bc = batch_create(WIRE_HEADER_LEN, 0) };
    if (!w.bc) return NULL;
    long last_sweep = now_ms();

    while (!g_stop) {
        struct epoll_event events[MAX_EPOLL_EVENTS];
        int n = epoll_wait(s->epfd, events, MAX_EPOLL_EVENTS, SWEEP_INTERVAL_MS);
        worker_report(&w);

        for (int i = 0; i < n; i++) {
            int slot = (int)events[i].data.u32;
            struct sockaddr_in dst;
            pthread_mutex_lock(&s->lock);
            int fd = s->peers[slot].in_use ? s->peers[slot].target_fd : -1;
            dst = s->peers[slot].remote;
            uint32_t sid = s->peers[slot].sid;
            uint32_t ctr = s->peers[slot].tx_ctr;
            pthread_mutex_unlock(&s->lock);
            if (fd < 0) continue;

            double t0 = prof_now();
            int rxn = batch_recv(&w, fd, MSG_DONTWAIT);
            double t1 = prof_now();
            if (rxn <= 0) continue;

            for (int b = 0; b < rxn; b++) {
                int wlen = wire_wrap(&w, b, sid, ctr);
                if (wlen < 0) continue;
                ctr++;
                log(LL_TRACE, "server: %u bytes target->%s:%d", w.bc->rxh[b].msg_len,
                    inet_ntoa(dst.sin_addr), ntohs(dst.sin_port));
                batch_queue(w.bc, w.bc->buf[b], wlen, &dst);
            }
            batch_flush(&w, s->listen_fd);

            pthread_mutex_lock(&s->lock);
            if (s->peers[slot].in_use && s->peers[slot].target_fd == fd)
                s->peers[slot].tx_ctr = ctr;
            pthread_mutex_unlock(&s->lock);

            w.recv_s += t1 - t0;
            w.work_s += prof_now() - t1;
            w.batches++;
            w.pkts += rxn;
        }

        long now = now_ms();
        if (now - last_sweep >= SWEEP_INTERVAL_MS) {
            server_sweep(s);
            last_sweep = now;
        }
    }
    free(w.bc);
    return NULL;
}

static int relay_server_run(const config_t *cfg) {
    struct sockaddr_in listen_bind;
    if (resolve_udp_addr(cfg->bind_host, cfg->bind_port, &listen_bind) != 0) {
        log(LL_ERROR, "cannot resolve listen %s", cfg->bind_host); return 1;
    }

    server_ctx_t s;
    memset(&s, 0, sizeof(s));
    pthread_mutex_init(&s.lock, NULL);
    s.cap = cfg->max_clients > 0 ? cfg->max_clients : 1;
    s.idle_timeout_s = cfg->idle_timeout_s;
    if (resolve_udp_addr(cfg->target_host, cfg->target_port, &s.target) != 0) {
        log(LL_ERROR, "cannot resolve target %s", cfg->target_host); return 1;
    }
    s.peers = calloc((size_t)s.cap, sizeof(*s.peers));
    if (!s.peers) { log(LL_ERROR, "out of memory for peer table"); return 1; }

    s.listen_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (s.listen_fd < 0) { serror("socket"); return 1; }
    configure_udp_socket(s.listen_fd);
    enable_rxq_overflow_report(s.listen_fd);
    set_rx_timeout(s.listen_fd);
    if (bind(s.listen_fd, (struct sockaddr *)&listen_bind, sizeof(listen_bind)) != 0) {
        serror("bind listen %s:%d", cfg->bind_host, cfg->bind_port); return 1;
    }

    s.epfd = epoll_create1(0);
    if (s.epfd < 0) { serror("epoll_create1"); return 1; }

    log(LL_INFO, "server: listen=%s:%d target=%s:%d max_clients=%d idle_timeout=%ds",
        cfg->bind_host, cfg->bind_port, cfg->target_host, cfg->target_port, s.cap, s.idle_timeout_s);

    pthread_t enc, dec;
    if (pthread_create(&enc, NULL, server_encode_main, &s) != 0) { serror("pthread_create"); return 1; }
    if (pthread_create(&dec, NULL, server_decode_main, &s) != 0) {
        serror("pthread_create");
        g_stop = 1;
        pthread_join(enc, NULL);
        return 1;
    }
    pthread_join(enc, NULL);
    pthread_join(dec, NULL);

    for (int i = 0; i < s.cap; i++)
        if (s.peers[i].in_use) close(s.peers[i].target_fd);
    free(s.peers);
    close(s.listen_fd);
    close(s.epfd);
    pthread_mutex_destroy(&s.lock);
    return 0;
}

int relay_mode_run(const config_t *cfg) {
    if (cfg->role == ROLE_SERVER) return relay_server_run(cfg);
    return relay_client_run(cfg);
}
