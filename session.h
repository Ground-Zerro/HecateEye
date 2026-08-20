#ifndef _SESSION_H_
#define _SESSION_H_

#include <netinet/in.h>
#include <sys/types.h>
#include <stdint.h>
#include "ppp_hdlc.h"

typedef struct ppp_session {
    struct sockaddr_in peer;
    int pty_fd;
    pid_t pppd_pid;
    hdlc_deframer_t deframer;
    long last_rx_ms;
    uint32_t sid;
    uint32_t rx_ctr;
    uint32_t tx_ctr;
    struct ppp_session *next;
} ppp_session_t;

ppp_session_t *session_create(const char *pppd_path, char *const *pppd_extra_argv,
                               const struct sockaddr_in *peer, uint32_t sid, uint32_t ctr);

int session_reap_if_dead(ppp_session_t *s);

void session_destroy(ppp_session_t *s);

#endif
