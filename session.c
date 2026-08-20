#include "session.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <pty.h>
#include <termios.h>
#include <sys/wait.h>
#include <signal.h>

#include "log.h"

static void set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0) fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static char **build_pppd_argv(const char *pppd_path, const char *slave_name, char *const *extra_argv) {
    int extra_count = 0;
    while (extra_argv && extra_argv[extra_count]) extra_count++;

    int total = 1 + 1 + 1 + extra_count + 1;
    char **argv = calloc((size_t)total, sizeof(char *));
    if (!argv) return NULL;

    int i = 0;
    argv[i++] = strdup(pppd_path);
    argv[i++] = strdup(slave_name);
    argv[i++] = strdup("nodetach");
    for (int j = 0; j < extra_count; j++) argv[i++] = strdup(extra_argv[j]);
    argv[i] = NULL;
    return argv;
}

static void free_argv(char **argv) {
    if (!argv) return;
    for (int i = 0; argv[i]; i++) free(argv[i]);
    free(argv);
}

ppp_session_t *session_create(const char *pppd_path, char *const *pppd_extra_argv,
                               const struct sockaddr_in *peer, uint32_t sid, uint32_t ctr) {
    int master_fd, slave_fd;
    char slave_name[64];

    if (openpty(&master_fd, &slave_fd, slave_name, NULL, NULL) == -1) {
        serror("openpty");
        return NULL;
    }
    log(LL_DEBUG, "opened pty %s for pppd", slave_name);

    struct termios tio;
    if (tcgetattr(slave_fd, &tio) == 0) {
        cfmakeraw(&tio);
        tcsetattr(slave_fd, TCSANOW, &tio);
    }

    char **argv = build_pppd_argv(pppd_path, slave_name, pppd_extra_argv);
    if (!argv) {
        close(master_fd);
        close(slave_fd);
        return NULL;
    }

    pid_t pid = fork();
    if (pid < 0) {
        serror("fork");
        close(master_fd);
        close(slave_fd);
        free_argv(argv);
        return NULL;
    }
    if (pid == 0) {
        close(master_fd);
        setsid();
        execv(pppd_path, argv);
        perror("execv pppd");
        _exit(127);
    }

    close(slave_fd);
    free_argv(argv);
    set_nonblocking(master_fd);

    ppp_session_t *s = calloc(1, sizeof(*s));
    if (!s) {
        kill(pid, SIGTERM);
        waitpid(pid, NULL, 0);
        close(master_fd);
        return NULL;
    }
    s->pty_fd = master_fd;
    s->pppd_pid = pid;
    s->peer = *peer;
    s->sid = sid;
    s->rx_ctr = ctr;
    hdlc_deframer_init(&s->deframer);
    return s;
}

int session_reap_if_dead(ppp_session_t *s) {
    if (s->pppd_pid <= 0) return 1;
    int status;
    pid_t r = waitpid(s->pppd_pid, &status, WNOHANG);
    if (r == s->pppd_pid) {
        s->pppd_pid = -1;
        return 1;
    }
    return 0;
}

void session_destroy(ppp_session_t *s) {
    if (!s) return;
    if (s->pty_fd >= 0) close(s->pty_fd);
    if (s->pppd_pid > 0) {
        kill(s->pppd_pid, SIGTERM);
        waitpid(s->pppd_pid, NULL, 0);
    }
    free(s);
}
