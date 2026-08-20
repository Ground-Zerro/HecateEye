#include "netif.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

#include "log.h"

#define VETH_HOST "pwgc0"
#define VETH_BRIDGE_SIDE "pwgc0p"

static const char *find_ip_bin(void) {
    static const char *candidates[] = {
        "/opt/sbin/ip", "/sbin/ip", "/usr/sbin/ip", "/bin/ip", "/usr/bin/ip", NULL
    };
    for (int i = 0; candidates[i]; i++) {
        if (access(candidates[i], X_OK) == 0) return candidates[i];
    }
    return "ip";
}

static void log_argv(char *const argv[]) {
    if (g_verbose < LL_TRACE) return;
    char line[256] = {0};
    size_t off = 0;
    for (int i = 0; argv[i] && off < sizeof(line) - 1; i++) {
        off += (size_t)snprintf(line + off, sizeof(line) - off, "%s%s", i ? " " : "", argv[i]);
    }
    log(LL_TRACE, "netif: running: %s", line);
}

static int run_ip(char *const argv[]) {
    log_argv(argv);
    pid_t pid = fork();
    if (pid < 0) { serror("netif: fork"); return -1; }
    if (pid == 0) {
        execvp(argv[0], argv);
        perror("execvp");
        _exit(127);
    }
    int status;
    if (waitpid(pid, &status, 0) < 0) { serror("netif: waitpid"); return -1; }
    int ok = WIFEXITED(status) && WEXITSTATUS(status) == 0;
    if (!ok) log(LL_DEBUG, "netif: command failed (exit status 0x%x)", status);
    return ok ? 0 : -1;
}

int netif_keenetic_setup(const char *bridge, const char *ip, int prefix) {
    const char *ipbin = find_ip_bin();
    char ip_cidr[192];
    snprintf(ip_cidr, sizeof(ip_cidr), "%s/%d", ip, prefix);

    log(LL_INFO, "netif: provisioning %s/%s on bridge %s, ip=%s", VETH_HOST, VETH_BRIDGE_SIDE, bridge, ip_cidr);

    char *del_argv[] = { (char *)ipbin, "link", "del", VETH_HOST, NULL };
    run_ip(del_argv);

    char *add_argv[] = { (char *)ipbin, "link", "add", VETH_HOST, "type", "veth",
                          "peer", "name", VETH_BRIDGE_SIDE, NULL };
    if (run_ip(add_argv) != 0) {
        log(LL_ERROR, "netif: failed to create veth pair %s/%s", VETH_HOST, VETH_BRIDGE_SIDE);
        return -1;
    }

    char *master_argv[] = { (char *)ipbin, "link", "set", VETH_BRIDGE_SIDE, "master", (char *)bridge, NULL };
    if (run_ip(master_argv) != 0) {
        log(LL_ERROR, "netif: failed to attach %s to bridge %s", VETH_BRIDGE_SIDE, bridge);
        netif_keenetic_teardown();
        return -1;
    }

    char *up_bridge_argv[] = { (char *)ipbin, "link", "set", VETH_BRIDGE_SIDE, "up", NULL };
    run_ip(up_bridge_argv);

    char *addr_argv[] = { (char *)ipbin, "addr", "add", ip_cidr, "dev", VETH_HOST, NULL };
    if (run_ip(addr_argv) != 0) {
        log(LL_ERROR, "netif: failed to assign %s to %s", ip_cidr, VETH_HOST);
        netif_keenetic_teardown();
        return -1;
    }

    char *up_host_argv[] = { (char *)ipbin, "link", "set", VETH_HOST, "up", NULL };
    if (run_ip(up_host_argv) != 0) {
        log(LL_ERROR, "netif: failed to bring up %s", VETH_HOST);
        netif_keenetic_teardown();
        return -1;
    }

    log(LL_DEBUG, "netif: %s/%s up, %s attached to %s", VETH_HOST, VETH_BRIDGE_SIDE, VETH_BRIDGE_SIDE, bridge);
    return 0;
}

void netif_keenetic_teardown(void) {
    log(LL_DEBUG, "netif: tearing down %s/%s", VETH_HOST, VETH_BRIDGE_SIDE);
    const char *ipbin = find_ip_bin();
    char *del_argv[] = { (char *)ipbin, "link", "del", VETH_HOST, NULL };
    run_ip(del_argv);
}
