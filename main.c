#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <signal.h>

#include "config.h"
#include "util.h"
#include "ppp_mode.h"
#include "relay.h"
#include "netif.h"
#include "log.h"
#include "wire.h"

volatile sig_atomic_t g_stop = 0;
static void on_signal(int sig) { (void)sig; g_stop = 1; }

int g_verbose = LL_DEFAULT;
const char *g_log_tag = "main";

static void usage(const char *prog) {
    fprintf(stderr,
        "usage: %s --mode ppp|relay --role client|server --key <string>\n"
        "       %s --config <file>\n"
        "\n"
        "  mode=ppp (pty-bridge, obfuscator owns pppd directly):\n"
        "    --pppd <path> [--pppd-arg <arg> ...]\n"
        "    --role client --peer host:port | --role server --listen host:port\n"
        "\n"
        "  mode=relay (proxy in front of a stock client/server, no pppd):\n"
        "    --role client --local host:port --peer host:port\n"
        "    --role server --listen host:port --target host:port\n"
        "    --role keenetic --local ip:port --peer host:port\n"
        "      --lan-bridge ifname [--lan-prefix N]\n"
        "      (like role=client, but first gives itself a distinct LAN\n"
        "      identity via a veth pair bridged into --lan-bridge, so\n"
        "      --local's ip does not collide with the router's own stock\n"
        "      client on the same port; --lan-prefix defaults to 24)\n"
        "\n"
        "  common: [--max-clients N] [--idle-timeout S]\n"
        "          [--session-id <string>] (client-side identity carried in\n"
        "          every packet, so the server keeps recognising this client\n"
        "          after its NAT mapping changes; set it to survive a restart\n"
        "          too, otherwise a random one is drawn at every start)\n"
        "          [--verbose error|warn|info|debug|trace] (default: info)\n"
        "          [--obfuscate-bytes N] (mask only the first N payload bytes\n"
        "          of each packet instead of all of them; enough to break the\n"
        "          protocol signature at a fraction of the CPU cost; 0 = whole\n"
        "          payload, the default. The 8-byte header is always masked in\n"
        "          full regardless)\n"
        "\n"
        "  --config <file>  read options from a file instead of (or in addition\n"
        "                   to) the flags above: one \"key = value\" per line,\n"
        "                   using the long option names without \"--\"; \"#\"\n"
        "                   starts a comment, a leading \"[name]\" line is\n"
        "                   allowed and ignored. Repeat \"pppd-arg = ...\" for\n"
        "                   multiple pppd arguments.\n",
        prog, prog);
}

typedef struct {
    int have_mode, have_role, have_key, have_pppd;
    int have_listen, have_peer, have_local, have_target, have_lan_bridge;
    int extra_n;
} parse_flags_t;

static int apply_option(const char *name, const char *val, config_t *cfg, parse_flags_t *f) {
    if (strcmp(name, "mode") == 0) {
        if (strcmp(val, "ppp") == 0) cfg->mode = MODE_PPP;
        else if (strcmp(val, "relay") == 0) cfg->mode = MODE_RELAY;
        else { log(LL_ERROR, "mode must be ppp or relay"); return -1; }
        f->have_mode = 1;
    } else if (strcmp(name, "role") == 0) {
        if (strcmp(val, "client") == 0) cfg->role = ROLE_CLIENT;
        else if (strcmp(val, "server") == 0) cfg->role = ROLE_SERVER;
        else if (strcmp(val, "keenetic") == 0) cfg->role = ROLE_KEENETIC;
        else { log(LL_ERROR, "role must be client, server or keenetic"); return -1; }
        f->have_role = 1;
    } else if (strcmp(name, "listen") == 0) {
        if (parse_hostport(val, cfg->bind_host, sizeof(cfg->bind_host), &cfg->bind_port) != 0) {
            log(LL_ERROR, "listen expects host:port"); return -1;
        }
        f->have_listen = 1;
    } else if (strcmp(name, "peer") == 0) {
        if (parse_hostport(val, cfg->peer_host, sizeof(cfg->peer_host), &cfg->peer_port) != 0) {
            log(LL_ERROR, "peer expects host:port"); return -1;
        }
        f->have_peer = 1;
    } else if (strcmp(name, "local") == 0) {
        if (parse_hostport(val, cfg->local_host, sizeof(cfg->local_host), &cfg->local_port) != 0) {
            log(LL_ERROR, "local expects host:port"); return -1;
        }
        f->have_local = 1;
    } else if (strcmp(name, "target") == 0) {
        if (parse_hostport(val, cfg->target_host, sizeof(cfg->target_host), &cfg->target_port) != 0) {
            log(LL_ERROR, "target expects host:port"); return -1;
        }
        f->have_target = 1;
    } else if (strcmp(name, "key") == 0) {
        strncpy(cfg->key, val, sizeof(cfg->key) - 1);
        cfg->key_len = (int)strlen(cfg->key);
        f->have_key = 1;
    } else if (strcmp(name, "session-id") == 0) {
        strncpy(cfg->session_id, val, sizeof(cfg->session_id) - 1);
    } else if (strcmp(name, "pppd") == 0) {
        strncpy(cfg->pppd_path, val, sizeof(cfg->pppd_path) - 1);
        f->have_pppd = 1;
    } else if (strcmp(name, "pppd-arg") == 0) {
        if (f->extra_n >= MAX_EXTRA_ARGS) { log(LL_ERROR, "too many pppd-arg"); return -1; }
        char *copy = strdup(val);
        if (!copy) { log(LL_ERROR, "out of memory"); return -1; }
        cfg->pppd_extra_argv[f->extra_n++] = copy;
    } else if (strcmp(name, "max-clients") == 0) {
        cfg->max_clients = atoi(val);
    } else if (strcmp(name, "idle-timeout") == 0) {
        cfg->idle_timeout_s = atoi(val);
    } else if (strcmp(name, "lan-bridge") == 0) {
        strncpy(cfg->lan_bridge, val, sizeof(cfg->lan_bridge) - 1);
        f->have_lan_bridge = 1;
    } else if (strcmp(name, "lan-prefix") == 0) {
        cfg->lan_prefix = atoi(val);
    } else if (strcmp(name, "verbose") == 0) {
        int level = log_parse_level(val);
        if (level < 0) { log(LL_ERROR, "verbose must be error|warn|info|debug|trace or 0-4"); return -1; }
        g_verbose = level;
    } else if (strcmp(name, "obfuscate-bytes") == 0) {
        cfg->obfuscate_bytes = atoi(val);
    } else {
        log(LL_ERROR, "unknown option: %s", name);
        return -1;
    }
    return 0;
}

static char *trim(char *s) {
    while (*s == ' ' || *s == '\t') s++;
    size_t len = strlen(s);
    while (len > 0 && (s[len - 1] == ' ' || s[len - 1] == '\t' ||
                        s[len - 1] == '\r' || s[len - 1] == '\n')) s[--len] = '\0';
    return s;
}

static int read_config_file(const char *path, config_t *cfg, parse_flags_t *f) {
    FILE *fp = fopen(path, "r");
    if (!fp) { serror("%s", path); return -1; }

    log(LL_DEBUG, "reading config file %s", path);
    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        char *hash = strchr(line, '#');
        if (hash) *hash = '\0';
        char *p = trim(line);
        if (!*p || p[0] == '[') continue;

        char *eq = strchr(p, '=');
        if (!eq) {
            log(LL_ERROR, "%s: invalid line (expected \"key = value\"): %s", path, p);
            fclose(fp);
            return -1;
        }
        *eq = '\0';
        char *key = trim(p);
        char *val = trim(eq + 1);
        if (!*key || !*val) {
            log(LL_ERROR, "%s: invalid line (empty key or value)", path);
            fclose(fp);
            return -1;
        }
        log(LL_TRACE, "%s: %s = %s", path, key, val);
        if (apply_option(key, val, cfg, f) != 0) {
            log(LL_ERROR, "%s: while parsing \"%s\"", path, key);
            fclose(fp);
            return -1;
        }
    }
    fclose(fp);
    return 0;
}

static int parse_args(int argc, char **argv, config_t *cfg) {
    memset(cfg, 0, sizeof(*cfg));
    cfg->max_clients = 8;
    cfg->idle_timeout_s = 300;
    cfg->lan_prefix = 24;
    parse_flags_t f = {0};

    enum { OPT_MODE = 256, OPT_ROLE, OPT_LISTEN, OPT_PEER, OPT_LOCAL, OPT_TARGET,
           OPT_KEY, OPT_SESSION_ID, OPT_PPPD, OPT_PPPD_ARG, OPT_MAX_CLIENTS, OPT_IDLE_TIMEOUT,
           OPT_LAN_BRIDGE, OPT_LAN_PREFIX, OPT_VERBOSE, OPT_OBFUSCATE_BYTES, OPT_CONFIG, OPT_HELP };
    static struct option long_opts[] = {
        {"mode", required_argument, 0, OPT_MODE},
        {"role", required_argument, 0, OPT_ROLE},
        {"listen", required_argument, 0, OPT_LISTEN},
        {"peer", required_argument, 0, OPT_PEER},
        {"local", required_argument, 0, OPT_LOCAL},
        {"target", required_argument, 0, OPT_TARGET},
        {"key", required_argument, 0, OPT_KEY},
        {"session-id", required_argument, 0, OPT_SESSION_ID},
        {"pppd", required_argument, 0, OPT_PPPD},
        {"pppd-arg", required_argument, 0, OPT_PPPD_ARG},
        {"max-clients", required_argument, 0, OPT_MAX_CLIENTS},
        {"idle-timeout", required_argument, 0, OPT_IDLE_TIMEOUT},
        {"lan-bridge", required_argument, 0, OPT_LAN_BRIDGE},
        {"lan-prefix", required_argument, 0, OPT_LAN_PREFIX},
        {"verbose", required_argument, 0, OPT_VERBOSE},
        {"obfuscate-bytes", required_argument, 0, OPT_OBFUSCATE_BYTES},
        {"config", required_argument, 0, OPT_CONFIG},
        {"help", no_argument, 0, OPT_HELP},
        {0, 0, 0, 0}
    };

    static const char *name_of[] = {
        [OPT_MODE] = "mode", [OPT_ROLE] = "role", [OPT_LISTEN] = "listen",
        [OPT_PEER] = "peer", [OPT_LOCAL] = "local", [OPT_TARGET] = "target",
        [OPT_KEY] = "key", [OPT_SESSION_ID] = "session-id",
        [OPT_PPPD] = "pppd", [OPT_PPPD_ARG] = "pppd-arg",
        [OPT_MAX_CLIENTS] = "max-clients", [OPT_IDLE_TIMEOUT] = "idle-timeout",
        [OPT_LAN_BRIDGE] = "lan-bridge", [OPT_LAN_PREFIX] = "lan-prefix",
        [OPT_VERBOSE] = "verbose", [OPT_OBFUSCATE_BYTES] = "obfuscate-bytes",
    };

    int c;
    while ((c = getopt_long(argc, argv, "", long_opts, NULL)) != -1) {
        if (c == OPT_CONFIG) {
            if (read_config_file(optarg, cfg, &f) != 0) return -1;
        } else if (c == OPT_HELP || c < OPT_MODE || c > OPT_OBFUSCATE_BYTES) {
            usage(argv[0]);
            return -1;
        } else if (apply_option(name_of[c], optarg, cfg, &f) != 0) {
            return -1;
        }
    }
    cfg->pppd_extra_argv[f.extra_n] = NULL;

    if (!f.have_mode || !f.have_role || !f.have_key) { usage(argv[0]); return -1; }

    if (cfg->role == ROLE_SERVER && cfg->session_id[0]) {
        log(LL_ERROR, "session-id is a client-side option, the server learns it from each client");
        return -1;
    }

    if (cfg->mode == MODE_PPP) {
        if (cfg->role == ROLE_KEENETIC) { log(LL_ERROR, "role=keenetic is only valid with mode=relay"); return -1; }
        if (!f.have_pppd) { log(LL_ERROR, "mode=ppp requires pppd"); return -1; }
        if (cfg->role == ROLE_CLIENT && !f.have_peer) { log(LL_ERROR, "role=client requires peer"); return -1; }
        if (cfg->role == ROLE_SERVER && !f.have_listen) { log(LL_ERROR, "role=server requires listen"); return -1; }
    } else {
        if (cfg->role == ROLE_CLIENT && !(f.have_local && f.have_peer)) {
            log(LL_ERROR, "mode=relay role=client requires local and peer"); return -1;
        }
        if (cfg->role == ROLE_SERVER && !(f.have_listen && f.have_target)) {
            log(LL_ERROR, "mode=relay role=server requires listen and target"); return -1;
        }
        if (cfg->role == ROLE_KEENETIC) {
            if (!(f.have_local && f.have_peer && f.have_lan_bridge)) {
                log(LL_ERROR, "mode=relay role=keenetic requires local, peer and lan-bridge"); return -1;
            }
            if (cfg->lan_prefix < 1 || cfg->lan_prefix > 32) {
                log(LL_ERROR, "lan-prefix must be between 1 and 32"); return -1;
            }
        }
    }
    return 0;
}

static const char *mode_name(app_mode_t m) { return m == MODE_PPP ? "ppp" : "relay"; }
static const char *role_name(role_t r) {
    switch (r) { case ROLE_CLIENT: return "client"; case ROLE_SERVER: return "server"; default: return "keenetic"; }
}

int main(int argc, char **argv) {
    config_t cfg;
    if (parse_args(argc, argv, &cfg) != 0) return 1;

    g_log_tag = role_name(cfg.role);

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    signal(SIGPIPE, SIG_IGN);

    log(LL_INFO, "starting: mode=%s role=%s", mode_name(cfg.mode), role_name(cfg.role));

    if (wire_keystream_init(cfg.key, cfg.key_len, cfg.obfuscate_bytes) != 0) return 1;
    warn_small_tcp_buffers();

    if (cfg.mode == MODE_PPP) return ppp_mode_run(&cfg);

    if (cfg.role == ROLE_KEENETIC) {
        if (netif_keenetic_setup(cfg.lan_bridge, cfg.local_host, cfg.lan_prefix) != 0) {
            log(LL_ERROR, "role=keenetic: failed to set up %s on bridge %s", cfg.local_host, cfg.lan_bridge);
            return 1;
        }
        int rc = relay_mode_run(&cfg);
        netif_keenetic_teardown();
        log(LL_INFO, "stopped");
        return rc;
    }
    int rc = relay_mode_run(&cfg);
    log(LL_INFO, "stopped");
    return rc;
}
