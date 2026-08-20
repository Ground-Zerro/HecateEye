#ifndef _CONFIG_H_
#define _CONFIG_H_

#define MAX_EXTRA_ARGS 32

typedef enum { MODE_PPP, MODE_RELAY } app_mode_t;
typedef enum { ROLE_CLIENT, ROLE_SERVER, ROLE_KEENETIC } role_t;

typedef struct {
    app_mode_t mode;
    role_t role;

    char bind_host[128];
    int bind_port;
    char peer_host[128];
    int peer_port;
    char local_host[128];
    int local_port;
    char target_host[128];
    int target_port;

    char lan_bridge[64];
    int lan_prefix;

    char key[256];
    int key_len;

    char session_id[64];

    char pppd_path[256];
    char *pppd_extra_argv[MAX_EXTRA_ARGS + 1];

    int max_clients;
    int idle_timeout_s;
    int obfuscate_bytes;
} config_t;

#endif
