#ifndef _NETIF_H_
#define _NETIF_H_

int netif_keenetic_setup(const char *bridge, const char *ip, int prefix);
void netif_keenetic_teardown(void);

#endif
