#ifndef NETWORK_NOTIFY_H__
#define NETWORK_NOTIFY_H__

typedef void (*network_notify_callback)(void);
int notify_network_change(network_notify_callback cb);

#endif