#ifndef NETWORK_NOTIFY_H__
#define NETWORK_NOTIFY_H__

#ifdef  __cplusplus
extern "C" {
#endif

int notify_network_change(int notify);

typedef void (*network_notify_callback)(void);
int register_network_change_cb(network_notify_callback cb);



#ifdef  __cplusplus
}
#endif

#endif
