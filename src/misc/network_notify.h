#ifndef NETWORK_NOTIFY_H__
#define NETWORK_NOTIFY_H__

#ifdef  __cplusplus
extern "C" {
#endif

int create_notifier_fd();
int have_network_changed(int fd);

typedef void (*network_notify_callback)();
int register_network_change_cb(network_notify_callback cb);



#ifdef  __cplusplus
}
#endif

#endif
