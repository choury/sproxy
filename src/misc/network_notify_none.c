#include "network_notify.h"
#include "common/common.h"

int notify_network_change(network_notify_callback cb){
    LOGD(DNET, "use none network notify\n");
    (void)cb;
    return 0;
}
