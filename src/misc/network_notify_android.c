#include <jni.h>

#include "network_notify.h"
#include "common/common.h"

static network_notify_callback cb = NULL;

JNIEXPORT void JNICALL Java_com_choury_sproxy_SproxyVpnService_network_1notify(JNIEnv* env, jobject obj) {
    (void)env;
    (void)obj;
    LOG("native SproxyVpnService network_notify.\n");
    if(cb)
        cb();
}

int notify_network_change(network_notify_callback cb_){
    cb = cb_;
    return 0;
}
