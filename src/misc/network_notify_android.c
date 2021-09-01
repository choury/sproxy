#include "network_notify.h"
#include "common/common.h"

#include <jni.h>
#include <unistd.h>

static int notify_ = -1;

JNIEXPORT void JNICALL Java_com_choury_sproxy_SproxyVpnService_network_1notify(JNIEnv* env, jobject obj) {
    (void)env;
    (void)obj;
    LOG("native SproxyVpnService network_notify.\n");
    if(notify_ >= 0)
        write(notify_, "1", 1);
}

int notify_network_change(int notify){
    notify_ = notify;
    return 0;
}
