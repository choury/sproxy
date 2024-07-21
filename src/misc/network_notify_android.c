#include "network_notify.h"
#include "common/common.h"

#include <jni.h>
#include <unistd.h>
#include <errno.h>

static int notify_ = -1;


int create_notifier_fd() {
    int pipes[2];
    if(pipe(pipes) < 0) {
        LOGE("create pipe failed: %s\n", strerror(errno));
        return -1;
    }
    notify_ = pipes[1];
    return pipes[0];
}


int have_network_changed(int fd) {
    char buff[BUFSIZ];
    while(read(fd, buff, sizeof(buff)) > 0){}
    return 1;
}

JNIEXPORT void JNICALL Java_com_choury_sproxy_SproxyVpnService_network_1notify(JNIEnv* env, jobject obj) {
    (void)env;
    (void)obj;
    LOG("native SproxyVpnService network_notify.\n");
    if(notify_ >= 0)
        write(notify_, "1", 1);
}
