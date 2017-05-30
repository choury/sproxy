#include "com_choury_sproxy_Service.h"
#include "vpn.h"

#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>


static JavaVM *jnijvm;
static jobject jniobj;

/*
 * Class:     com_choury_sproxy_SproxyVpnService
 * Method:    start
 * Signature: (I)V
 */
JNIEXPORT void JNICALL Java_com_choury_sproxy_SproxyVpnService_start
        (JNIEnv *env, jobject obj, jint sockfd) {
    env->GetJavaVM(&jnijvm);
    jniobj = env->NewGlobalRef(obj);
    LOG("native CapCapture.startCapture %d.", sockfd);
    int flags  = fcntl(sockfd,F_GETFL,0);
    fcntl(sockfd,F_SETFL,flags&~O_NONBLOCK);

    struct VpnConfig vpn;
    vpn.disable_ipv6 = 1;
    vpn.ignore_cert_error = 0;
    vpn.server="a.choury.com";
    vpn.fd = sockfd;

    pthread_t thread_recv;
    pthread_create(&thread_recv, NULL, (void *(*)(void*))(vpn_start), (void *)&vpn);
    pthread_join(thread_recv, NULL);
}

/*
 * call back to java to
 * protect fd so that the socket can access internet
 */
int protectFd(int sockfd) {
    JNIEnv *jnienv;
    if(jnijvm->AttachCurrentThread(&jnienv, NULL) != JNI_OK){
        LOGE("AttachCurrentThread failed\n");
        return 0;
    }
    jclass cls = jnienv->GetObjectClass(jniobj);
    jmethodID mid = jnienv->GetMethodID(cls, "protect", "(I)Z");
    int ret = jnienv->CallBooleanMethod(jniobj, mid, sockfd);
    jnijvm->DetachCurrentThread();
    return ret;
}
