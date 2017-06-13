#include "com_choury_sproxy_Service.h"
#include "vpn.h"

#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>


static JavaVM *jnijvm;
static jobject jniobj;
static VpnConfig vpn;

/*
 * Class:     com_choury_sproxy_SproxyVpnService
 * Method:    start
 * Signature: (ILjava/lang/String;)V
 */
JNIEXPORT void JNICALL Java_com_choury_sproxy_SproxyVpnService_start
        (JNIEnv *env, jobject obj, jint sockfd, jstring server) {
    env->GetJavaVM(&jnijvm);
    jniobj = env->NewGlobalRef(obj);
    LOG("native SproxyVpnService.start %d.", sockfd);
    int flags  = fcntl(sockfd,F_GETFL,0);
    fcntl(sockfd,F_SETFL,flags&~O_NONBLOCK);

    const char *server_str = env->GetStringUTFChars(server, 0);

    vpn.disable_ipv6 = 1;
    vpn.ignore_cert_error = 1;
    sprintf(vpn.server, "dtls://%s", server_str);
    env->ReleaseStringUTFChars(server, server_str);
    vpn.fd = sockfd;
    env->DeleteLocalRef(server);
    vpn_start(&vpn);
}

JNIEXPORT void JNICALL Java_com_choury_sproxy_SproxyVpnService_stop(JNIEnv *, jobject){
    LOG("native SproxyVpnService.stop.");
    return vpn_stop();
}

JNIEXPORT void JNICALL Java_com_choury_sproxy_SproxyVpnService_reset(JNIEnv *, jobject) {
    LOG("native SproxyVpnService.reset.");
    return vpn_reset();
}

/*
 * call back to java to
 * protect fd so that the socket can access internet
 */
int protectFd(int sockfd) {
    JNIEnv *jnienv;
    jnijvm->GetEnv((void **)&jnienv, JNI_VERSION_1_6);
    jclass cls = jnienv->GetObjectClass(jniobj);
    jmethodID mid = jnienv->GetMethodID(cls, "protect", "(I)Z");
    int ret =  jnienv->CallBooleanMethod(jniobj, mid, sockfd);
    jnienv->DeleteLocalRef(cls);
    return ret;
}

const char* getpackagename(int uid) {
    static char name[DOMAINLIMIT];
    JNIEnv *jnienv;
    jnijvm->GetEnv((void **)&jnienv, JNI_VERSION_1_6);
    jclass cls = jnienv->GetObjectClass(jniobj);
    jmethodID mid = jnienv->GetMethodID(cls, "getPackageName", "(I)Ljava/lang/String;");
    jstring jname = (jstring)jnienv->CallObjectMethod(jniobj, mid, uid);
    const char *jname_str = jnienv->GetStringUTFChars(jname, 0);
    strcpy(name, jname_str);
    jnienv->ReleaseStringUTFChars(jname, jname_str);
    jnienv->DeleteLocalRef(jname);
    jnienv->DeleteLocalRef(cls);
    return name;
}
