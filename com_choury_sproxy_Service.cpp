#include "com_choury_sproxy_Service.h"
#include "vpn.h"

#include <unistd.h>
#include <fcntl.h>
#include <iostream>
#include <map>
#include <vector>
#include <fstream>
#include <android/log.h>

static JavaVM *jnijvm;
static jobject jniobj;
static VpnConfig vpn;
static std::map<int, std::string> packages;
static std::string extenalFilesDir;
static std::string extenalCacheDir;

/*
 * Class:     com_choury_sproxy_SproxyVpnService
 * Method:    start
 * Signature: (ILjava/lang/String;)V
 */
JNIEXPORT void JNICALL Java_com_choury_sproxy_SproxyVpnService_start
        (JNIEnv *env, jobject obj, jint sockfd, jstring server, jstring secret) {
    env->GetJavaVM(&jnijvm);
    jniobj = env->NewGlobalRef(obj);
    LOG("native SproxyVpnService.start %d.", sockfd);
    int flags  = fcntl(sockfd,F_GETFL,0);
    fcntl(sockfd,F_SETFL,flags&~O_NONBLOCK);

    const char *server_str = env->GetStringUTFChars(server, 0);
    const char *secret_str = env->GetStringUTFChars(secret, 0);

    vpn.disable_ipv6 = 1;
    vpn.ignore_cert_error = 1;
    sprintf(vpn.server, "ssl://%s", server_str);
    strcpy(vpn.secret, secret_str);
    env->ReleaseStringUTFChars(server, server_str);
    env->ReleaseStringUTFChars(secret, secret_str);
    vpn.fd = sockfd;
    env->DeleteLocalRef(server);
    env->DeleteLocalRef(secret);
    vpn_start(&vpn);
    env->DeleteGlobalRef(jniobj);
}

JNIEXPORT void JNICALL Java_com_choury_sproxy_SproxyVpnService_stop(JNIEnv *, jobject){
    LOG("native SproxyVpnService.stop.");
    return vpn_stop();
}

JNIEXPORT void JNICALL Java_com_choury_sproxy_SproxyVpnService_reset(JNIEnv *, jobject){
    LOG("native SproxyVpnService.reset.");
    return vpn_reset();
}

JNIEXPORT void JNICALL Java_com_choury_sproxy_SproxyVpnService_reload(JNIEnv *, jobject){
    LOG("native SproxyVpnService.reload.");
    return vpn_reload();
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
    if(packages.count(uid)){
        strcpy(name, packages[uid].c_str());
    }else {
        JNIEnv *jnienv;
        jnijvm->GetEnv((void **) &jnienv, JNI_VERSION_1_6);
        jclass cls = jnienv->GetObjectClass(jniobj);
        jmethodID mid = jnienv->GetMethodID(cls, "getPackageName", "(I)Ljava/lang/String;");
        jstring jname = (jstring) jnienv->CallObjectMethod(jniobj, mid, uid);
        const char *jname_str = jnienv->GetStringUTFChars(jname, 0);
        strcpy(name, jname_str);
        jnienv->ReleaseStringUTFChars(jname, jname_str);
        jnienv->DeleteLocalRef(jname);
        jnienv->DeleteLocalRef(cls);
    }
    return name;
}

std::vector<std::string> getDns(){
    JNIEnv *jnienv;
    jnijvm->GetEnv((void **) &jnienv, JNI_VERSION_1_6);
    jclass cls = jnienv->GetObjectClass(jniobj);
    jmethodID mid = jnienv->GetMethodID(cls, "getDns", "()[Ljava/lang/String;");
    jobjectArray jDns = (jobjectArray) jnienv->CallObjectMethod(jniobj, mid);
    int n = jnienv->GetArrayLength(jDns);
    std::vector<std::string> dns;
    for(int i=0; i< n; i++){
        jstring jdns=(jstring)jnienv->GetObjectArrayElement(jDns,i);
        const char *jdns_str = jnienv->GetStringUTFChars(jdns, 0);
        dns.push_back(jdns_str);
        jnienv->ReleaseStringUTFChars(jdns, jdns_str);
        jnienv->DeleteLocalRef(jdns);
    }
    jnienv->DeleteLocalRef(jDns);
    jnienv->DeleteLocalRef(cls);
    return dns;
}

std::string getExternalFilesDir() {
    if(extenalFilesDir != ""){
        return extenalFilesDir;
    }
    JNIEnv *jnienv;
    jnijvm->GetEnv((void **)&jnienv, JNI_VERSION_1_6);
    // getExternalFilesDir() - java
    jclass cls = jnienv->GetObjectClass(jniobj);
    jmethodID mid = jnienv->GetMethodID(cls, "getExternalFilesDir",
                                     "(Ljava/lang/String;)Ljava/io/File;");
    jobject File_obj = jnienv->CallObjectMethod(jniobj, mid, NULL);
    jclass File_cls = jnienv->FindClass("java/io/File");
    jmethodID getPath_mid = jnienv->GetMethodID(File_cls, "getPath", "()Ljava/lang/String;");
    jstring Path_obj = (jstring) jnienv->CallObjectMethod(File_obj, getPath_mid);

    const char *path_str = jnienv->GetStringUTFChars(Path_obj, 0);

    extenalFilesDir = path_str;
    jnienv->ReleaseStringUTFChars(Path_obj, path_str);
    jnienv->DeleteLocalRef(Path_obj);
    jnienv->DeleteLocalRef(File_obj);
    jnienv->DeleteLocalRef(cls);
    return extenalFilesDir;
}

std::string getExternalCacheDir() {
    if(extenalCacheDir != ""){
        return extenalCacheDir;
    }
    JNIEnv *jnienv;
    jnijvm->GetEnv((void **)&jnienv, JNI_VERSION_1_6);
    // getExternalCacheDir() - java
    jclass cls = jnienv->GetObjectClass(jniobj);
    jmethodID mid = jnienv->GetMethodID(cls, "getExternalCacheDir", "()Ljava/io/File;");
    jobject File_obj = jnienv->CallObjectMethod(jniobj, mid);
    jclass File_cls = jnienv->FindClass("java/io/File");
    jmethodID getPath_mid = jnienv->GetMethodID(File_cls, "getPath", "()Ljava/lang/String;");
    jstring Path_obj = (jstring) jnienv->CallObjectMethod(File_obj, getPath_mid);

    const char *path_str = jnienv->GetStringUTFChars(Path_obj, 0);

    extenalCacheDir = path_str;
    jnienv->ReleaseStringUTFChars(Path_obj, path_str);
    jnienv->DeleteLocalRef(Path_obj);
    jnienv->DeleteLocalRef(File_obj);
    jnienv->DeleteLocalRef(cls);
    return extenalCacheDir;
}


void android_log(int level, const char* fmt, ...){
    va_list args;
    va_start(args, fmt);
    switch(level){
    case LOG_INFO:
        level = ANDROID_LOG_INFO;
        break;
    case LOG_ERR:
        level = ANDROID_LOG_ERROR;
        break;
    case LOG_DEBUG:
        level = ANDROID_LOG_DEBUG;
        break;
    default:
        level = ANDROID_LOG_DEFAULT;

    }
    char printbuff[1024];
    vsnprintf(printbuff, sizeof(printbuff), fmt, args);
    va_end(args);
    if(level != ANDROID_LOG_DEBUG) {
        __android_log_print(level, "sproxy_client", "%s", printbuff);
    }
    std::string cachedir = getExternalCacheDir();
    std::ofstream logfile(cachedir+"/vpn.log", std::ios::app);
    logfile<<printbuff;
    logfile.close();
}