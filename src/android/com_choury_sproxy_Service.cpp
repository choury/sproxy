#include "com_choury_sproxy_Service.h"
#include "misc/strategy.h"
#include "misc/config.h"
#include "req/guest_vpn.h"
#include "req/cli.h"

#include <unistd.h>
#include <fcntl.h>
#include <iostream>
#include <map>
#include <vector>
#include <iomanip>
#include <fstream>
#include <android/log.h>
#include <android/file_descriptor_jni.h>
#include <sys/system_properties.h>
#include <misc/util.h>

static JavaVM *jnijvm;
static jobject jniobj;
static std::string extenalFilesDir;
static std::string extenalCacheDir;
char   appVersion[DOMAINLIMIT];

std::string getExternalFilesDir() {
    if(!extenalFilesDir.empty()){
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

    const char *path_str = jnienv->GetStringUTFChars(Path_obj, nullptr);

    extenalFilesDir = path_str;
    jnienv->ReleaseStringUTFChars(Path_obj, path_str);
    jnienv->DeleteLocalRef(Path_obj);
    jnienv->DeleteLocalRef(File_obj);
    jnienv->DeleteLocalRef(File_cls);
    jnienv->DeleteLocalRef(cls);
    return extenalFilesDir;
}

static std::string getExternalCacheDir() {
    if(!extenalCacheDir.empty()){
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

    const char *path_str = jnienv->GetStringUTFChars(Path_obj, nullptr);

    extenalCacheDir = path_str;
    jnienv->ReleaseStringUTFChars(Path_obj, path_str);
    jnienv->DeleteLocalRef(Path_obj);
    jnienv->DeleteLocalRef(File_obj);
    jnienv->DeleteLocalRef(File_cls);
    jnienv->DeleteLocalRef(cls);
    return extenalCacheDir;
}

static int vpn_start(){
    std::shared_ptr<Cli_server> cli;
    if(opt.admin.hostname[0]){
        int svsk_cli = -1;
        if(opt.admin.port){
            sockaddr_storage addr{};
            if(storage_aton(opt.admin.hostname, opt.admin.port, &addr) == 0) {
                LOGE("failed to parse admin addr: %s\n", opt.admin.hostname);
                return -1;
            }
            svsk_cli = ListenTcp(&addr, nullptr);
        }else{
            svsk_cli = ListenUnix(opt.admin.hostname, nullptr);
        }
        if(svsk_cli < 0){
            return -1;
        }
        cli = std::make_shared<Cli_server>(svsk_cli);
    }
    new Guest_vpn(opt.tun_fd, false);
    LOG("Accepting connections ...\n");
    will_contiune = 1;
    while (will_contiune) {
        uint32_t msec = do_delayjob();
        if(event_loop(msec) < 0){
            break;
        }
    }
    LOG("VPN exiting ...\n");
    neglect();
    return 0;
}
/*
 * Class:     com_choury_sproxy_SproxyVpnService
 * Method:    start
 * Signature: (ILjava/lang/String;)V
 */
extern "C" JNIEXPORT void JNICALL Java_com_choury_sproxy_SproxyVpnService_start
        (JNIEnv *jnienv, jobject obj, jint sockfd, jstring server, jstring secret) {
    jnienv->GetJavaVM(&jnijvm);
    jniobj = jnienv->NewGlobalRef(obj);
    std::string config_file = getExternalFilesDir() + "/sproxy.conf";
    std::string sites_file = getExternalFilesDir() + "/sites.list";
    std::string pcap_file = getExternalCacheDir() + "/vpn.pcap";

    if(access(config_file.c_str(), R_OK) == 0){
        LOG("read config from %s.\n", config_file.c_str());
        parseConfigFile(config_file.c_str());
    }
    opt.policy_read = fopen(sites_file.c_str(), "re");
    opt.pcap_len = 200;
    //opt.pcap_file = pcap_file.c_str();
    const char *server_str = jnienv->GetStringUTFChars(server, nullptr);
    const char *secret_str = jnienv->GetStringUTFChars(secret, nullptr);
    parseDest(server_str, &opt.Server);
    Base64Encode(secret_str, strlen(secret_str), opt.rewrite_auth);
    postConfig();
    LOG("native SproxyVpnService.start %d.\n", sockfd);

    jnienv->ReleaseStringUTFChars(server, server_str);
    jnienv->ReleaseStringUTFChars(secret, secret_str);

    jnienv->DeleteLocalRef(server);
    jnienv->DeleteLocalRef(secret);

    jclass cls = jnienv->GetObjectClass(jniobj);
    jmethodID mid = jnienv->GetMethodID(cls, "getMyVersion", "()Ljava/lang/String;");
    jstring jversion = (jstring) jnienv->CallObjectMethod(jniobj, mid);
    const char *jversion_str = jnienv->GetStringUTFChars(jversion, nullptr);
    strcpy(appVersion, jversion_str);
    jnienv->ReleaseStringUTFChars(jversion, jversion_str);
    jnienv->DeleteLocalRef(jversion);

    jnienv->DeleteLocalRef(cls);

    opt.tun_fd = sockfd;
    vpn_start();
    extenalCacheDir.clear();
    extenalFilesDir.clear();
    jnienv->DeleteGlobalRef(jniobj);
    jniobj = nullptr;
    jnijvm = nullptr;
}

extern "C" JNIEXPORT void JNICALL Java_com_choury_sproxy_SproxyVpnService_stop(JNIEnv *, jobject){
    LOG("native SproxyVpnService.stop.\n");
    return exit_loop();
}

extern "C" JNIEXPORT void JNICALL Java_com_choury_sproxy_SproxyVpnService_reload_1strategy(JNIEnv *, jobject){
    LOG("native SproxyVpnService.reload strategy.\n");
    return reloadstrategy();
}

/*
 * call back to java to
 * protect fd so that the socket can access internet
 */
int protectFd(int sockfd) {
    JNIEnv *jnienv;
    jnijvm->GetEnv((void **)&jnienv, JNI_VERSION_1_6);
    jclass cls = jnienv->GetObjectClass(jniobj);
    jmethodID protecdMid = jnienv->GetMethodID(cls, "protect", "(I)Z");
    if(android_get_device_api_level() >= 31) {
        //jobject jfd = AFileDescriptor_create(jnienv);
    }
    return  jnienv->CallBooleanMethod(jniobj, protecdMid, sockfd);
}

const char* getPackageNameFromUid(int uid) {
    static char name[DOMAINLIMIT];
    JNIEnv *jnienv;
    jnijvm->GetEnv((void **) &jnienv, JNI_VERSION_1_6);
    jclass cls = jnienv->GetObjectClass(jniobj);
    jmethodID mid = jnienv->GetMethodID(cls, "getPackageFromUid", "(I)Ljava/lang/String;");
    jstring jname = (jstring) jnienv->CallObjectMethod(jniobj, mid, uid);
    const char *jname_str = jnienv->GetStringUTFChars(jname, nullptr);
    strcpy(name, jname_str);
    jnienv->ReleaseStringUTFChars(jname, jname_str);
    jnienv->DeleteLocalRef(jname);
    jnienv->DeleteLocalRef(cls);
    return name;
}

const char* getPackageNameFromAddr(int protocol, const struct sockaddr_storage* src, const struct sockaddr_storage* dst){
    static char name[DOMAINLIMIT];
    JNIEnv *jnienv;
    jnijvm->GetEnv((void **) &jnienv, JNI_VERSION_1_6);
    jclass cls = jnienv->GetObjectClass(jniobj);
    jmethodID mid = jnienv->GetMethodID(cls, "getPackageFromAddr", "(I[BI[BI)Ljava/lang/String;");
    jbyteArray sdata, ddata;
    int sport = ntohs(((sockaddr_in*)src)->sin_port);
    int dport = ntohs(((sockaddr_in*)dst)->sin_port);
    jbyte sbuf[255], dbuf[255];
    if(src->ss_family == AF_INET){
        jsize len = sizeof(in_addr);
        sdata = jnienv->NewByteArray(len);
        ddata = jnienv->NewByteArray(len);
        memcpy(sbuf, &((sockaddr_in*)src)->sin_addr, len);
        memcpy(dbuf, &((sockaddr_in*)dst)->sin_addr, len);

        jnienv->SetByteArrayRegion(sdata, 0, len, sbuf);
        jnienv->SetByteArrayRegion(ddata, 0, len, dbuf);
    }else{
        jsize len = sizeof(in6_addr);
        sdata = jnienv->NewByteArray(len);
        ddata = jnienv->NewByteArray(len);
        memcpy(sbuf, &((sockaddr_in6*)src)->sin6_addr, len);
        memcpy(dbuf, &((sockaddr_in6*)dst)->sin6_addr, len);

        jnienv->SetByteArrayRegion(sdata, 0, len, sbuf);
        jnienv->SetByteArrayRegion(ddata, 0, len, dbuf);
    }
    jstring jname = (jstring) jnienv->CallObjectMethod(jniobj, mid, protocol, sdata, sport, ddata, dport);
    const char *jname_str = jnienv->GetStringUTFChars(jname, nullptr);
    strcpy(name, jname_str);
    jnienv->ReleaseStringUTFChars(jname, jname_str);
    jnienv->DeleteLocalRef(sdata);
    jnienv->DeleteLocalRef(ddata);
    jnienv->DeleteLocalRef(jname);
    jnienv->DeleteLocalRef(cls);
    return name;
}

const char *getDeviceName(){
    static char deviceName[DOMAINLIMIT];
    if(strlen(deviceName)){
        return deviceName;
    }
    char model[PROP_VALUE_MAX];
    __system_property_get("ro.product.model", model);
    char release[PROP_NAME_MAX];
    __system_property_get("ro.build.version.release", release);
    char buildtime[PROP_VALUE_MAX];
    __system_property_get("ro.build.date.utc", buildtime);
    sprintf(deviceName, "Android %s; %s Build/%s", release, model, buildtime);
    return deviceName;
}

std::vector<std::string> getDns(){
    std::vector<std::string> dns;
    JNIEnv *jnienv;
    jnijvm->GetEnv((void **) &jnienv, JNI_VERSION_1_6);
    jclass cls = jnienv->GetObjectClass(jniobj);
    jmethodID mid = jnienv->GetMethodID(cls, "getDns", "()[Ljava/lang/String;");
    jobjectArray jDns = (jobjectArray) jnienv->CallObjectMethod(jniobj, mid);
    if(jDns == nullptr){
        jnienv->DeleteLocalRef(cls);
        return dns;
    }
    int n = jnienv->GetArrayLength(jDns);
    for (int i = 0; i < n; i++) {
        jstring jdns = (jstring) jnienv->GetObjectArrayElement(jDns, i);
        const char *jdns_str = jnienv->GetStringUTFChars(jdns, nullptr);
        dns.emplace_back(jdns_str);
        jnienv->ReleaseStringUTFChars(jdns, jdns_str);
        jnienv->DeleteLocalRef(jdns);
    }
    jnienv->DeleteLocalRef(jDns);
    jnienv->DeleteLocalRef(cls);
    return dns;
}

void android_vlog(int level, const char* fmt, va_list args){
    char prefix;
    switch(level){
    case LOG_INFO:
        level = ANDROID_LOG_INFO;
        prefix = 'I';
        break;
    case LOG_ERR:
        level = ANDROID_LOG_ERROR;
        prefix = 'E';
        break;
    case LOG_DEBUG:
        level = ANDROID_LOG_DEBUG;
        prefix = 'D';
        break;
    default:
        level = ANDROID_LOG_DEFAULT;
        prefix = 'V';
    }
    char printbuff[1024];
    vsnprintf(printbuff, sizeof(printbuff), fmt, args);
    if(level != ANDROID_LOG_DEBUG) {
        __android_log_print(level, "SproxyClient", "%s", printbuff);
    }
    if(jnijvm) {
        std::string cachedir = getExternalCacheDir();
        std::ofstream logfile(cachedir + "/vpn.log", std::ios::app);
        auto now = time(nullptr);
        logfile << prefix << "/" <<std::put_time(std::localtime(&now), "%F %T: ") << printbuff;
        logfile.close();
    }
}

void android_log(int level, const char* fmt, ...){
    va_list args;
    va_start(args, fmt);
    android_vlog(level, fmt, args);
    va_end(args);
}
