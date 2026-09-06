#include "com_choury_sproxy_Service.h"
#include "misc/strategy.h"
#include "misc/config.h"
#include "req/guest_vpn.h"
#include "req/rguest2.h"
#include "req/rguest3.h"
#include "req/cli.h"

#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <time.h>
#include <cerrno>
#include <cstring>
#include <iostream>
#include <map>
#include <mutex>
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

static void log_open(const std::string& cachedir);

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

std::string getExternalCacheDir() {
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
    if(opt.rproxy_name) {
#ifdef HAVE_QUIC
        // 根据协议选择rguest2还是rguest3
        if(strcmp(opt.rproxy_server.protocol, "quic") == 0) {
            LOG("Starting rproxy3 client to %s\n", dumpDest(opt.rproxy_server).c_str());
            new Rguest3(opt.rproxy_server, opt.rproxy_name);
        } else
#endif
        {
            LOG("Starting rproxy2 client to %s\n", dumpDest(opt.rproxy_server).c_str());
            new Rguest2(opt.rproxy_server, opt.rproxy_name);
        }
    }
    new Guest_vpn(opt.tun_fd, false);
    LOG("Accepting connections ...\n");
    will_contiune = 1;
    while (will_contiune) {
        uint32_t msec = 0;
        while(msec ==0) msec = do_delayjob();
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
    log_open(getExternalCacheDir());

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
    return exit_loop(0);
}

extern "C" JNIEXPORT void JNICALL Java_com_choury_sproxy_SproxyVpnService_reload_1strategy(JNIEnv *, jobject){
    LOG("native SproxyVpnService.reload strategy.\n");
    return reloadstrategy();
}

/*
 * call back to java to
 * protect fd so that the socket can access internet
 */
int protectFd(int sockfd, const sockaddr_storage*) {
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

/*
 * 日志后端：android_vlog 的统一出口，三个 sink：
 *   - logcat：所有级别（含 DEBUG），统一 tag
 *   - 内存环形缓冲：最近 RING_LIMIT 字节，供 UI 经 getLogTail 拉取
 *   - vpn.log：常开 fd 追加写，超过 LOG_ROTATE_SZ 轮转为 vpn.log.1
 * 日志路径不碰 JNI，VPN 停止后残留的写线程不会因 jniobj 置空而崩溃。
 */
static constexpr const char* LOG_TAG  = "sproxy";
static constexpr size_t RING_LIMIT    = 256 * 1024;
static constexpr off_t  LOG_ROTATE_SZ = 4 * 1024 * 1024;

static std::mutex log_mtx;
static int         log_fd = -1;
static off_t       log_size = 0;
static std::string log_path;
static std::string log_ring;

static void log_open(const std::string& cachedir){
    std::lock_guard<std::mutex> lg(log_mtx);
    if(log_fd >= 0){
        close(log_fd);
        log_fd = -1;
    }
    log_path = cachedir + "/vpn.log";
    log_fd = open(log_path.c_str(), O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0644);
    struct stat st{};
    log_size = (log_fd >= 0 && fstat(log_fd, &st) == 0) ? st.st_size : 0;
}

// caller holds log_mtx
static void log_write_file_locked(const char* line, size_t len){
    if(log_fd < 0){
        return;
    }
    if(log_size + (off_t)len > LOG_ROTATE_SZ){
        close(log_fd);
        std::string rotated = log_path + ".1";
        unlink(rotated.c_str());
        if(rename(log_path.c_str(), rotated.c_str()) != 0){
            // 不能用 LOG：会经 android_vlog 递归抢 log_mtx 死锁
            __android_log_print(ANDROID_LOG_ERROR, LOG_TAG,
                                "failed to rotate %s: %s\n", log_path.c_str(), strerror(errno));
        }
        log_fd = open(log_path.c_str(), O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0644);
        log_size = 0;
        if(log_fd < 0){
            return;
        }
    }
    ssize_t w = write(log_fd, line, len);
    if(w > 0){
        log_size += w;
    }
}

// caller holds log_mtx
static void log_ring_append_locked(const std::string& line){
    log_ring.append(line);
    if(log_ring.size() > RING_LIMIT){
        // 从头部裁到下一个整行边界，保证缓冲里只有完整行
        size_t drop = log_ring.size() - RING_LIMIT;
        size_t nl = log_ring.find('\n', drop);
        drop = (nl == std::string::npos) ? log_ring.size() : nl + 1;
        log_ring.erase(0, drop);
    }
}

// 统一行格式 "L MM-DD HH:MM:SS.mmm msg"，logcat 只输出 msg 本身
static void log_dispatch(int priority, char prefix, const char* msg, size_t len, bool to_logcat){
    if(to_logcat){
        __android_log_print(priority, LOG_TAG, "%.*s", (int)len, msg);
    }
    struct timespec ts{};
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm tmv{};
    localtime_r(&ts.tv_sec, &tmv);
    char head[40];
    int hn = snprintf(head, sizeof(head), "%c %02d-%02d %02d:%02d:%02d.%03d ",
                      prefix, tmv.tm_mon + 1, tmv.tm_mday,
                      tmv.tm_hour, tmv.tm_min, tmv.tm_sec, (int)(ts.tv_nsec / 1000000));
    std::string line;
    line.reserve(hn + len + 2);
    line.append(head, hn);
    line.append(msg, len);
    line.push_back('\n');
    std::lock_guard<std::mutex> lg(log_mtx);
    log_ring_append_locked(line);
    log_write_file_locked(line.data(), line.size());
}

void android_vlog(int level, const char* fmt, va_list args){
    android_LogPriority priority;
    char prefix;
    switch(level){
    case LOG_INFO:
        priority = ANDROID_LOG_INFO;
        prefix = 'I';
        break;
    case LOG_ERR:
        priority = ANDROID_LOG_ERROR;
        prefix = 'E';
        break;
    case LOG_WARNING:
        priority = ANDROID_LOG_WARN;
        prefix = 'W';
        break;
    case LOG_DEBUG:
        priority = ANDROID_LOG_DEBUG;
        prefix = 'D';
        break;
    default:
        priority = ANDROID_LOG_DEFAULT;
        prefix = 'V';
    }
    char msg[8192];
    int n = vsnprintf(msg, sizeof(msg), fmt, args);
    if(n < 0){
        return;
    }
    if(n >= (int)sizeof(msg)){
        n = sizeof(msg) - 1;
    }
    // 消息自身常以 \n 结尾，去掉后由 log_dispatch 保证恰好一个结尾换行
    while(n > 0 && msg[n-1] == '\n'){
        n--;
    }
    msg[n] = '\0';
    log_dispatch(priority, prefix, msg, n, true);
}

void android_log(int level, const char* fmt, ...){
    va_list args;
    va_start(args, fmt);
    android_vlog(level, fmt, args);
    va_end(args);
}

extern "C" JNIEXPORT jbyteArray JNICALL Java_com_choury_sproxy_SproxyVpnService_getLogTail
        (JNIEnv* env, jclass, jint maxBytes){
    std::string tail;
    {
        std::lock_guard<std::mutex> lg(log_mtx);
        if(maxBytes > 0 && (size_t)maxBytes < log_ring.size()){
            // 从 maxBytes 边界后的第一个整行起点开始取，保证行完整
            size_t start = log_ring.size() - maxBytes;
            size_t nl = log_ring.find('\n', start);
            start = (nl == std::string::npos) ? start : nl + 1;
            tail = log_ring.substr(start);
        }else{
            tail = log_ring;
        }
    }
    jbyteArray arr = env->NewByteArray(tail.size());
    if(arr == nullptr){
        return nullptr;
    }
    env->SetByteArrayRegion(arr, 0, tail.size(), (const jbyte*)tail.data());
    return arr;
}

extern "C" JNIEXPORT void JNICALL Java_com_choury_sproxy_SproxyVpnService_clearLog
        (JNIEnv*, jclass){
    std::lock_guard<std::mutex> lg(log_mtx);
    log_ring.clear();
}

// Java 层日志汇入环形缓冲与 vpn.log；logcat 由 Java 侧 android.util.Log 输出
extern "C" JNIEXPORT void JNICALL Java_com_choury_sproxy_SproxyVpnService_log
        (JNIEnv* env, jclass, jint level, jstring jmsg){
    const char* msg = env->GetStringUTFChars(jmsg, nullptr);
    if(msg == nullptr){
        return;
    }
    char prefix;
    switch(level){
    case 3:  prefix = 'D'; break; // Log.DEBUG
    case 4:  prefix = 'I'; break; // Log.INFO
    case 5:  prefix = 'W'; break; // Log.WARN
    case 6:  prefix = 'E'; break; // Log.ERROR
    default: prefix = 'V'; break;
    }
    log_dispatch(ANDROID_LOG_DEBUG, prefix, msg, strlen(msg), false);
    env->ReleaseStringUTFChars(jmsg, msg);
}
