#include "rpc.h"

#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <sys/un.h>
#include <sys/socket.h>

#include <thread>
#include <netinet/in.h>
#include <arpa/inet.h>

typedef unsigned char uchar;
#define get32(a) (((uchar*)(a))[0]<<24 | ((uchar*)(a))[1]<<16 | ((uchar*)(a))[2]<<8 | ((uchar*)(a))[3])
#define set32(a, x) \
do {\
    ((uchar*)(a))[0] = ((x)>>24) & 0xff;\
    ((uchar*)(a))[1] = ((x)>>16) & 0xff;\
    ((uchar*)(a))[2] = ((x)>>8) & 0xff;\
    ((uchar*)(a))[3] = (x) & 0xff;\
}while(0)


bool RpcBase::sendJson(json_object *content) {
    const char* body = json_object_get_string(content);
    size_t len = strlen(body);
    if(len > UINT32_MAX){
        return false;
    }
    char prefix[4];
    set32(prefix, len);
    return send(prefix, 4) && send(body, len);
}

ssize_t RpcServer::DefaultProc(const char *buff, size_t len) {
    if(len <= 6){ //合法的json至少有两字节: "{}"
        return 0;
    }
    size_t body_size = get32(buff);
    if(body_size + 4 > len){
        return 0;
    }
    ssize_t ret = 4 + body_size;

    struct json_tokener *tok = json_tokener_new();
    json_object* jres = nullptr, *jmethod;
    //fprintf(stderr, "%.*s\n", (int)body_size, buff+4);
    json_object* jreq = json_tokener_parse_ex(tok, buff + 4, body_size);
    if(jreq == nullptr) {
        jres = json_object_new_object();
        json_object_object_add(jres, "error", json_object_new_string(json_tokener_error_desc(json_tokener_get_error(tok))));
        goto out;
    }
    jmethod = json_object_object_get(jreq, "method");
    if(jmethod == nullptr) {
        jres = json_object_new_object();
        json_object_object_add(jres, "error", json_object_new_string("no method field found"));
        goto out;
    }
    jres = call(json_object_get_string(jmethod), jreq);
    if(jres == nullptr){
        jres = json_object_new_object();
        json_object_object_add(jres, "error", json_object_new_string("no such method"));
        goto out;
    }
out:
    if(jreq)
        json_object_put(jreq);
    if(jres) {
        sendJson(jres);
        json_object_put(jres);
    }

    json_tokener_free(tok);
    return ret;
}


ssize_t RpcClient::DefaultProc(const char *buff, size_t len) {
    if(len <= 6){
        return 0;
    }
    size_t body_size = get32(buff);
    if(body_size + 4 > len){
        return 0;
    }
    struct json_tokener *tok = json_tokener_new();
    json_object* jres = nullptr;
    //fprintf(stderr, "%.*s\n", (int)body_size, buff+4);

    if((jres = json_tokener_parse_ex(tok, buff + 4, body_size)) == nullptr){
        jres = json_object_new_object();
        json_object_object_add(jres, "error", json_object_new_string(json_tokener_error_desc(json_tokener_get_error(tok))));
    }
    if(!responser.empty()){
        responser.front()(jres);
        responser.pop();
    } else {
        fprintf(stderr, "no response callback\n");
    }
    json_object_put(jres);
    json_tokener_free(tok);
    return body_size + 4;
}

void RpcClient::call(const std::string& method, json_object* body, const std::function<void(json_object *)>& response) {
    json_object_object_add(body, "method", json_object_new_string(method.c_str()));
    responser.push(response);
    if(!sendJson(body)){
        responser.pop();
        json_object* jres = json_object_new_object();
        json_object_object_add(jres, "error", json_object_new_string("send failed"));
        response(jres);
        json_object_put(jres);
    }
}

json_object * SproxyServer::call(std::string method, json_object* content) {
    json_object* jres = json_object_new_object();
    if(method == "AddStrategy") {
        json_object* jhost = json_object_object_get(content, "host");
        json_object* jstrategy = json_object_object_get(content, "strategy");
        json_object* jext = json_object_object_get(content, "ext");
        if(!jhost || !jstrategy || !jext ){
            json_object_object_add(jres, "error", json_object_new_string("require some params"));
            return jres;
        }
        auto ok = AddStrategy(json_object_get_string(jhost), json_object_get_string(jstrategy), json_object_get_string(jext));
        json_object_object_add(jres, "ok", json_object_new_boolean(ok));
    }else if(method == "DelStrategy") {
        json_object* jhost = json_object_object_get(content, "host");
        if(!jhost){
            json_object_object_add(jres, "error", json_object_new_string("require some params"));
            return jres;
        }
        auto ok = DelStrategy(json_object_get_string(jhost));
        json_object_object_add(jres, "ok", json_object_new_boolean(ok));
    }else if(method == "TestStrategy") {
        json_object* jhost = json_object_object_get(content, "host");
        if(!jhost){
            json_object_object_add(jres, "error", json_object_new_string("require some params"));
            return jres;
        }
        auto strategy = TestStrategy(json_object_get_string(jhost));
        json_object_object_add(jres, "strategy", json_object_new_string(strategy.c_str()));
    }else if(method == "DumpStrategy") {
        auto lists = DumpStrategy();
        json_object* jlist = json_object_new_array();
        for(const auto& strategy : lists){
            json_object_array_add(jlist, json_object_new_string(strategy.c_str()));
        }
        json_object_object_add(jres, "strategies", jlist);
    }else if(method == "FlushCgi") {
        FlushCgi();
    }else if(method == "FlushDns") {
        FlushDns();
    }else if(method == "FlushStrategy") {
        FlushStrategy();
    }else if(method == "SetServer"){
        json_object* jserver = json_object_object_get(content, "server");
        if(!jserver){
            json_object_object_add(jres, "error", json_object_new_string("require some params"));
            return jres;
        }
        auto ok = SetServer(json_object_get_string(jserver));
        json_object_object_add(jres, "ok", json_object_new_boolean(ok));
    }else if(method == "GetServer") {
        auto server = GetServer();
        json_object_object_add(jres, "server", json_object_new_string(server.c_str()));
    }else if(method == "DumpStatus") {
        auto server = DumpStatus();
        json_object_object_add(jres, "status", json_object_new_string(server.c_str()));
    }else if(method == "DumpMemUsage") {
        auto server = DumpMemUsage();
        json_object_object_add(jres, "mem_usage", json_object_new_string(server.c_str()));
    }else if(method == "DumpDns") {
        auto server = DumpDns();
        json_object_object_add(jres, "dns_status", json_object_new_string(server.c_str()));
    }else if(method == "Login") {
        json_object* jtoken = json_object_object_get(content, "token");
        json_object* jsource = json_object_object_get(content, "source");
        if(!jtoken || !jsource){
            json_object_object_add(jres, "error", json_object_new_string("require some params"));
            return jres;
        }
        auto ok = Login(json_object_get_string(jtoken), json_object_get_string(jsource));
        json_object_object_add(jres, "ok", json_object_new_boolean(ok));
    }else if(method == "Debug"){
        json_object* jmodule = json_object_object_get(content, "module");
        json_object* jenable = json_object_object_get(content, "enable");
        if(!jmodule || !jenable){
            json_object_object_add(jres, "error", json_object_new_string("require some params"));
            return jres;
        }
        auto ok = Debug(json_object_get_string(jmodule), json_object_get_boolean(jenable));
        json_object_object_add(jres, "ok", json_object_new_boolean(ok));
    }else if(method == "killCon") {
        json_object* jaddress = json_object_object_get(content, "address");
        if(!jaddress){
            json_object_object_add(jres, "error", json_object_new_string("require some params"));
            return jres;
        }
        auto ok = killCon(json_object_get_string(jaddress));
        json_object_object_add(jres, "ok", json_object_new_boolean(ok));
    }else{
        json_object_object_add(jres, "error", json_object_new_string("no such method"));
    }
    return jres;
}

std::promise<bool> SproxyClient::AddStrategy(const std::string &host, const std::string &strategy, const std::string &ext) {
    json_object* body = json_object_new_object();
    json_object_object_add(body, "host", json_object_new_string(host.c_str()));
    json_object_object_add(body, "strategy", json_object_new_string(strategy.c_str()));
    json_object_object_add(body, "ext", json_object_new_string(ext.c_str()));
    std::promise<bool> promise;
    call(__func__, body, [&promise](json_object* content){
        json_object* jerror = json_object_object_get(content, "error");
        if(jerror){
            promise.set_exception(std::make_exception_ptr(std::string(json_object_get_string(jerror))));
            return;
        }
        json_object* jok = json_object_object_get(content, "ok");
        promise.set_value(json_object_get_boolean(jok));
    });
    json_object_put(body);
    return promise;
}

std::promise<bool> SproxyClient::DelStrategy(const std::string &host) {
    json_object* body = json_object_new_object();
    json_object_object_add(body, "host", json_object_new_string(host.c_str()));
    std::promise<bool> promise;
    call(__func__, body, [&promise](json_object* content){
        json_object* jerror = json_object_object_get(content, "error");
        if(jerror){
            promise.set_exception(std::make_exception_ptr(std::string(json_object_get_string(jerror))));
            return;
        }
        json_object* jok = json_object_object_get(content, "ok");
        promise.set_value(json_object_get_boolean(jok));
    });
    json_object_put(body);
    return promise;
}

std::promise<std::string> SproxyClient::TestStrategy(const std::string &host) {
    json_object* body = json_object_new_object();
    json_object_object_add(body, "host", json_object_new_string(host.c_str()));
    std::promise<std::string> promise;
    call(__func__, body, [&promise](json_object* content){
        json_object* jerror = json_object_object_get(content, "error");
        if(jerror){
            promise.set_exception(std::make_exception_ptr(std::string(json_object_get_string(jerror))));
            return;
        }
        json_object* jstrategy = json_object_object_get(content, "strategy");
        promise.set_value(json_object_get_string(jstrategy));
    });
    json_object_put(body);
    return promise;
}

std::promise<std::vector<std::string>> SproxyClient::DumpStrategy() {
    json_object* body = json_object_new_object();
    std::promise<std::vector<std::string>> promise;
    call(__func__, body,[&promise](json_object* content){
        json_object* jerror = json_object_object_get(content, "error");
        if(jerror){
            promise.set_exception(std::make_exception_ptr(std::string(json_object_get_string(jerror))));
            return;
        }
        array_list* jlist = json_object_get_array(json_object_object_get(content, "strategies"));
        std::vector<std::string> strategies;
        for(size_t i = 0; i <  array_list_length(jlist); i++){
            json_object* item = (json_object*)array_list_get_idx(jlist, i);
            strategies.emplace_back(json_object_get_string(item));
        }
        promise.set_value(strategies);
    });
    json_object_put(body);
    return promise;
}

std::promise<void> SproxyClient::FlushCgi() {
    json_object* body = json_object_new_object();
    std::promise<void> promise;
    call(__func__, body,[&promise](json_object* content){
        json_object* jerror = json_object_object_get(content, "error");
        if(jerror){
            promise.set_exception(std::make_exception_ptr(std::string(json_object_get_string(jerror))));
            return;
        }
        promise.set_value();
    });
    json_object_put(body);
    return promise;
}

std::promise<void> SproxyClient::FlushDns() {
    json_object* body = json_object_new_object();
    std::promise<void> promise;
    call(__func__, body,[&promise](json_object* content){
        json_object* jerror = json_object_object_get(content, "error");
        if(jerror){
            promise.set_exception(std::make_exception_ptr(std::string(json_object_get_string(jerror))));
            return;
        }
        promise.set_value();
    });
    json_object_put(body);
    return promise;
}

std::promise<void> SproxyClient::FlushStrategy() {
    json_object* body = json_object_new_object();
    std::promise<void> promise;
    call(__func__, body,[&promise](json_object* content){
        json_object* jerror = json_object_object_get(content, "error");
        if(jerror){
            promise.set_exception(std::make_exception_ptr(std::string(json_object_get_string(jerror))));
            return;
        }
        promise.set_value();
    });
    json_object_put(body);
    return promise;
}

std::promise<std::string> SproxyClient::GetServer() {
    json_object* body = json_object_new_object();
    std::promise<std::string> promise;
    call(__func__, body,[&promise](json_object* content){
        json_object* jerror = json_object_object_get(content, "error");
        if(jerror){
            promise.set_exception(std::make_exception_ptr(std::string(json_object_get_string(jerror))));
            return;
        }
        json_object* jstrategy = json_object_object_get(content, "server");
        promise.set_value(json_object_get_string(jstrategy));
    });
    json_object_put(body);
    return promise;
}

std::promise<bool> SproxyClient::SetServer(const std::string &server) {
    json_object* body = json_object_new_object();
    json_object_object_add(body, "server", json_object_new_string(server.c_str()));
    std::promise<bool> promise;
    call(__func__, body,[&promise](json_object* content){
        json_object* jerror = json_object_object_get(content, "error");
        if(jerror){
            promise.set_exception(std::make_exception_ptr(std::string(json_object_get_string(jerror))));
            return;
        }
        json_object* jok = json_object_object_get(content, "ok");
        promise.set_value(json_object_get_boolean(jok));
    });
    json_object_put(body);
    return promise;
}

std::promise<bool> SproxyClient::Login(const std::string &token, const std::string &source) {
    json_object* body = json_object_new_object();
    json_object_object_add(body, "token", json_object_new_string(token.c_str()));
    json_object_object_add(body, "source", json_object_new_string(source.c_str()));
    std::promise<bool> promise;
    call(__func__, body,[&promise](json_object* content){
        json_object* jerror = json_object_object_get(content, "error");
        if(jerror){
            promise.set_exception(std::make_exception_ptr(std::string(json_object_get_string(jerror))));
            return;
        }
        json_object* jok = json_object_object_get(content, "ok");
        promise.set_value(json_object_get_boolean(jok));
    });
    json_object_put(body);
    return promise;
}

std::promise<std::string> SproxyClient::DumpStatus() {
    json_object* body = json_object_new_object();
    std::promise<std::string> promise;
    call(__func__, body,[&promise](json_object* content){
        json_object* jerror = json_object_object_get(content, "error");
        if(jerror){
            promise.set_exception(std::make_exception_ptr(std::string(json_object_get_string(jerror))));
            return;
        }
        json_object* jstatus = json_object_object_get(content, "status");
        promise.set_value(json_object_get_string(jstatus));
    });
    json_object_put(body);
    return promise;
}

std::promise<std::string> SproxyClient::DumpDns() {
    json_object* body = json_object_new_object();
    std::promise<std::string> promise;
    call(__func__, body,[&promise](json_object* content){
        json_object* jerror = json_object_object_get(content, "error");
        if(jerror){
            promise.set_exception(std::make_exception_ptr(std::string(json_object_get_string(jerror))));
            return;
        }
        json_object* jstatus = json_object_object_get(content, "dns_status");
        promise.set_value(json_object_get_string(jstatus));
    });
    json_object_put(body);
    return promise;
}

std::promise<std::string> SproxyClient::DumpMemUsage() {
    json_object* body = json_object_new_object();
    std::promise<std::string> promise;
    call(__func__, body,[&promise](json_object* content){
        json_object* jerror = json_object_object_get(content, "error");
        if(jerror){
            promise.set_exception(std::make_exception_ptr(std::string(json_object_get_string(jerror))));
            return;
        }
        json_object* jusage = json_object_object_get(content, "mem_usage");
        promise.set_value(json_object_get_string(jusage));
    });
    json_object_put(body);
    return promise;
}

std::promise<bool> SproxyClient::Debug(const std::string& module, bool enable) {
    json_object* body = json_object_new_object();
    json_object_object_add(body, "module", json_object_new_string(module.c_str()));
    json_object_object_add(body, "enable", json_object_new_boolean(enable));
    std::promise<bool> promise;
    call(__func__, body,[&promise](json_object* content){
        json_object* jerror = json_object_object_get(content, "error");
        if(jerror){
            promise.set_exception(std::make_exception_ptr(std::string(json_object_get_string(jerror))));
            return;
        }
        json_object* jok = json_object_object_get(content, "ok");
        promise.set_value(json_object_get_boolean(jok));
    });
    json_object_put(body);
    return promise;
}

std::promise<bool> SproxyClient::killCon(const std::string& address) {
    json_object* body = json_object_new_object();
    json_object_object_add(body, "address", json_object_new_string(address.c_str()));
    std::promise<bool> promise;
    call(__func__, body,[&promise](json_object* content){
        json_object* jerror = json_object_object_get(content, "error");
        if(jerror){
            promise.set_exception(std::make_exception_ptr(std::string(json_object_get_string(jerror))));
            return;
        }
        json_object* jok = json_object_object_get(content, "ok");
        promise.set_value(json_object_get_boolean(jok));
    });
    json_object_put(body);
    return promise;
}


static int storage_pton(const char* addrstr, struct sockaddr_storage* addr) {
    memset(addr, 0, sizeof(struct sockaddr_storage));
    char host[INET6_ADDRSTRLEN] = {0};
    const char* addrsplit;
    if (addrstr[0] == '[') {
        // this may be an ipv6 address
        if (!(addrsplit = strchr(addrstr, ']'))) {
            return 0;
        }
        if(addrsplit[1] != ':'){
            return 0;
        }
        long dport = strtol(addrsplit + 2, nullptr, 10);
        if(dport == 0 || dport > 65535){
            return 0;
        }
        int copylen = addrsplit - addrstr - 1;
        if((size_t)copylen >= sizeof(host)){
            return 0;
        }
        memcpy(host, addrstr+1, copylen);
        host[copylen] = 0;
        struct sockaddr_in6* addr6 = (struct sockaddr_in6*)addr;
        if (inet_pton(AF_INET6, host, &addr6->sin6_addr) != 1) {
            return 0;
        }
        addr6->sin6_family = AF_INET6;
        addr6->sin6_port = htons(dport);
        return 1;
    } else if ((addrsplit = strchr(addrstr, ':'))) {
        long dport = strtol(addrsplit + 1, nullptr, 10);
        if(dport == 0 || dport > 65535){
            return 0;
        }
        int copylen = addrsplit - addrstr;
        if((size_t)copylen >= sizeof(host)){
            return 0;
        }
        memcpy(host, addrstr, copylen);
        host[copylen] = 0;
        struct sockaddr_in* addr4 = (struct sockaddr_in*)addr;
        if (inet_pton(AF_INET, host, &addr4->sin_addr) != 1) {
            return 0;
        }
        addr4->sin_family = AF_INET;
        addr4->sin_port = htons(dport);
        return 1;
    }
    return 0;
}

void SproxyClient::callback() {
    size_t off = 0;
    size_t buflen = 1024;
    char* buff = new char[buflen];
    json_object* jres = json_object_new_object();
    while(true) {
        assert(buflen > off);
        ssize_t ret = read(this->fd, buff + off, buflen - off);
        if(ret < 0){
            perror("read from server");
            json_object_object_add(jres, "error",
                                   json_object_new_string("socket error"));
            break;
        }
        if(ret == 0){
            fprintf(stderr, "socket closed\n");
            json_object_object_add(jres, "error",
                                   json_object_new_string("socket shutdown"));
            break;
        }
        off += ret;
        ssize_t eaten = DefaultProc(buff, off);
        if(eaten < 0){
            break;
        }
        if(off == buflen && eaten == 0){
            buflen <<= 1;
            char* nbuff = new char[buflen];
            memcpy(nbuff, buff, off);
            delete []buff;
            buff = nbuff;
        }else {
            memmove(buff, buff + eaten, off - eaten);
            off -= eaten;
        }
    }
    while(!responser.empty()){
        responser.front()(jres);
        responser.pop();
    }
    json_object_put(jres);
    delete []buff;
    close(this->fd);
    this->fd = -1;
}

SproxyClient::SproxyClient(int fd): fd(fd) {
    reader = std::thread([this] {callback(); });
}

SproxyClient::SproxyClient(const char* sock) {
    struct sockaddr_storage addr{};
    socklen_t socklen = sizeof(addr);
    if(strncmp(sock, "tcp:", 4) == 0){
        if(storage_pton(sock+4, &addr) != 1){
            fprintf(stderr, "parse addr failed\n");
            exit(1);
        }
        if(addr.ss_family == AF_INET6){
            fd = socket(AF_INET6, SOCK_STREAM, 0);
            socklen = sizeof(sockaddr_in6);
        }else{
            fd = socket(AF_INET, SOCK_STREAM, 0);
            socklen = sizeof(sockaddr_in);
        }
    }else{
        struct sockaddr_un* addrun = (struct sockaddr_un*)&addr;
        fd = socket(AF_UNIX, SOCK_STREAM, 0);
        addrun->sun_family = AF_UNIX;
        if(sock[0] == '@') {
            addrun->sun_path[0] = '\0';
        }else{
            addrun->sun_path[0] = sock[0];
        }
        char* end = stpcpy(addrun->sun_path+1, sock+1);
        socklen = end - (char*)&addr;
    }
    if (fd < 0){
        perror("client socket error");
        exit(1);
    }

    if (connect(fd, (struct sockaddr *)&addr, socklen) < 0){
        perror("connect error");
        exit(1);
    }
    reader = std::thread([this] {callback();});
}

SproxyClient::~SproxyClient(){
    if(fd >= 0){
        shutdown(fd, SHUT_RDWR);
    }
    reader.join();
}
bool SproxyClient::send(const char* data, size_t len) {
    if(fd < 0) {
        return false;
    }
    return write(fd, data, len) > 0;
}
