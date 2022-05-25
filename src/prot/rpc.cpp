#include "rpc.h"

#include <errno.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <sys/un.h>
#include <sys/socket.h>

#include <thread>

void RpcBase::sendJson(json_object *content) {
    const char* body = json_object_get_string(content);
    size_t len = strlen(body);
    char prefix[5];
    sprintf(prefix, "%04zx", len);
    send(prefix, 4);
    send(body, len);
}

ssize_t RpcServer::DefaultProc(const char *buff, size_t len) {
    if(len <= 4){
        return 0;
    }
    size_t body_size = 0;
    for(int i = 0; i < 4; i++){
        body_size *= 16;
        if(buff[i] >= 'a' && buff[i] <= 'f'){
            body_size += buff[i] - 'a' + 10;
            continue;
        }
        if(buff[i] >= '0' && buff[i] <= '9'){
            body_size += buff[i] - '0';
            continue;
        }
        return -EINVAL;
    }
    if(body_size > len + 4){
        return 0;
    }
    ssize_t ret = 4 + body_size;

    struct json_tokener *tok = json_tokener_new();
    json_object* jres = nullptr, *jmethod;
    //fprintf(stderr, "%.*s\n", (int)body_size, buff+4);
    json_object* jreq = json_tokener_parse_ex(tok, buff + 4, body_size);
    if(jreq == nullptr) {
        ret = -EINVAL;
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
    if(len <= 4){
        return 0;
    }
    size_t body_size = 0;
    struct json_tokener *tok = json_tokener_new();
    json_object* jres = nullptr;
    for(int i = 0; i < 4; i++){
        body_size *= 16;
        if(buff[i] >= 'a' && buff[i] <= 'f'){
            body_size += buff[i] - 'a' + 10;
            continue;
        }
        if(buff[i] >= '0' && buff[i] <= '9'){
            body_size += buff[i] - '0';
            continue;
        }
        jres = json_object_new_object();
        json_object_object_add(jres, "error", json_object_new_string("can't parse body length"));
        goto out;
    }

    if(body_size > len + 4){
        json_tokener_free(tok);
        return 0;
    }
    len = 4 + body_size;
    //fprintf(stderr, "%.*s\n", (int)body_size, buff+4);

    if((jres = json_tokener_parse_ex(tok, buff + 4, body_size)) == nullptr){
        jres = json_object_new_object();
        json_object_object_add(jres, "error", json_object_new_string(json_tokener_error_desc(json_tokener_get_error(tok))));
    }
out:
    if(!responser.empty()){
        auto resp = responser.front();
        resp(jres);
        responser.pop();
    }
    json_object_put(jres);
    json_tokener_free(tok);
    return len;
}

void RpcClient::call(const std::string& method, json_object* body, std::function<void(json_object *)> response) {
    json_object_object_add(body, "method", json_object_new_string(method.c_str()));
    responser.push(response);
    sendJson(body);
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
    }else if(method == "ListStrategy") {
        auto lists = ListStrategy();
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
    }else if(method == "GetStatus") {
        auto server = GetStatus();
        json_object_object_add(jres, "status", json_object_new_string(server.c_str()));
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

std::promise<std::vector<std::string>> SproxyClient::ListStrategy() {
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

std::promise<std::string> SproxyClient::GetStatus() {
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


SproxyClient::SproxyClient(const char* sock) {
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0){
        perror("client socket error");
        exit(1);
    }
    struct  sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, sock);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(sockaddr_un)) < 0){
        perror("connect error");
        exit(1);
    }
    reader = std::thread([this] {
        size_t off = 0;
        size_t buflen = 1024;
        char* buff = new char[buflen];
        while(true) {
            assert(buflen > off);
            ssize_t ret = read(this->fd, buff + off, buflen - off);
            if(ret < 0){
                perror("read from server");
                exit((int)ret);
            }
            if(ret == 0){
                //shutdown by destructor
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
        delete []buff;
    });
}
SproxyClient::~SproxyClient(){
    shutdown(fd, SHUT_RDWR);
    reader.join();
    close(fd);
}
void SproxyClient::send(const char* data, size_t len){
    write(fd, data, len);
}
