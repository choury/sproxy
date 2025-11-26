#include "req/requester.h"
#include "misc/strategy.h"
#include "misc/util.h"
#include "misc/config.h"
#include "misc/defer.h"
#include "misc/hook.h"
#include "prot/memio.h"

#include "host.h"
#include "file.h"
#include "ping.h"
#include "uhost.h"
#include "rproxy2.h"

#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <sstream>


bimap<std::string, Responser*> responsers;
enum class CheckResult{
    Succeed,
    AuthFailed,
    LoopBack,
    NoPort,
};

static std::string identify = "HTTP/1.1 sproxy:" + std::to_string(getpid());

bool shouldNegotiate(const std::string& hostname, const strategy* stra_){
    const auto& stra = stra_ ? *stra_ : getstrategy(hostname.c_str());
    if (stra.s == Strategy::direct && stra.ext == NO_MITM) {
        //for vpn, only works with fakeip enabled
        return false;
    }
    if(opt.mitm_mode == Enable) {
        return true;
    }
    if(opt.mitm_mode == Auto && opt.ca.key && (stra.s == Strategy::block || mayBeBlocked(hostname.c_str()))) {
        return true;
    }
    return false;
}

bool shouldNegotiate(std::shared_ptr<const HttpReqHeader> req, Requester* src){
    auto stra = getstrategy(req->Dest.hostname, req->path);
    if(shouldNegotiate(req->Dest.hostname, &stra)){
        return true;
    }
    if(stra.s == Strategy::local && req->getDport() == src->getDst().port) {
        return true;
    }
    return false;
}

static CheckResult check_header(std::shared_ptr<const HttpReqHeader> req, const char* src_host){
    if (!checkauth(src_host, req->get("Proxy-Authorization"), req->get("Authorization"))){
        return CheckResult::AuthFailed;
    }
    if(req->has("via") && strstr(req->get("via"), identify.c_str())){
        return CheckResult::LoopBack;
    }
    if(req->Dest.port == 0 && req->ismethod("CONNECT")){
        return CheckResult::NoPort;
    }

    return CheckResult::Succeed;
}

void response(std::shared_ptr<MemRWer> rw, std::shared_ptr<HttpResHeader> res, std::string_view body){
    res->set("Content-Length", body.size());
    rw->SendHeader(res);
    if(!body.empty()) {
        rw->Send(Buffer{body.data(), body.size(), res->request_id});
    }
    rw->Send(Buffer{nullptr, res->request_id});
}

void distribute(std::shared_ptr<HttpReqHeader> req, std::shared_ptr<MemRWer> rw){
    HOOK_FUNC(req, rw);
    defer([req] { req->tracker.emplace_back("distribute", getmtime()); });
    auto id = req->request_id;
    //std::shared_ptr<HttpRes> res;
    if(!req->Dest.hostname[0]){
        return response(rw, HttpResHeader::create(S400, sizeof(S400), id), "[[host not set]]\n");
    }
    if (!req->valid_method()) {
        return response(rw, HttpResHeader::create(S405, sizeof(S405), id), "[[unsupported method]]\n");
    }
    if(opt.redirect_http && opt.ssl_list && is_http_listen_port(rw->getDst().port)) {
        auto reqh = HttpReqHeader(*req);
        strcpy(reqh.Dest.scheme, "https");
        reqh.Dest.port = opt.ssl_list->dest.port;

        auto resh = HttpResHeader::create(S308, sizeof(S308), id);
        resh->set("Location", reqh.geturl());
        return response(rw, resh, reqh.geturl().c_str());
    }
    strategy stra = getstrategy(req->Dest.hostname, req->path);
    if(stra.s == Strategy::block){
        req->set(STRATEGY, getstrategystring(Strategy::block));
        return response(rw, HttpResHeader::create(S403, sizeof(S403), id),
                            "This site is blocked, please contact administrator for more information.\n");
    }
    if(stra.s == Strategy::local){
        if(!opt.restrict_local && !req->http_method() && !req->webdav_method()) {
            return response(rw, HttpResHeader::create(S405, sizeof(S405), id),
                                            "[[unsupported method]]\n");
        }
        if(!opt.restrict_local ||
            ((req->http_method() ||(req->webdav_method())) && (rw->getDst().port == 0 || req->getDport() == rw->getDst().port)))
        {
            req->set(STRATEGY, getstrategystring(Strategy::local));
            return File::getfile(req, rw);
        }
        stra.s = Strategy::direct;
    }
    req->set(STRATEGY, getstrategystring(stra.s));
    switch(check_header(req, rw->getSrc().hostname)){
    case CheckResult::Succeed:
        break;
    case CheckResult::AuthFailed: {
        auto sheader = HttpResHeader::create(S407, sizeof(S407), id);
        sheader->set("Proxy-Authenticate", "Basic realm=\"Secure Area\"");
        return response(rw, sheader, "[[Authorization needed]]\n");
    }
    case CheckResult::LoopBack:
        return response(rw, HttpResHeader::create(S508, sizeof(S508), id), "[[redirect back]]\n");
    case CheckResult::NoPort:
        return response(rw, HttpResHeader::create(S400, sizeof(S400), id), "[[no port]]\n");
    }
    if(req->has("rproxy")) {
        return distribute_rproxy(req, rw);
    }
    req->append("Via", identify);
    Destination dest;
    switch(stra.s){
    case Strategy::proxy:
        memcpy(&dest, &opt.Server, sizeof(dest));
        if(dest.port == 0){
            return response(rw, HttpResHeader::create(S400, sizeof(S400), id), "[[server not set]]\n");
        }
        if(strlen(opt.rewrite_auth)){
            req->set("Proxy-Authorization", std::string("Basic ") + opt.rewrite_auth);
        }
        //req->set("X-Forwarded-For", "2001:da8:b000:6803:62eb:69ff:feb4:a6c2");
        req->chain_proxy = true;
        if(!stra.ext.empty() && parseDest(stra.ext.c_str(), &dest)){
            return response(rw, HttpResHeader::create(S500, sizeof(S500), id), "[[ext misformat]]\n");
        }
        break;
    case Strategy::direct:
        memcpy(&dest, &req->Dest, sizeof(dest));
        dest.port = req->getDport();
        if(req->has("Rproxy-Name") && req->has("X-Forwarded-For")) {
            if(opt.rproxy_keep_src) strncpy(dest.assign_src, req->get("X-Forwarded-For"), sizeof(dest.assign_src) - 1);
            if(!req->ismethod("CONNECT")) req->del("X-Forwarded-For");
        }
        req->del("Proxy-Authorization");
        if(strcmp(dest.protocol, "icmp") == 0){
            return (new Ping(dest))->request(req, rw);
        }
        if(strcmp(dest.protocol, "udp") == 0) {
            return (new Uhost(dest))->request(req, rw);
        }
        break;
    //rewrite 和 forward的唯一区别就是rewrite会修改host为目标地址
    case Strategy::rewrite:
        /* FALLTHROUGH */
    case Strategy::forward:
        if(stra.ext.empty()){
            return response(rw, HttpResHeader::create(S500, sizeof(S500), id), "[[destination not set]]\n");
        }
        memcpy(&dest, &req->Dest, sizeof(dest));
        strcpy(dest.protocol, "tcp"); // rewrite and forward only support tcp
        if(dest.port == 0) {
            dest.port = req->getDport();
        }
        if(spliturl(stra.ext.c_str(), &dest, nullptr)){
            return response(rw, HttpResHeader::create(S500, sizeof(S500), id), "[[ext misformat]]\n");
        }
        if(stra.s == Strategy::rewrite) {
            req->set("host", dumpAuthority(&dest));
        }
        break;
    default:
        return response(rw, HttpResHeader::create(S503, sizeof(S503), id), "[[BUG]]\n");
    }
    dest.system_resolve = req->Dest.system_resolve;
    return Host::distribute(req, dest, rw);
}

std::map<std::string, Responser*> rproxys;

static std::vector<std::string> split(const std::string& s, char delimiter) {
    std::vector<std::string> tokens;
    std::string token;
    std::istringstream tokenStream(s);
    while (std::getline(tokenStream, token, delimiter)) {
        if (!token.empty()) {
            tokens.push_back(token);
        }
    }
    return tokens;
}

void distribute_rproxy(std::shared_ptr<HttpReqHeader> req, std::shared_ptr<MemRWer> rw) {
    uint64_t id = req->request_id;
    if(!checkauth(rw->getSrc().hostname, req->get("Proxy-Authorization"), req->get("Authorization"))){
        auto sheader = HttpResHeader::create(S401, sizeof(S401), id);
        sheader->set("WWW-Authenticate", "Basic realm=\"Secure Area\"");
        response(rw, sheader, "");
        return;
    }
    std::string filename;
    if(req->has("rproxy")) {
        filename = req->get("rproxy");
        req->del("rproxy");
    }else {
        std::string path = req->path;
        auto fragment = split(req->path, '/');
        assert(fragment.size() >= 1 && fragment[0] == "rproxy");
        if(fragment.size() == 1) {
            auto resh = HttpResHeader::create(S200, sizeof(S200), id);
            resh->set("Transfer-Encoding", "chunked");
            resh->set("Content-Type", "text/plain; charset=utf8");
            rw->SendHeader(resh);
            char buff[2048];
            rw->Send(Buffer{buff, (size_t)snprintf(buff, sizeof(buff), "======================================\n")});
            for(auto [name, rproxy]: rproxys) {
                rw->Send(Buffer{buff, (size_t)snprintf(buff, sizeof(buff), "%s [%p]: %s\n",
                                                       name.c_str(), rproxy, dumpDest(rproxy->getPeer()).c_str())});
            }
            rw->Send(Buffer{buff, (size_t)snprintf(buff, sizeof(buff), "======================================\n")});
            rw->Send(nullptr);
            return;
        }
        if(fragment.size() < 3) {
            response(rw, HttpResHeader::create(S400, sizeof(S400), id), "");
            return;
        }
        filename = fragment[1];
        memset(&req->Dest.hostname, 0, sizeof(req->Dest.hostname));
        req->Dest.port = 0;
        if(strcmp(req->Dest.protocol, "websocket")) {
            memset(&req->Dest.protocol, 0, sizeof(req->Dest.protocol));
        }
        strcpy(req->Dest.scheme, "http");
        if(spliturl(path.c_str() + 9 + filename.length(), &req->Dest, req->path)) {
            response(rw, HttpResHeader::create(S400, sizeof(S400), id), "");
            return;
        }
        if(strcmp(req->path, "/") == 0 && path.back() != '/'){
            // /rproxy/example.com => /rproxy/example.com/

            auto resh = HttpResHeader::create(S308, sizeof(S308), id);
            resh->set("Location", path + '/');
            response(rw, resh, "");
            return;
        }
        req->postparse();
        LOGD(DFILE, "rproxy: %s -> %s\n", path.c_str(), req->geturl().c_str());
    }
    const auto& src = rw->getSrc();
    req->set("X-Forwarded-For", dumpAuthority(&src));
    req->set("Rproxy-Name", filename);
    if(filename == "local") {
        return distribute(req, rw);
    }
    if(rproxys.count(filename) == 0) {
        response(rw, HttpResHeader::create(S404, sizeof(S404), id), "");
        return;
    }
    req->chain_proxy = true;
    rproxys[filename]->request(req, rw);
}

void rewrite_rproxy_location(std::shared_ptr<HttpReqHeader> req, std::shared_ptr<HttpResHeader> res) {
    if(!req || !res) {
        return;
    }
    if(!res->has("Location")) {
        return;
    }
    const char* rproxy = req->get("Rproxy-Name");
    if(rproxy == nullptr) {
        return;
    }
    std::string location = res->get("Location");
    if(location.empty() || startwith(location.c_str(), "/rproxy/")) {
        return;
    }

    std::string prefix = std::string("/rproxy/") + rproxy + "/";
    if(location.size() >= 2 && location[0] == '/' && location[1] == '/') {
        /*
        *   //example.com => /rproxy/<name>/http://example.com
        */
        const char* scheme = req->Dest.scheme[0] ? req->Dest.scheme : "http";
        res->set("Location", prefix + std::string(scheme) + ":" + location);
        return;
    }

    Destination parsed{};
    char parsed_path[URLLIMIT] = {0};
    if(spliturl(location.c_str(), &parsed, parsed_path) != 0) {
        return;
    }

    if(parsed.scheme[0]) {
        // http://example.com/... => /rproxy/<name>/http://example.com/...
        res->set("Location", prefix + location);
        return;
    }

    // concat last / + path
    std::string new_location = prefix + dumpDest(&req->Dest) + (parsed_path[0] ? std::string(parsed_path) : "/");
    res->set("Location", new_location);
}
