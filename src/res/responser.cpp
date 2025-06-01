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
#include <inttypes.h>


bimap<std::string, Responser*> responsers;
enum class CheckResult{
    Succeed,
    AuthFailed,
    LoopBack,
    NoPort,
};

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

static CheckResult check_header(std::shared_ptr<const HttpReqHeader> req, Requester* src){
    if (!checkauth(src->getSrc().hostname, req->get("Proxy-Authorization"))){
        return CheckResult::AuthFailed;
    }
    if(req->get("via") && strstr(req->get("via"), "sproxy")){
        return CheckResult::LoopBack;
    }
    if(req->Dest.port == 0 && req->ismethod("CONNECT")){
        return CheckResult::NoPort;
    }

    return CheckResult::Succeed;
}

void response(std::shared_ptr<MemRWer> rw, std::shared_ptr<HttpResHeader> res, const char* body){
    int len = body ? strlen(body): 0;
    res->set("Content-Length", len);
    rw->SendHeader(res);
    if(len) {
        rw->Send(Buffer{body, (size_t)len, res->request_id});
    }
    rw->Send(Buffer{nullptr, res->request_id});
}

void distribute(std::shared_ptr<HttpReqHeader> req, std::shared_ptr<MemRWer> rw, Requester* src){
    HOOK_FUNC(req, src);
    defer([req] { req->tracker.emplace_back("distribute", getmtime()); });
    auto id = req->request_id;
    //std::shared_ptr<HttpRes> res;
    if(!req->Dest.hostname[0]){
        return response(rw, HttpResHeader::create(S400, sizeof(S400), id), "[[host not set]]\n");
    }
    if(opt.redirect_http && opt.ssl.hostname[0] && src->getDst().port == opt.http.port) {
        auto reqh = HttpReqHeader(*req);
        strcpy(reqh.Dest.scheme, "https");
        reqh.Dest.port = opt.ssl.port;

        auto resh = HttpResHeader::create(S308, sizeof(S308), id);
        resh->set("Location", reqh.geturl());
        return response(rw, resh, reqh.geturl().c_str());
    }
    if (req->valid_method()) {
        strategy stra = getstrategy(req->Dest.hostname, req->path);
        if(stra.s == Strategy::block){
            req->set(STRATEGY, getstrategystring(Strategy::block));
            return response(rw, HttpResHeader::create(S403, sizeof(S403), id),
                              "This site is blocked, please contact administrator for more information.\n");
        }
        if(stra.s == Strategy::local){
            if(!opt.restrict_local && !req->http_method()) {
                return response(rw, HttpResHeader::create(S405, sizeof(S405), id),
                                                "[[unsported method]]\n");
            }
            if(!opt.restrict_local ||
               (req->http_method() && (src->getDst().port == 0 || req->getDport() == src->getDst().port)))
            {
                req->set(STRATEGY, getstrategystring(Strategy::local));
                return File::getfile(req, rw, src);
            }
            stra.s = Strategy::direct;
        }
        req->set(STRATEGY, getstrategystring(stra.s));
        switch(check_header(req, src)){
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
        if(req->get("rproxy")) {
            return Rproxy2::distribute(req, rw, src);
        }
        req->append("Via", "HTTP/1.1 sproxy");
        Destination dest;
        switch(stra.s){
        case Strategy::proxy:
            memcpy(&dest, &opt.Server, sizeof(dest));
            if(dest.port == 0){
                return response(rw, HttpResHeader::create(S400, sizeof(S400), id), "[[server not set]]\n");
            }
            req->del("via");
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
            if(strcmp(req->Dest.protocol, "icmp") == 0){
                return (new Ping(req))->request(req, rw, src);
            }
            if(strcmp(req->Dest.protocol, "udp") == 0) {
                return (new Uhost(req))->request(req, rw, src);
            }
            req->del("Proxy-Authorization");
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
        return Host::distribute(req, dest, rw, src);
    } else{
        return response(rw, HttpResHeader::create(S405, sizeof(S405), id), "[[unsported method]]\n");
    }
}
