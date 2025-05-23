#include "req/requester.h"
#include "misc/strategy.h"
#include "misc/util.h"
#include "misc/config.h"
#include "misc/defer.h"
#include "misc/hook.h"

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

void distribute(std::shared_ptr<HttpReq> req, Requester* src){
    HOOK_FUNC(req, src);
    defer([req] { req->header->tracker.emplace_back("distribute", getmtime()); });
    auto header = req->header;
    auto id = header->request_id;
    std::shared_ptr<HttpRes> res;
    if(!header->Dest.hostname[0]){
        res = std::make_shared<HttpRes>(HttpResHeader::create(S400, sizeof(S400), id),
                                        "[[host not set]]\n");
        goto out;
    }
    if(opt.redirect_http && opt.ssl.hostname[0] && src->getDst().port == opt.http.port) {
        auto reqh = HttpReqHeader(*header);
        strcpy(reqh.Dest.scheme, "https");
        reqh.Dest.port = opt.ssl.port;

        auto resh = HttpResHeader::create(S308, sizeof(S308), id);
        resh->set("Location", reqh.geturl());
        res = std::make_shared<HttpRes>(resh, reqh.geturl().c_str());
        goto out;
    }
    if (header->valid_method()) {
        strategy stra = getstrategy(header->Dest.hostname, header->path);
        if(stra.s == Strategy::block){
            header->set(STRATEGY, getstrategystring(Strategy::block));
            res = std::make_shared<HttpRes>(HttpResHeader::create(S403, sizeof(S403), id),
                              "This site is blocked, please contact administrator for more information.\n");
            goto out;
        }
        if(stra.s == Strategy::local){
            if(!opt.restrict_local && !header->http_method()) {
                res = std::make_shared<HttpRes>(HttpResHeader::create(S405, sizeof(S405), id),
                                                "[[unsported method]]\n");
                goto out;
            }
            if(!opt.restrict_local ||
               (header->http_method() && (src->getDst().port == 0 || header->getDport() == src->getDst().port)))
            {
                header->set(STRATEGY, getstrategystring(Strategy::local));
                return File::getfile(req, src);
            }
            stra.s = Strategy::direct;
        }
        header->set(STRATEGY, getstrategystring(stra.s));
        switch(check_header(header, src)){
        case CheckResult::Succeed:
            break;
        case CheckResult::AuthFailed: {
            auto sheader = HttpResHeader::create(S407, sizeof(S407), id);
            sheader->set("Proxy-Authenticate", "Basic realm=\"Secure Area\"");
            res = std::make_shared<HttpRes>(sheader,
                                            "[[Authorization needed]]\n");
            goto out;
        }
        case CheckResult::LoopBack:
            res = std::make_shared<HttpRes>(HttpResHeader::create(S508, sizeof(S508), id),
                                            "[[redirect back]]\n");
            goto out;
        case CheckResult::NoPort:
            res = std::make_shared<HttpRes>(HttpResHeader::create(S400, sizeof(S400), id),
                                            "[[no port]]\n");
            goto out;
        }
        if(header->get("rproxy")) {
            return Rproxy2::distribute(req, src);
        }
        header->append("Via", "HTTP/1.1 sproxy");
        Destination dest;
        switch(stra.s){
        case Strategy::proxy:
            memcpy(&dest, &opt.Server, sizeof(dest));
            if(dest.port == 0){
                res = std::make_shared<HttpRes>(HttpResHeader::create(S400, sizeof(S400), id),
                                                "[[server not set]]\n");
                goto out;
            }
            header->del("via");
            if(strlen(opt.rewrite_auth)){
                header->set("Proxy-Authorization", std::string("Basic ") + opt.rewrite_auth);
            }
            //req->set("X-Forwarded-For", "2001:da8:b000:6803:62eb:69ff:feb4:a6c2");
            header->chain_proxy = true;
            if(!stra.ext.empty() && parseDest(stra.ext.c_str(), &dest)){
                res = std::make_shared<HttpRes>(HttpResHeader::create(S500, sizeof(S500), id),
                                                "[[ext misformat]]\n");
                goto out;
            }
            break;
        case Strategy::direct:
            memcpy(&dest, &header->Dest, sizeof(dest));
            dest.port = header->getDport();
            if(strcmp(header->Dest.protocol, "icmp") == 0){
                return (new Ping(header))->request(req, src);
            }
            if(strcmp(header->Dest.protocol, "udp") == 0) {
                return (new Uhost(header))->request(req, src);
            }
            header->del("Proxy-Authorization");
            break;
        //rewrite 和 forward的唯一区别就是rewrite会修改host为目标地址
        case Strategy::rewrite:
            /* FALLTHROUGH */
        case Strategy::forward:
            if(stra.ext.empty()){
                res = std::make_shared<HttpRes>(HttpResHeader::create(S500, sizeof(S500), id),
                                                "[[destination not set]]\n");
                goto out;
            }
            memcpy(&dest, &header->Dest, sizeof(dest));
            strcpy(dest.protocol, "tcp"); // rewrite and forward only support tcp
            if(dest.port == 0) {
                dest.port = header->getDport();
            }
            if(spliturl(stra.ext.c_str(), &dest, nullptr)){
                res = std::make_shared<HttpRes>(HttpResHeader::create(S500, sizeof(S500), id),
                                                "[[ext misformat]]\n");
                goto out;
            }
            if(stra.s == Strategy::rewrite) {
                header->set("host", dumpAuthority(&dest));
            }
            break;
        default:
            res = std::make_shared<HttpRes>(HttpResHeader::create(S503, sizeof(S503), id),
                                            "[[BUG]]\n");
            goto out;
        }
        return Host::distribute(req, dest, src);
    } else{
        res = std::make_shared<HttpRes>(HttpResHeader::create(S405, sizeof(S405), id),
                                        "[[unsported method]]\n");
        goto out;
    }
out:
    assert(res);
    req->response(res);
}
