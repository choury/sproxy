#include "req/requester.h"
#include "misc/strategy.h"
#include "misc/util.h"
#include "misc/config.h"

#include "host.h"
#include "file.h"
#include "ping.h"

#include <string.h>
#include <assert.h>


enum class CheckResult{
    Succeed,
    AuthFailed,
    LoopBack,
    NoPort,
};

static CheckResult check_header(std::shared_ptr<HttpReqHeader> req, Requester* src){
    if (!checkauth(src->getid(), req->get("Proxy-Authorization"))){
        return CheckResult::AuthFailed;
    }
    if(req->get("via") && strstr(req->get("via"), "sproxy")){
        return CheckResult::LoopBack;
    }
    if(req->Dest.port == 0 && (req->ismethod("SEND") || req->ismethod("CONNECT"))){
        return CheckResult::NoPort;
    }

    if(req->get("Upgrade") && strcmp(req->get("Upgrade"), "websocket") == 0){
        //only allow websocket upgrade
    }else{
        req->del("Connection");
        if(req->get("Proxy-Connection")){
            req->set("Connection", req->get("Proxy-Connection"));
        }
        req->del("Upgrade");
    }
    req->del("Public");
    req->del("Proxy-Connection");
    req->append("Via", "HTTP/1.1 sproxy");
    return CheckResult::Succeed;
}

void distribute(std::shared_ptr<HttpReq> req, Requester* src){
    auto header = req->header;
    std::shared_ptr<HttpRes> res;
    if(!header->Dest.hostname[0]){
        res = std::make_shared<HttpRes>(UnpackHttpRes(H400), "[[host not set]]\n");
        goto out;
    }
    if (header->valid_method()) {
        strategy stra = getstrategy(header->Dest.hostname);
        header->set("Strategy", getstrategystring(stra.s));
        if(stra.s == Strategy::block){
            res = std::make_shared<HttpRes>(UnpackHttpRes(H403),
                              "This site is blocked, please contact administrator for more information.\n");
            goto out;
        }
        if(stra.s == Strategy::local){
            if(header->http_method()){
                return File::getfile(req, src);
            }else{
                stra.s = Strategy::direct;
            }
        }
        header->set(STRATEGY, getstrategystring(stra.s));
        switch(check_header(header, src)){
        case CheckResult::Succeed:
            break;
        case CheckResult::AuthFailed:
            res = std::make_shared<HttpRes>(UnpackHttpRes(H407), "[[Authorization needed]]\n");
            goto out;
        case CheckResult::LoopBack:
            res = std::make_shared<HttpRes>(UnpackHttpRes(H508), "[[redirect back]]\n");
            goto out;
        case CheckResult::NoPort:
            res = std::make_shared<HttpRes>(UnpackHttpRes(H400), "[[no port]]\n");
            goto out;
        }
        Destination dest;
        switch(stra.s){
        case Strategy::proxy:
            memcpy(&dest, &opt.Server, sizeof(dest));
            if(dest.port == 0){
                res = std::make_shared<HttpRes>(UnpackHttpRes(H400), "[[server not set]]\n");
                goto out;
            }
            header->del("via");
            if(strlen(opt.rewrite_auth)){
                header->set("Proxy-Authorization", std::string("Basic ") + opt.rewrite_auth);
            }
            //req->set("X-Forwarded-For", "2001:da8:b000:6803:62eb:69ff:feb4:a6c2");
            header->should_proxy = true;
            if(!stra.ext.empty() && loadproxy(stra.ext.c_str(), &dest)){
                res = std::make_shared<HttpRes>(UnpackHttpRes(H500), "[[ext misformat]]\n");
                goto out;
            }
            break;
        case Strategy::direct:
            memcpy(&dest, &header->Dest, sizeof(dest));
            if(header->ismethod("PING")){
                return (new Ping(header))->request(req, src);
            }
            header->del("Proxy-Authorization");
            break;
        case Strategy::rewrite:
            header->set("host", stra.ext);
            /* FALLTHROUGH */
        case Strategy::forward:
            if(stra.ext.empty()){
                res = std::make_shared<HttpRes>(UnpackHttpRes(H500), "[[destination not set]]\n");
                goto out;
            }
            memcpy(&dest, &header->Dest, sizeof(dest));
            if(spliturl(stra.ext.c_str(), &dest, nullptr)){
                res = std::make_shared<HttpRes>(UnpackHttpRes(H500), "[[ext misformat]]\n");
                goto out;
            }
            break;
        default:
            res = std::make_shared<HttpRes>(UnpackHttpRes(H503), "[[BUG]]\n");
            goto out;
        }
        return Host::gethost(req, &dest, src);
    } else{
        res = std::make_shared<HttpRes>(UnpackHttpRes(H405), "[[unsported method]]\n");
        goto out;
    }
out:
    assert(res);
    req->response(res);
}
