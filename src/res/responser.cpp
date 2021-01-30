#include "req/requester.h"
#include "misc/strategy.h"
#include "misc/util.h"
#include "misc/config.h"
#include "misc/net.h"

#include "host.h"
#include "file.h"
#include "cgi.h"
#include "ping.h"
#include "proxy2.h"

#include <map>
#include <string.h>
#include <assert.h>


enum class CheckResult{
    Succeed,
    AuthFailed,
    LoopBack,
    NoPort,
};

static CheckResult check_header(HttpReqHeader* req, Requester* src){
    if (!checkauth(src->getip()) &&
        req->get("Proxy-Authorization") &&
        strcmp(opt.auth_string, req->get("Proxy-Authorization")+6) == 0)
    {
        addauth(src->getip());
    }
    if (!checkauth(src->getip())){
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

static std::string getstraname(HttpReqHeader* header) {
    if(header->Dest.hostname[0] != '['){
        return header->geturl();
    }
    //for ipv6, we should drop '[]'
    char name[URLLIMIT]={0};
    int l = sprintf(name, "%s", header->Dest.hostname + 1);
    if(header->path[1]){
        sprintf(name + l - 1, "%s", header->path);
    }else{
        name[l - 1] = 0;
    }
    return name;
}

void distribute(HttpReq* req, Requester* src){
    HttpRes* res = nullptr;
    if(!req->header->Dest.hostname[0]){
        res = new HttpRes(new HttpResHeader(H400), "[[host not set]]\n");
        goto out;
    }
    if (req->header->normal_method()) {
        strategy stra = getstrategy(req->header->Dest.hostname);
        req->header->set("Strategy", getstrategystring(stra.s));
        if(stra.s == Strategy::block){
            res = new HttpRes(new HttpResHeader(H403),
                              "This site is blocked, please contact administrator for more information.\n");
            goto out;
        }
        if(stra.s == Strategy::local){
            if(req->header->http_method()){
                return File::getfile(req, src);
            }else{
                stra.s = Strategy::direct;
            }
        }
        req->header->set("Strategy", getstrategystring(stra.s));
        switch(check_header(req->header, src)){
        case CheckResult::Succeed:
            break;
        case CheckResult::AuthFailed:
            res = new HttpRes(new HttpResHeader(H407), "[[Authorization needed]]\n");
            goto out;
        case CheckResult::LoopBack:
            res = new HttpRes(new HttpResHeader(H508), "[[redirect back]]\n");
            goto out;
        case CheckResult::NoPort:
            res = new HttpRes(new HttpResHeader(H400), "[[no port]]\n");
            goto out;
        }
        Destination dest;
        switch(stra.s){
        case Strategy::proxy:
            memcpy(&dest, &opt.Server, sizeof(dest));
            if(dest.port == 0){
                res = new HttpRes(new HttpResHeader(H400), "[[server not set]]\n");
                goto out;
            }
            req->header->del("via");
            if(strlen(opt.rewrite_auth)){
                req->header->set("Proxy-Authorization", std::string("Basic ") + opt.rewrite_auth);
            }
            //req->set("X-Forwarded-For", "2001:da8:b000:6803:62eb:69ff:feb4:a6c2");
            req->header->should_proxy = true;
            if(!stra.ext.empty() && loadproxy(stra.ext.c_str(), &dest)){
                res = new HttpRes(new HttpResHeader(H500), "[[ext misformat]]\n");
                goto out;
            }
            break;
        case Strategy::direct:
            memcpy(&dest, &req->header->Dest, sizeof(dest));
            if(req->header->ismethod("PING")){
                return (new Ping(req->header))->request(req, src);
            }
            req->header->del("Proxy-Authorization");
            break;
        case Strategy::rewrite:
            req->header->set("host", stra.ext);
            /* FALLTHROUGH */
        case Strategy::forward:
            if(stra.ext.empty()){
                res = new HttpRes(new HttpResHeader(H500), "[[destination not set]]\n");
                goto out;
            }
            memcpy(&dest, &req->header->Dest, sizeof(dest));
            if(spliturl(stra.ext.c_str(), &dest, nullptr)){
                res = new HttpRes(new HttpResHeader(H500), "[[ext misformat]]\n");
                goto out;
            }
            break;
        default:
            res = new HttpRes(new HttpResHeader(H503), "[[BUG]]\n");
            goto out;
        }
        return Host::gethost(req, &dest, src);
    }else if (req->header->ismethod("ADDS")) {
        const char *strategy = req->header->get("s");
        if(!strategy){
            res = new HttpRes(new HttpResHeader(H400), "[[no strategy]]\n");
            goto out;
        }
        const char *ext = req->header->get("ext");
        req->header->set("Strategy", strategy);
        if(strategy && addstrategy(getstraname(req->header).c_str(), strategy, ext ? ext:"")){
            res = new HttpRes(new HttpResHeader(H200), "[[ok]]\n");
            goto out;
        }else{
            res = new HttpRes(new HttpResHeader(H400), "[[failed]]\n");
            goto out;
        }
    } else if (req->header->ismethod("DELS")) {
        std::string host = getstraname(req->header);
        strategy stra = getstrategy(host.c_str());
        const char *strategy = getstrategystring(stra.s);
        req->header->set("Strategy", strategy);
        if(delstrategy(host.c_str())){
            HttpResHeader* header = new HttpResHeader(H200, sizeof(H200));
            header->set("Strategy", strategy);
            header->set("Ext", stra.ext);
            res = new HttpRes(header, "[[ok]]\n");
            goto out;
        }else{
            res = new HttpRes(new HttpResHeader(H404), "[[not found]]\n");
            goto out;
        }
    } else if (req->header->ismethod("SWITCH")) {
        if(loadproxy(req->header->geturl().c_str(), &opt.Server)){
            res = new HttpRes(new HttpResHeader(H400), "[[failed]]\n");
            goto out;
        }else{
            flushproxy2(1);
            res = new HttpRes(new HttpResHeader(H200), "[[ok]]\n");
            goto out;
        }
    } else if (req->header->ismethod("TEST")){
        strategy stra = getstrategy(getstraname(req->header).c_str());
        const char *strategy = getstrategystring(stra.s);
        req->header->set("Strategy", strategy);
        HttpResHeader* header = new HttpResHeader(H200);
        header->set("Strategy", strategy);
        header->set("Ext", stra.ext);
        res = new HttpRes(header, "[[ok]]\n");
        goto out;
    } else if(req->header->ismethod("FLUSH")){
        if(strcasecmp(req->header->Dest.hostname, "cgi") == 0){
            flushcgi();
            res = new HttpRes(new HttpResHeader(H200), "[[ok]]\n");
            goto out;
        }else if(strcasecmp(req->header->Dest.hostname, "strategy") == 0){
            reloadstrategy();
            res = new HttpRes(new HttpResHeader(H200), "[[ok]]\n");
            goto out;
        }else if(strcasecmp(req->header->Dest.hostname, "dns") == 0){
            flushdns();
            res = new HttpRes(new HttpResHeader(H200), "[[ok]]\n");
            goto out;
        }else{
            res = new HttpRes(new HttpResHeader(H400), "[[failed]]\n");
            goto out;
        }
    } else{
        res = new HttpRes(new HttpResHeader(H405), "[[unsported method]]\n");
        goto out;
    }
out:
    assert(res);
    req->response(res);
}
