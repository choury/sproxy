#include "req/requester.h"
#include "misc/strategy.h"
#include "misc/util.h"
#include "misc/config.h"
#include "misc/net.h"
#include "prot/dns.h"

#include "host.h"
#include "file.h"
#include "cgi.h"
#include "ping.h"

#include <map>
#include <string.h>
#include <assert.h>


static int check_header(HttpReqHeader* req){
    auto requester = req->src.lock();
    if (!checkauth(requester->getip()) &&
        req->get("Proxy-Authorization") &&
        strcmp(opt.auth_string, req->get("Proxy-Authorization")+6) == 0)
    {
        addauth(requester->getip());
    }
    if (!checkauth(requester->getip())){
        HttpResHeader* res = new HttpResHeader(H407, sizeof(H407));
        res->index = req->index;
        requester->response(res);
        return 1;
    }

    if(req->get("via") && strstr(req->get("via"), "sproxy")){
        HttpResHeader* res = new HttpResHeader(H508, sizeof(H508));
        res->index = req->index;
        requester->response(res);
        return 2;
    }
    req->del("Connection");
    if(req->get("Proxy-Connection")){
        req->set("Connection", req->get("Proxy-Connection"));
        req->del("Proxy-Connection");
    }
    req->del("Upgrade");
    req->del("Public");
    req->append("Via", "HTTP/1.1 sproxy");
    return 0;
}

std::weak_ptr<Responser> distribute(HttpReqHeader* req, std::weak_ptr<Responser> responser_ptr) {
    assert(!req->src.expired());
    auto requester = req->src.lock();
    char log_buff[URLLIMIT];
    snprintf(log_buff, sizeof(log_buff), "(%s): %s %s [%s]",
            requester->getsrc(req->index), req->method,
            req->geturl().c_str(), req->get("User-Agent"));
    if(!req->hostname[0]){
        LOG("[[bad request]] %s\n", log_buff);
        HttpResHeader* res = new HttpResHeader(H400, sizeof(H400));
        res->index = req->index;
        requester->response(res);
        return std::weak_ptr<Responser>();
    }
    if (req->ismethod("GET") ||
        req->ismethod("POST") ||
        req->ismethod("PUT") ||
        req->ismethod("CONNECT") ||
        req->ismethod("HEAD") ||
        req->ismethod("DELETE") ||
        req->ismethod("OPTIONS") ||
        req->ismethod("SEND") ||
        req->ismethod("PING"))
    {
        if(req->port == 0 && !req->ismethod("SEND") && !req->ismethod("PING")){
            req->port = HTTPPORT;
        }
        strategy stra = getstrategy(req->hostname);
        if(stra.s == Strategy::block){
            LOG("[[block]] %s\n", log_buff);
            const char* header = "HTTP/1.1 403 Forbidden" CRLF "Content-Length:73" CRLF CRLF;
            HttpResHeader* res = new HttpResHeader(header, strlen(header));
            res->index = req->index;
            requester->response(res);
            requester->Send("This site is blocked, please contact administrator"
                            " for more information.\n", 73, req->index);
            return std::weak_ptr<Responser>();
        }
        if(stra.s == Strategy::local){
            LOG("[[local]] %s\n", log_buff);
            return File::getfile(req);
        }
        switch(check_header(req)){
        case 1:
            LOG("[[Authorization needed]] %s\n", log_buff);
            return std::weak_ptr<Responser>();
        case 2:
            LOG("[[redirect back]] %s\n", log_buff);
            return std::weak_ptr<Responser>();
        }
        char fprotocol[DOMAINLIMIT];
        char fhost[DOMAINLIMIT];
        uint16_t fport = opt.SPORT;
        switch(stra.s){
        case Strategy::proxy:
            strcpy(fprotocol, opt.SPROT);
            strcpy(fhost, opt.SHOST);
            fport = opt.SPORT;
            if(opt.SPORT == 0){
                HttpResHeader* res = new HttpResHeader(H400, sizeof(H400));
                res->index = req->index;
                requester->response(res);
                LOG("[[server not set]] %s\n", log_buff);
                return std::weak_ptr<Responser>();
            }
            req->del("via");
            if(strlen(opt.rewrite_auth)){
                req->set("Proxy-Authorization", std::string("Basic ") + opt.rewrite_auth);
            }
            req->should_proxy = true;
            break;
        case Strategy::direct:
            strcpy(fprotocol, req->protocol);
            strcpy(fhost, req->hostname);
            fport = req->port;
            if(req->ismethod("PING")){
                LOG("[[%s]] %s\n", getstrategystring(stra.s), log_buff);
                return std::dynamic_pointer_cast<Responser>((new Ping(req))->shared_from_this());
            }else if(req->ismethod("SEND")){
                strcpy(fprotocol, "udp");
            }
            req->del("Proxy-Authorization");
            break;
        case Strategy::rewrite:
            req->set("host", stra.ext);
        case Strategy::forward:
            if(stra.ext.empty()){
                HttpResHeader* res = new HttpResHeader(H500, sizeof(H500));
                res->index = req->index;
                requester->response(res);
                LOGE("[[destination not set]] %s\n", log_buff);
                return std::weak_ptr<Responser>();
            }
            break;
        default:{
            LOG("[[BUG]] %s\n", log_buff);
            HttpResHeader* res = new HttpResHeader(H503, sizeof(H503));
            res->index = req->index;
            requester->response(res);
            return std::weak_ptr<Responser>();}
        }
        if(!stra.ext.empty() && stra.s != Strategy::direct){
            if(spliturl(stra.ext.c_str(), fprotocol, fhost, nullptr, &fport)){
                HttpResHeader* res = new HttpResHeader(H500, sizeof(H500));
                res->index = req->index;
                requester->response(res);
                LOGE("[[ext misformat]] %s -> %s\n", log_buff, stra.ext.c_str());
                return std::weak_ptr<Responser>();
            }
        }
        if(fprotocol[0] == 0){
            strcpy(fprotocol, "http");
        }
        LOG("[[%s]] %s\n", getstrategystring(stra.s), log_buff);
        return Host::gethost(fprotocol, fhost, fport, req, std::move(responser_ptr));
    }else if (req->ismethod("ADDS")) {
        const char *strategy = req->get("s");
        const char *ext = req->get("ext");
        LOG("[[add %s]] %s %s\n", strategy, log_buff, ext);
        if(strategy && addstrategy(req->geturl().c_str(), strategy, ext ? ext:"")){
            HttpResHeader* res = new HttpResHeader(H200, sizeof(H200));
            res->index = req->index;
            requester->response(res);
        }else{
            HttpResHeader* res = new HttpResHeader(H400, sizeof(H400));
            res->index = req->index;
            requester->response(res);
        }
        return std::weak_ptr<Responser>();
    } else if (req->ismethod("DELS")) {
        strategy stra = getstrategy(req->hostname);
        LOG("[[del %s]] %s %s\n", getstrategystring(stra.s), log_buff, stra.ext.c_str());
        if(delstrategy(req->hostname)){
            HttpResHeader* res = new HttpResHeader(H200, sizeof(H200));
            res->set("Strategy", getstrategystring(stra.s));
            res->set("Ext", stra.ext);
            res->index = req->index;
            requester->response(res);
        }else{
            HttpResHeader* res = new HttpResHeader(H404, sizeof(H404));
            res->index = req->index;
            requester->response(res);
        }
        return std::weak_ptr<Responser>();
    } else if (req->ismethod("SWITCH")) {
        if(setproxy(req->geturl().c_str())){
            HttpResHeader* res = new HttpResHeader(H400, sizeof(H400));
            res->index = req->index;
            requester->response(res);
        }else{
            HttpResHeader* res = new HttpResHeader(H200, sizeof(H200));
            res->index = req->index;
            requester->response(res);
        }
    } else if (req->ismethod("TEST")){
        HttpResHeader* res = new HttpResHeader(H200, sizeof(H200));
        strategy stra = getstrategy(req->hostname);
        res->set("Strategy", getstrategystring(stra.s));
        res->set("Ext", stra.ext);
        res->index = req->index;
        requester->response(res);
    } else if(req->ismethod("FLUSH")){
        if(strcasecmp(req->hostname, "cgi") == 0){
            flushcgi();
            HttpResHeader* res = new HttpResHeader(H200, sizeof(H200));
            res->index = req->index;
            requester->response(res);
        }else if(strcasecmp(req->hostname, "strategy") == 0){
            reloadstrategy();
            HttpResHeader* res = new HttpResHeader(H200, sizeof(H200));
            res->index = req->index;
            requester->response(res);
        }else if(strcasecmp(req->hostname, "dns") == 0){
            flushdns();
            HttpResHeader* res = new HttpResHeader(H200, sizeof(H200));
            res->index = req->index;
            requester->response(res);
        }else{
            HttpResHeader* res = new HttpResHeader(H400, sizeof(H400));
            res->index = req->index;
            requester->response(res);
        }
    } else{
        LOG("[[unsported method]] %s\n", log_buff);
        HttpResHeader* res = new HttpResHeader(H405, sizeof(H405));
        res->index = req->index;
        requester->response(res);
        return std::weak_ptr<Responser>();
    }
    LOG("%s\n", log_buff);
    return std::weak_ptr<Responser>();
}

#if 0
void* Responser::request(HttpReq* req){
    void* index = request(req->header);
    while(req->body.size()){
        auto wb =req->body.pop();
        Send(wb.buff, wb.len , index);
    }
    req->header = nullptr;
    return index;
}
#endif
