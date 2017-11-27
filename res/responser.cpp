#include "req/requester.h"
#include "misc/strategy.h"

#include "proxy.h"
#include "file.h"
#include "cgi.h"
#include "ping.h"

#include <map>
#include <string.h>


std::map<std::pair<Requester*, void*>, Responser*> sessions;


static int check_header(HttpReqHeader* req){
    Requester *requester = req->src;
    if (!checkauth(requester->getip()) &&
        req->get("Proxy-Authorization") &&
        strcmp(auth_string, req->get("Proxy-Authorization")+6) == 0)
    {
        addauth(requester->getip());
    }
    if (!checkauth(requester->getip())){
        HttpResHeader* res = new HttpResHeader(H407);
        res->index = req->index;
        requester->response(res);
        return 1;
    }

    if(req->get("via") && strstr(req->get("via"), "sproxy")){
        HttpResHeader* res = new HttpResHeader(H508);
        res->index = req->index;
        requester->response(res);
        return 2;
    }
    req->del("Connection");
    if(req->get("Proxy-Connection")){
        req->add("Connection", req->get("Proxy-Connection"));
        req->del("Proxy-Connection");
    }
    req->del("Upgrade");
    req->del("Public");
    req->append("Via", "HTTP/1.1 sproxy");
    return 0;
}

Responser* distribute(HttpReqHeader* req, Responser* responser_ptr) {
    Requester *requester = req->src;
    char log_buff[URLLIMIT];
    snprintf(log_buff, sizeof(log_buff), "(%s): %s %s [%s]",
            requester->getsrc(req->index), req->method,
            req->geturl().c_str(), req->get("User-Agent"));
    if(!req->hostname[0]){
        LOG("[[bad request]] %s\n", log_buff);
        HttpResHeader* res = new HttpResHeader(H400);
        res->index = req->index;
        requester->response(res);
        return nullptr;
    }
    if (req->ismethod("GET") ||
        req->ismethod("POST") ||
        req->ismethod("PUT") ||
        req->ismethod("CONNECT") ||
        req->ismethod("HEAD") ||
        req->ismethod("DELETE") ||
        req->ismethod("SEND") ||
        req->ismethod("PING"))
    {
        if(req->port == 0 && !req->ismethod("SEND") && !req->ismethod("PING")){
            req->port = HTTPPORT;
        }
        std::string ext;
        Strategy s = getstrategy(req->hostname, ext);
        if(s == Strategy::block){
            LOG("[[block]] %s\n", log_buff);
            HttpResHeader* res = new HttpResHeader("HTTP/1.1 403 Forbidden" CRLF
                                "Content-Length:73" CRLF CRLF);
            res->index = req->index;
            requester->response(res);
            requester->Send("This site is blocked, please contact administrator"
                            " for more information.\n", 73, req->index);
            return nullptr;
        }
        if(s == Strategy::local){
            LOG("[[local]] %s\n", log_buff);
            return File::getfile(req);
        }
        switch(check_header(req)){
        case 1:
            LOG("[[Authorization needed]] %s\n", log_buff);
            return nullptr;
        case 2:
            LOG("[[redirect back]] %s\n", log_buff);
            return nullptr;
        }
        switch(s){
        case Strategy::direct:
            LOG("[[dirct]] %s\n", log_buff);
            req->del("Proxy-Authorization");
            if(req->ismethod("PING")){
                return new Ping(req);
            }else{
                return Host::gethost(req, responser_ptr);
            }
        case Strategy::forward:{
            LOG("[[forward]] %s\n", log_buff);
            char fprotocol[DOMAINLIMIT];
            char fhost[DOMAINLIMIT];
            uint16_t fport;
            if(!spliturl(ext.c_str(), fprotocol, fhost, nullptr, &fport)){
                if(req->ismethod("PING")){
                    return new Ping(fhost, fport);
                }
                if(fprotocol[0] == 0 || strcasecmp(fprotocol, "tcp") == 0 ){
                    return new Host(fhost, fport, Protocol::TCP);
                }
                if(strcasecmp(fprotocol, "udp") == 0){
                    return new Host(fhost, fport, Protocol::UDP);
                }
            }
            HttpResHeader* res = new HttpResHeader(H500);
            res->index = req->index;
            requester->response(res);
            LOGE("[[forward misformat]] %s -> %s\n", log_buff, ext.c_str());
            return nullptr;
        }
        case Strategy::proxy:
            if(SPORT == 0){
                HttpResHeader* res = new HttpResHeader(H400);
                res->index = req->index;
                requester->response(res);
                LOG("[[server not set]] %s\n", log_buff);
                return nullptr;
            }
            req->del("via");
            if(strlen(rewrite_auth)){
                req->add("Proxy-Authorization", std::string("Basic ")+rewrite_auth);
            }
            LOG("[[proxy]] %s\n", log_buff);
            req->should_proxy = true;
            return Proxy::getproxy(req, responser_ptr);
        default:{
            LOG("[[BUG]] %s\n", log_buff);
            HttpResHeader* res = new HttpResHeader(H503);
            res->index = req->index;
            requester->response(res);
            return nullptr;}
        }
    }else if (req->ismethod("ADDS")) {
        const char *strategy = req->get("s");
        const char *ext = req->get("ext");
        LOG("[[add %s]] %s %s\n", strategy, log_buff, ext);
        if(strategy && addstrategy(req->geturl().c_str(), strategy, ext ? ext:"")){
            HttpResHeader* res = new HttpResHeader(H200);
            res->index = req->index;
            requester->response(res);
        }else{
            HttpResHeader* res = new HttpResHeader(H400);
            res->index = req->index;
            requester->response(res);
        }
        return nullptr;
    } else if (req->ismethod("DELS")) {
        std::string ext;
        const char* strategy = getstrategystring(getstrategy(req->hostname, ext));
        LOG("[[del %s]] %s %s\n", strategy, log_buff, ext.c_str());
        if(delstrategy(req->hostname)){
            HttpResHeader* res = new HttpResHeader(H200);
            res->add("Strategy", strategy);
            res->add("Ext", ext);
            res->index = req->index;
            requester->response(res);
        }else{
            HttpResHeader* res = new HttpResHeader(H404);
            res->index = req->index;
            requester->response(res);
        }
        return nullptr;
    } else if (req->ismethod("SWITCH")) {
        if(setproxy(req->geturl().c_str())){
            HttpResHeader* res = new HttpResHeader(H400);
            res->index = req->index;
            requester->response(res);
        }else{
            HttpResHeader* res = new HttpResHeader(H200);
            res->index = req->index;
            requester->response(res);
        }
    } else if (req->ismethod("TEST")){
        HttpResHeader* res = new HttpResHeader("HTTP/1.1 200 Ok" CRLF
                          "Content-Length:0" CRLF CRLF);
        std::string ext;
        res->add("Strategy", getstrategystring(getstrategy(req->hostname, ext)));
        res->add("Ext", ext);
        res->index = req->index;
        requester->response(res);
    } else if(req->ismethod("FLUSH")){
        if(strcasecmp(req->hostname, "cgi") == 0){
            flushcgi();
            HttpResHeader* res = new HttpResHeader(H200);
            res->index = req->index;
            requester->response(res);
        }else if(strcasecmp(req->hostname, "strategy") == 0){
            reloadstrategy();
            HttpResHeader* res = new HttpResHeader(H200);
            res->index = req->index;
            requester->response(res);
        }else if(strcasecmp(req->hostname, "dns") == 0){
            flushdns();
            HttpResHeader* res = new HttpResHeader(H200);
            res->index = req->index;
            requester->response(res);
        }else{
            HttpResHeader* res = new HttpResHeader(H400);
            res->index = req->index;
            requester->response(res);
        }
    } else{
        LOG("[[unsported method]] %s\n", log_buff);
        HttpResHeader* res = new HttpResHeader(H405);
        res->index = req->index;
        requester->response(res);
        return nullptr;
    }
    LOG("%s\n", log_buff);
    return nullptr;
}

void* Responser::request(HttpReq* req){
    void* index = request(req->header);
    while(req->body.size()){
        auto wb =req->body.pop();
        Send(wb.buff, wb.len , index);
    }
    req->header = nullptr;
    return index;
}
