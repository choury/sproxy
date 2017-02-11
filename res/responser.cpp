#include "req/requester.h"

#include "proxy.h"
#include "file.h"
#include "cgi.h"


extern void flushproxy2();

static int check_header(HttpReqHeader& req){
    Requester *requester = req.src;
    if (auth_string[0] &&
        !checkauth(requester->getip()) &&
        req.get("Proxy-Authorization") &&
        strcmp(auth_string, req.get("Proxy-Authorization")+6) == 0)
    {
        addauth(requester->getip());
    }
    if (auth_string[0] && !checkauth(requester->getip())){
        HttpResHeader res(H407);
        res.http_id = req.http_id;
        requester->response(std::move(res));
        return 1;
    }

    if(req.get("via") && strstr(req.get("via"), "sproxy")){
        HttpResHeader res(H508);
        res.http_id = req.http_id;
        requester->response(std::move(res));
        return 2;
    }
    req.del("Connection");
    if(req.get("Proxy-Connection")){
        req.add("Connection", req.get("Proxy-Connection"));
        req.del("Proxy-Connection");
    }
    req.del("Upgrade");
    req.del("Public");
    req.append("Via", "HTTP/1.1 sproxy");
    return 0;
}

Responser* distribute(HttpReqHeader& req, Responser* responser_ptr) {
    Requester *requester = req.src;
    char log_buff[URLLIMIT];
    if(req.url[0] == '/'){
        snprintf(log_buff, sizeof(log_buff), "(%s): %s %s%s [%s]",
                requester->getsrc(), req.method,
                req.hostname, req.url, req.get("User-Agent"));
        if(!req.hostname[0]){
            LOG("[[bad request]] %s\n", log_buff);
            HttpResHeader res(H400);
            res.http_id = req.http_id;
            requester->response(std::move(res));
            return nullptr;
        }
    }else{
        snprintf(log_buff, sizeof(log_buff),"(%s): %s %s [%s]",
                requester->getsrc(), req.method,
                req.url, req.get("User-Agent"));
    }
    if (req.ismethod("GET") ||
        req.ismethod("POST") ||
        req.ismethod("PUT") ||
        req.ismethod("CONNECT") ||
        req.ismethod("HEAD") ||
        req.ismethod("DELETE") ||
        req.ismethod("SEND"))
    {
        if(req.port == 0){
            req.port = HTTPPORT;
        }
        switch(getstrategy(req.hostname)){
            case Strategy::local:
                LOG("[[local]] %s\n", log_buff);
                if(index_file && endwith(req.filename, "/")){
                    strncat(req.filename, index_file, sizeof(req.filename));
                }
                if(req.ismethod("CONNECT")){
                    HttpResHeader res(H400);
                    res.http_id = req.http_id;
                    requester->response(std::move(res));
                    return nullptr;
                }else if (endwith(req.filename,".so")) {
                    return Cgi::getcgi(req);
                } else {
                    return File::getfile(req);
                }
            case Strategy::direct:
                switch(check_header(req)){
                case 1:
                    LOG("[[Authorization needed]] %s\n", log_buff);
                    return nullptr;
                case 2:
                    LOG("[[redirect back]] %s\n", log_buff);
                    return nullptr;
                }
                LOG("[[dirct]] %s\n", log_buff);
                req.del("Proxy-Authorization");
                return Host::gethost(req, responser_ptr);
            case Strategy::proxy:
                switch(check_header(req)){
                case 1:
                    LOG("[[Authorization needed]] %s\n", log_buff);
                    return nullptr;
                case 2:
                    LOG("[[redirect back]] %s\n", log_buff);
                    return nullptr;
                }
                if(SPORT == 0){
                    HttpResHeader res(H400);
                    res.http_id = req.http_id;
                    requester->response(std::move(res));
                    LOG("[[server not set]] %s\n", log_buff);
                    return nullptr;
                }
                req.del("via");
                LOG("[[proxy]] %s\n", log_buff);
                req.should_proxy = true;
                return Proxy::getproxy(req, responser_ptr);
            case Strategy::block:
                LOG("[[block]] %s\n", log_buff);
                HttpResHeader res("HTTP/1.1 403 Forbidden" CRLF
                                  "Content-Length:73" CRLF CRLF);
                res.http_id = req.http_id;
                requester->response(std::move(res));
                requester->Write("This site is blocked, please contact administrator"
                                 " for more information.\n", 73, req.http_id);
                return nullptr;
        }
    }else if (req.ismethod("ADDS")) {
        const char *strategy = req.get("s");
        LOG("[[add %s]] %s\n", strategy, log_buff);
        if(strategy && addstrategy(req.hostname, strategy)){
            HttpResHeader res(H200);
            res.http_id = req.http_id;
            requester->response(std::move(res));
        }else{
            HttpResHeader res(H400);
            res.http_id = req.http_id;
            requester->response(std::move(res));
        }
        return nullptr;
    } else if (req.ismethod("DELS")) {
        const char* strategy = getstrategystring(req.hostname);
        LOG("[[del %s]] %s\n", strategy, log_buff);
        if(delstrategy(req.hostname)){
            HttpResHeader res(H200);
            res.add("Strategy", strategy);
            res.http_id = req.http_id;
            requester->response(std::move(res));
        }else{
            HttpResHeader res(H404);
            res.http_id = req.http_id;
            requester->response(std::move(res));
        }
        return nullptr;
    } else if (req.ismethod("SWITCH")) {
        if(strlen(req.protocol) == 0 ||
            strcasecmp(req.protocol, "ssl") == 0)
        {
            SPROT = TCP;
        }else if(strcasecmp(req.protocol, "dtls") == 0){
            SPROT = UDP;
        }else{
            HttpResHeader res(H400);
            res.http_id = req.http_id;
            requester->response(std::move(res));
            return nullptr;
        }
        SPORT = req.port?req.port:443;
        strcpy(SHOST, req.hostname);
        flushproxy2();
        HttpResHeader res(H200);
        res.http_id = req.http_id;
        requester->response(std::move(res));
    } else if (req.ismethod("TEST")){
        HttpResHeader res("HTTP/1.1 200 Ok" CRLF
                          "Content-Length:0" CRLF CRLF);
        res.add("Strategy", getstrategystring(req.hostname));
        res.http_id = req.http_id;
        requester->response(std::move(res));
    } else if(req.ismethod("FLUSH")){
        if(strcasecmp(req.url, "cgi") == 0){
            flushcgi();
            HttpResHeader res(H200);
            res.http_id = req.http_id;
            requester->response(std::move(res));
        }else if(strcasecmp(req.url, "sites") == 0){
            loadsites();
            HttpResHeader res(H200);
            res.http_id = req.http_id;
            requester->response(std::move(res));
        }else{
            HttpResHeader res(H400);
            res.http_id = req.http_id;
            requester->response(std::move(res));
        }
    } else{
        LOG("[[unsported method]] %s\n", log_buff);
        HttpResHeader res(H405);
        res.http_id = req.http_id;
        requester->response(std::move(res));
        return nullptr;
    }
    LOG("%s\n", log_buff);
    return nullptr;
}

void Responser::closeHE(uint32_t events) {
    delete this;
}
