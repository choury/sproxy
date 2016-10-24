#include "host.h"
#include "requester.h"

#ifdef CLIENT
#include "proxy.h"
#include "proxy2.h"
#else
#include "file.h"
#include "cgi.h"
#endif

#define ADDPTIP    "HTTP/1.0 200 Proxy site Added" CRLF CRLF
#define ADDBTIP    "HTTP/1.0 200 Block site Added" CRLF CRLF
#define DELPTIP    "HTTP/1.0 200 Proxy site Deleted" CRLF CRLF
#define DELBTIP    "HTTP/1.0 200 Block site Deleted" CRLF CRLF
#define EGLOBLETIP  "HTTP/1.0 200 Global proxy enabled" CRLF CRLF
#define DGLOBLETIP  "HTTP/1.0 200 Global proxy disabled" CRLF CRLF
#define SWITCHTIP   "HTTP/1.0 200 Switched proxy server" CRLF CRLF

#define BLOCKTIP    "HTTP/1.1 403 Forbidden" CRLF \
                    "Content-Length:73" CRLF CRLF \
                    "This site is blocked, please contact administrator for more information" CRLF

#define DELFTIP    "HTTP/1.0 404 The site is not found" CRLF CRLF

#define AUTHNEED    "HTTP/1.1 407 Proxy Authentication Required" CRLF \
                    "Proxy-Authenticate: Basic realm=\"Secure Area\"" CRLF \
                    "Content-Length: 0" CRLF CRLF

#define PROXYTIP    "HTTP/1.1 200 Proxy" CRLF \
                    "Content-Length:48" CRLF CRLF \
                    "This site is proxyed, you can do what you want" CRLF

#define NORMALIP    "HTTP/1.1 200 Ok" CRLF \
                    "Content-Length:56" CRLF CRLF \
                    "This site won't be proxyed, you can add it by addpsite" CRLF


char SHOST[DOMAINLIMIT];
uint16_t SPORT = 443;
Protocol SPROT = TCP;
char *auth_string=nullptr;

#ifdef CLIENT
int req_filter(HttpReqHeader& req){
    Requester *requester = dynamic_cast<Requester *>(req.src);
    req.should_proxy = checkproxy(req.hostname);
    if (auth_string &&
        !checkauth(requester->getip()) &&
        req.get("Proxy-Authorization") &&
        strcmp(auth_string, req.get("Proxy-Authorization")+6) == 0)
    {
        addauth(requester->getip());
    }
    if (auth_string && !checkauth(requester->getip())){
        LOG("%s: Authorization needed\n", requester->getsrc());
        requester->Write(AUTHNEED, strlen(AUTHNEED), requester);
        return 1;
    }
    if (checkblock(req.hostname) && !req.ismethod("DELBSITE")) {
        LOG("%s: site: %s blocked\n", requester->getsrc(), req.hostname);
        requester->Write(BLOCKTIP, strlen(BLOCKTIP), requester);
        return 1;
    } 
    if(req.get("via") && strstr(req.get("via"), "sproxy")){
        LOG("%s: [%s] redirect back!\n", requester->getsrc(), req.hostname);
        requester->Write(H400, strlen(H400), requester);
        return 1;
    }
    req.del("Connection");
    if(req.get("Proxy-Connection")){
        req.add("Connection", req.get("Proxy-Connection"));
        req.del("Proxy-Connection");
    }
    req.del("Upgrade");
    req.del("Public");
    req.del("Proxy-Authorization");
    req.append("Via", "HTTP/1.1 sproxy");
    return 0;
}

Responser* distribute(HttpReqHeader& req, Responser* responser_ptr) {
    if(req_filter(req)){
        return nullptr;
    }
    Requester *requester = dynamic_cast<Requester *>(req.src);
    if(req.url[0] == '/'){
        LOG("(%s%s): %s %s%s [%s]\n", requester->getsrc(),
            req.should_proxy?" PROXY":"", req.method,
            req.hostname, req.url, req.get("User-Agent"));
        if(!req.hostname[0]){
            requester->Write(H400, strlen(H400), requester);
            return nullptr;
        }
    }else{
        LOG("(%s%s): %s %s [%s]\n", requester->getsrc(),
            req.should_proxy?" PROXY":"", req.method,
            req.url, req.get("User-Agent"));
    }
    if (req.ismethod("GET") ||
        req.ismethod("POST") ||
        req.ismethod("PUT") ||
        req.ismethod("PATCH") ||
        req.ismethod("CONNECT") ||
        req.ismethod("HEAD") ||
        req.ismethod("SEND"))
    {
        if(req.should_proxy){
            return Proxy::getproxy(req, responser_ptr);
        }else{
            return Host::gethost(req, responser_ptr);
        }
    } else if (req.ismethod("ADDPSITE")) {
        addpsite(req.url);
        requester->Write(ADDPTIP, strlen(ADDPTIP), requester);
    } else if (req.ismethod("DELPSITE")) {
        if (delpsite(req.url)) {
            requester->Write(DELPTIP, strlen(DELPTIP), requester);
        } else {
            requester->Write(DELFTIP, strlen(DELFTIP), requester);
        }
    } else if (req.ismethod("ADDBSITE")) {
        addbsite(req.url);
        requester->Write(ADDBTIP, strlen(ADDBTIP), requester);
    } else if (req.ismethod("DELBSITE")) {
        if (delbsite(req.url)) {
            requester->Write(DELBTIP, strlen(DELBTIP), requester);
        } else {
            requester->Write(DELFTIP, strlen(DELFTIP), requester);
        }
    } else if (req.ismethod("GLOBALPROXY")) {
        if (globalproxy()) {
            requester->Write(EGLOBLETIP, strlen(EGLOBLETIP), requester);
        } else {
            requester->Write(DGLOBLETIP, strlen(DGLOBLETIP), requester);
        }
    } else if (req.ismethod("SWITCH")) {
        if(strlen(req.protocol) == 0 ||
           strcasecmp(req.protocol, "ssl") == 0)
        {
            SPROT = TCP;
        }else if(strcasecmp(req.protocol, "dtls") == 0){
            SPROT = UDP;
        }else{
            requester->Write(H400, strlen(H400), requester);
            return nullptr;
        }
        SPORT = req.port?req.port:443;
        strcpy(SHOST, req.hostname);
        flushproxy2();
        requester->Write(SWITCHTIP, strlen(SWITCHTIP), requester);
    } else if (req.ismethod("TEST")){
        if(checkblock(req.hostname)){
            requester->Write(BLOCKTIP, strlen(BLOCKTIP), requester);
            return nullptr;
        }
        if(checkproxy(req.hostname)){
            requester->Write(PROXYTIP, strlen(PROXYTIP), requester);
            return nullptr;
        }
        requester->Write(NORMALIP, strlen(NORMALIP), requester);
    } else if(req.ismethod("FLUSH")){
        if(strcasecmp(req.url, "dns") == 0){
            flushdns();
            requester->Write(H200, strlen(H200), requester);
            return nullptr;
        }
    } else{
        LOGE("%s: unsported method:%s\n", requester->getsrc(), req.method);
        requester->Write(H405, strlen(H405), requester);
        return nullptr;
    }
    return nullptr;
}

#else

Responser* distribute(HttpReqHeader& req, Responser* responser_ptr){
    Requester *requester = dynamic_cast<Requester *>(req.src);
    assert(requester);
    if(req.http_id){
        LOG("(%s [%d]): %s %s [%s]\n", requester->getsrc(), req.http_id,
            req.method, req.url, req.get("User-Agent"));
    }else{
        LOG("(%s): %s %s [%s]\n", requester->getsrc(), req.method,
            req.url, req.get("User-Agent"));
    }
    if(req.ismethod("FLUSH")){
        if(strcasecmp(req.url, "dns") == 0){
            flushdns();
            requester->Write(H200, strlen(H200), requester);
        }else if(strcasecmp(req.url, "cgi") == 0){
            flushcgi();
            requester->Write(H200, strlen(H200), requester);
        }
    } else  if (checklocal(req.hostname) && !req.ismethod("CONNECT")) {
        if (endwith(req.filename,".so")) {
            return Cgi::getcgi(req);
        } else {
            return File::getfile(req);
        }
    } else {
        return Host::gethost(req, responser_ptr);
    }
    return nullptr;
}

#endif

void Responser::closeHE(uint32_t events) {
    delete this;
}

void Responser::ResetRequester(Requester* r){
}


