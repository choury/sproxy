#include "host.h"
#include "proxy.h"
#include "guest.h"

#ifdef CLIENT
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
char *auth_string=nullptr;

#ifdef CLIENT
int req_filter(HttpReqHeader& req){
    Guest *guest = dynamic_cast<Guest *>(req.getsrc().get());
    req.should_proxy = checkproxy(req.hostname);
    if (auth_string &&
        !checkauth(guest->getip()) &&
        req.get("Proxy-Authorization") &&
        strcmp(auth_string, req.get("Proxy-Authorization")+6) == 0)
    {
        addauth(guest->getip());
    }
    if (auth_string && !checkauth(guest->getip())){
        LOG("%s: Authorization needed\n", guest->getsrc());
        guest->Write(AUTHNEED, strlen(AUTHNEED), guest);
        return 1;
    }
    if (checkblock(req.hostname)) {
        LOG("%s: site: %s blocked\n", guest->getsrc(), req.hostname);
        guest->Write(BLOCKTIP, strlen(BLOCKTIP), guest);
        return 1;
    } 
    if(req.get("via") && strstr(req.get("via"), "sproxy")){
        LOG("%s: [%s] redirect back!\n", guest->getsrc(), req.hostname);
        guest->Write(H400, strlen(H400), guest);
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

Ptr distribute(HttpReqHeader& req, Ptr responser_ptr) {
    if(req_filter(req)){
        return Ptr();
    }
    Guest *guest = dynamic_cast<Guest *>(req.getsrc().get());
    if(req.url[0] == '/'){
        LOG("(%s%s): %s %s%s [%s]\n", guest->getsrc(),
            req.should_proxy?" PROXY":"", req.method,
            req.hostname, req.url, req.get("User-Agent"));
        if(!req.hostname[0]){
            guest->Write(H400, strlen(H400), guest);
            return Ptr();
        }
    }else{
        LOG("(%s%s): %s %s [%s]\n", guest->getsrc(),
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
        guest->Write(ADDPTIP, strlen(ADDPTIP), guest);
    } else if (req.ismethod("DELPSITE")) {
        if (delpsite(req.url)) {
            guest->Write(DELPTIP, strlen(DELPTIP), guest);
        } else {
            guest->Write(DELFTIP, strlen(DELFTIP), guest);
        }
    } else if (req.ismethod("ADDBSITE")) {
        addbsite(req.url);
        guest->Write(ADDBTIP, strlen(ADDBTIP), guest);
    } else if (req.ismethod("DELBSITE")) {
        if (delbsite(req.url)) {
            guest->Write(DELBTIP, strlen(DELBTIP), guest);
        } else {
            guest->Write(DELFTIP, strlen(DELFTIP), guest);
        }
    } else if (req.ismethod("GLOBALPROXY")) {
        if (globalproxy()) {
            guest->Write(EGLOBLETIP, strlen(EGLOBLETIP), guest);
        } else {
            guest->Write(DGLOBLETIP, strlen(DGLOBLETIP), guest);
        }
    } else if (req.ismethod("SWITCH")) {
        SPORT = 443;
        spliturl(req.url, SHOST, nullptr, &SPORT);
        flushproxy2();
        guest->Write(SWITCHTIP, strlen(SWITCHTIP), guest);
    } else if (req.ismethod("TEST")){
        if(checkblock(req.hostname)){
            guest->Write(BLOCKTIP, strlen(BLOCKTIP), guest);
            return Ptr();
        }
        if(checkproxy(req.hostname)){
            guest->Write(PROXYTIP, strlen(PROXYTIP), guest);
            return Ptr();
        }
        guest->Write(NORMALIP, strlen(NORMALIP), guest);
    } else if(req.ismethod("FLUSH")){
        if(strcasecmp(req.url, "dns") == 0){
            flushdns();
            guest->Write(H200, strlen(H200), guest);
            return Ptr();
        }
    } else{
        LOGE("%s: unsported method:%s\n", guest->getsrc(), req.method);
        guest->Write(H405, strlen(H405), guest);
        return Ptr();
    }
    return Ptr();
}

#else

Ptr distribute(HttpReqHeader& req, Ptr responser_ptr){
    Guest *guest = dynamic_cast<Guest *>(req.getsrc().get());
    if(req.http_id){
        LOG("(%s [%d]): %s %s [%s]\n", guest->getsrc(), req.http_id,
            req.method, req.url, req.get("User-Agent"));
    }else{
        LOG("(%s): %s %s [%s]\n", guest->getsrc(), req.method,
            req.url, req.get("User-Agent"));
    }
    if(req.ismethod("FLUSH")){
        if(strcasecmp(req.url, "dns") == 0){
            flushdns();
            guest->Write(H200, strlen(H200), guest);
        }else if(strcasecmp(req.url, "cgi") == 0){
            flushcgi();
            guest->Write(H200, strlen(H200), guest);
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
    return Ptr();
}

#endif

void Responser::closeHE(uint32_t events) {
    delete this;
}



