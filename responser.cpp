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
Ptr distribute(HttpReqHeader& req, Ptr responser_ptr) {
    Guest *guest = dynamic_cast<Guest *>(req.getsrc().get());
    req.should_proxy = checkproxy(req.hostname);
    if(req.url[0] == '/'){
        LOG("%s: %s%s %s%s [%s]\n", guest->getsrc(),
            req.should_proxy?"PROXY ":"", req.method,
            req.hostname, req.url, req.get("User-Agent"));
        if(!req.hostname[0]){
            guest->Write(H400, strlen(H400), guest);
            return Ptr();
        }
    }else{
        LOG("%s: %s%s %s [%s]\n", guest->getsrc(),
            req.should_proxy?"PROXY ":"", req.method,
            req.url, req.get("User-Agent"));
    }
    if (auth_string &&
        !checkauth(guest->getip()) &&
        req.get("Proxy-Authorization") &&
        strcmp(auth_string, req.get("Proxy-Authorization")+6) == 0)
    {
        addauth(guest->getip());
    }
    req.rmonehupinfo();
    if (req.ismethod("GET") ||
        req.ismethod("POST") ||
        req.ismethod("PUT") ||
        req.ismethod("PATCH") ||
        req.ismethod("CONNECT") ||
        req.ismethod("HEAD") ||
        req.ismethod("SEND"))
    {
        if (auth_string && !checkauth(guest->getip())){
            guest->Write(AUTHNEED, strlen(AUTHNEED), guest);
            LOG("%s: Authorization needed\n", guest->getsrc());
        }else if (checkblock(req.hostname) || checklocal(req.hostname)) {
            LOG("%s: site: %s blocked\n", guest->getsrc(), req.hostname);
            guest->Write(BLOCKTIP, strlen(BLOCKTIP), guest);
        } else {
            Host *host;
            if(req.should_proxy){
                host = Proxy::getproxy(req, responser_ptr);
            }else{
                host = Host::gethost(req, responser_ptr);
            }
            return host->request(req);
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
    new Host(req.hostname, req.port);
    req.getfile();
    new File(req.filename);
    new Cgi(req.filename);
    return Ptr();
}

#endif


void Responser::clean(uint32_t errcode, Peer* who, uint32_t id)
{
    reset_this_ptr();
    Guest *guest = dynamic_cast<Guest *>(guest_ptr.get());
    if(who == this && guest){
        guest->clean(errcode, this, id);
    }
    Peer::clean(errcode, who, id);
}

