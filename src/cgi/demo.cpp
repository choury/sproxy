#include "res/cgi.h"


class handler: public CgiHandler {
    void GET(const CGI_Header*) override{
        std::shared_ptr<HttpResHeader> res = HttpResHeader::create(S200, sizeof(S200), req->request_id);
        Cookie cookie("sproxy", "demo");
        res->addcookie(cookie);
        Response(res);
        Finish();
    }
public:
    handler(int sfd, int cfd, const char* name, const CGI_Header* header):CgiHandler(sfd, -1, name, header){
        close(cfd);
    }
};

CGIMAIN(handler);
