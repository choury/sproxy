#include "res/cgi.h"


class handler: public CgiHandler {
    void GET(const CGI_Header*) override{
        if((flag & HTTP_REQ_COMPLETED) == 0){
            return;
        }
        std::shared_ptr<HttpResHeader> res = UnpackHttpRes(H200, sizeof(H200));
        Cookie cookie("sproxy", "demo");
        res->addcookie(cookie);
        Response(res);
        Finish();
    }
public:
    handler(int fd, const char* name, const CGI_Header* header):CgiHandler(fd, name, header){
    }
};

CGIMAIN(handler);
