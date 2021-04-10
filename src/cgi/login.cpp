#include "res/cgi.h"
#include "prot/rpc.h"

class handler: public CgiHandler{
    void POST(const CGI_Header* header) override{
        if(header->type == CGI_DATA){
            auto param = getparamsmap((char *)(header+1), ntohs(header->contentLength));
            params.insert(param.begin(), param.end());
        }
        if((flag & HTTP_REQ_COMPLETED) == 0){
            return;
        }
        if(params.count("key") == 0){
            BadRequest();
            return;
        }
        SproxyClient c(getenv("ADMIN_SOCK"));
        if(!c.Login(params["key"], req->get("X-Real-IP")).get_future().get()){
            Response(HttpResHeader(H403));
        }else{
            Response(HttpResHeader(H204));
        }
        Finish();
    }
public:
    handler(int fd, const CGI_Header* header):CgiHandler(fd, header){
    }
};

CGIMAIN(handler);