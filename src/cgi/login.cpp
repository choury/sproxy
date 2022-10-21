#include "res/cgi.h"
#include "prot/rpc.h"

class handler: public CgiHandler{
    static SproxyClient* c;
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
        if(!c->Login(params["key"], req->get("X-Real-IP")).get_future().get()){
            Response(UnpackHttpRes(H403));
        }else{
            Response(UnpackHttpRes(H204));
        }
        Finish();
    }
public:
    handler(int fd, const char* name, const CGI_Header* header):CgiHandler(fd, name, header){
        if(c == nullptr) {
            c = new SproxyClient(getenv("ADMIN_SOCK"));
        }
    }
};

SproxyClient* handler::c = nullptr;

CGIMAIN(handler);
