#include "res/cgi.h"
#include "prot/rpc.h"

class handler: public CgiHandler{
    void GET(const CGI_Header*) override{
        if(strcmp(req->get("X-Authorized"), "1")) {
            Response(HttpResHeader(H403, sizeof(H403)));
            Finish();
            return;
        }
        if((flag & HTTP_REQ_COMPLETED) == 0){
            return;
        }
        SproxyClient c(getenv("ADMIN_SOCK"));
        HttpResHeader res(H200, sizeof(H200));
        res.set("Content-Type", "application/json");
        Response(res);
        char callback[DOMAINLIMIT+sizeof("setproxy(\"\");")];
        auto server = c.GetServer().get_future().get();
        Send(callback, sprintf(callback, "setproxy(\"%s\");", server.c_str()));
        Finish();
    }
    void POST(const CGI_Header* header) override{
        if(strcmp(req->get("X-Authorized"), "1")) {
            Response(HttpResHeader(H403, sizeof(H403)));
            Finish();
            return;
        }
        if(header->type == CGI_DATA){
            auto param = getparamsmap((char *)(header+1), ntohs(header->contentLength));
            params.insert(param.begin(), param.end());
        }
        if((flag & HTTP_REQ_COMPLETED) == 0){
            return;
        }
        if(params.count("proxy") == 0) {
            BadRequest();
            return;
        }
        SproxyClient c(getenv("ADMIN_SOCK"));
        if(!c.SetServer(params["proxy"]).get_future().get()){
            BadRequest();
            return;
        }
        Response(HttpResHeader(H205));
        Finish();
    }
public:
    handler(int fd, const CGI_Header* header):CgiHandler(fd, header){
    }
};

CGIMAIN(handler);