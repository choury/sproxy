#include "res/cgi.h"
#include "prot/rpc.h"

class handler: public CgiHandler{
    static SproxyClient* c;
    void GET(const CGI_Header*) override{
        if(strcmp(req->get("X-Authorized"), "1") != 0) {
            Response(UnpackHttpRes(H403, sizeof(H403)));
            Finish();
            return;
        }
        if((flag & HTTP_REQ_COMPLETED) == 0){
            return;
        }
        std::shared_ptr<HttpResHeader> res = UnpackHttpRes(H200, sizeof(H200));
        res->set("Content-Type", "application/json");
        Response(res);
        char callback[DOMAINLIMIT+sizeof("setproxy(\"\");")];
        auto server = c->GetServer().get_future().get();
        Send(callback, snprintf(callback, sizeof(callback), "setproxy(\"%s\");", server.c_str()));
        Finish();
    }
    void POST(const CGI_Header* header) override{
        if(strcmp(req->get("X-Authorized"), "1") != 0) {
            Response(UnpackHttpRes(H403, sizeof(H403)));
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
        if(!c->SetServer(params["proxy"]).get_future().get()){
            BadRequest();
            return;
        }
        Response(UnpackHttpRes(H205));
        Finish();
    }
public:
    handler(int sfd, int cfd, const char* name, const CGI_Header* header):CgiHandler(sfd, cfd, name, header){
        if(c == nullptr) {
            c = new SproxyClient(cfd);
        }
    }
};

SproxyClient* handler::c = nullptr;
CGIMAIN(handler);
