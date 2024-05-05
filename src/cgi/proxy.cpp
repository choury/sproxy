#include "res/cgi.h"
#include "prot/rpc.h"

class handler: public CgiHandler{
    static SproxyClient* c;
    void GET(const CGI_Header*) override{
        if(strcmp(req->get("X-Authorized"), "1") != 0) {
            Response(HttpResHeader::create(S403, sizeof(S403), req->request_id));
            Finish();
            return;
        }
        if((flag & HTTP_REQ_COMPLETED) == 0){
            return;
        }
        std::shared_ptr<HttpResHeader> res = HttpResHeader::create(S200, sizeof(S200), req->request_id);
        res->set("Content-Type", "application/json");
        Response(res);
        char callback[DOMAINLIMIT+sizeof("setproxy(\"\");")];
        auto server = c->GetServer().get_future().get();
        Send(callback, snprintf(callback, sizeof(callback), "setproxy(\"%s\");", server.c_str()));
        Finish();
    }
    void POST(const CGI_Header* header) override{
        if(strcmp(req->get("X-Authorized"), "1") != 0) {
            Response(HttpResHeader::create(S403, sizeof(S403), req->request_id));
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
        Response(HttpResHeader::create(S205, sizeof(S205), req->request_id));
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
