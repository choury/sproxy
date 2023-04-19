#include "res/cgi.h"
#include "prot/rpc.h"

#include <string.h>
#include <json.h>

class handler: public CgiHandler{
    static SproxyClient* c;
    void GET(const CGI_Header*) override{
        if(strcmp(req->get("X-Authorized"), "1")) {
            Response(UnpackHttpRes(H403, sizeof(H403)));
            Finish();
            return;
        }
        if((flag & HTTP_REQ_COMPLETED) == 0){
            return;
        }
        auto slist = c->ListStrategy().get_future().get();
        json_object* jsites = json_object_new_array();
        for(auto item: slist) {
            char site[DOMAINLIMIT];
            char strategy[20];
            sscanf(item.c_str(), "%s %s", site, strategy);
            json_object *jsite = json_object_new_object();
            json_object_object_add(jsite, site, json_object_new_string(strategy));
            json_object_array_add(jsites, jsite);
        }
        std::shared_ptr<HttpResHeader> res = UnpackHttpRes(H200, sizeof(H200));
        res->set("Content-Type", "application/json");
        Cookie cookie;
        cookie.path = "/";
        cookie.domain = req->Dest.hostname;
        cookie.maxage = 3600;
        for(auto i: params){
            cookie.set(i.first.c_str(), i.second.c_str());
            res->addcookie(cookie);
        }
        Response(res);
        const char* jstring = json_object_get_string(jsites);
        Send(jstring, strlen(jstring));
        json_object_put(jsites);
        Finish();
    }
    void POST(const CGI_Header* header) override {
        if(strcmp(req->get("X-Authorized"), "1")) {
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
        if(params["method"] == "delete"){
            return DELETE(header);
        }
        if(params["method"] == "put"){
            return PUT(header);
        }
        NotImplemented();
    }
    void PUT(const CGI_Header* header) override{
        if(strcmp(req->get("X-Authorized"), "1")) {
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
        if(params.count("site") == 0 || params.count("strategy") == 0) {
            BadRequest();
            return;
        }
        if(!c->AddStrategy(params["site"], params["strategy"], "").get_future().get()){
            BadRequest();
            return;
        }
        std::shared_ptr<HttpResHeader> res = UnpackHttpRes(H303, sizeof(H303));
        if(req->get("Referer") != nullptr){
            res->set("Location", req->get("Referer"));
        }else{
            res->set("Location", "/");
        }
        Response(res);
        Finish();
    }
    void DELETE(const CGI_Header* header)override{
        if(strcmp(req->get("X-Authorized"), "1")) {
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
        if(params.count("site") == 0){
            BadRequest();
            return;
        }
        if(!c->DelStrategy(params["site"]).get_future().get()){
            BadRequest();
            return;
        }
        std::shared_ptr<HttpResHeader> res = UnpackHttpRes(H303, sizeof(H303));
        if(req->get("Referer") != nullptr){
            res->set("Location", req->get("Referer"));
        }else{
            res->set("Location", "/");
        }
        Response(res);
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
