#include "res/cgi.h"
#include "prot/rpc.h"

#include <string.h>
#include <json.h>

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
        auto slist = c.ListStrategy().get_future().get();
        json_object* jsites = json_object_new_array();
        for(auto item: slist) {
            char site[DOMAINLIMIT];
            char strategy[20];
            sscanf(item.c_str(), "%s %s", site, strategy);
            json_object *jsite = json_object_new_object();
            json_object_object_add(jsite, site, json_object_new_string(strategy));
            json_object_array_add(jsites, jsite);
        }
        HttpResHeader res(H200, sizeof(H200));
        res.set("Content-Type", "application/json");
        Cookie cookie;
        cookie.path = "/";
        cookie.domain = req->Dest.hostname;
        cookie.maxage = 3600;
        for(auto i: params){
            cookie.set(i.first.c_str(), i.second.c_str());
            addcookie(res, cookie);
        }
        Response(res);
        const char* jstring = json_object_get_string(jsites);
        Send(jstring, strlen(jstring));
        json_object_put(jsites);
        Finish();
    }
    void POST(const CGI_Header* header) override {
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
        if(params.count("site") == 0 || params.count("strategy") == 0) {
            BadRequest();
            return;
        }
        SproxyClient c(getenv("ADMIN_SOCK"));
        if(!c.AddStrategy(params["site"], params["strategy"], "").get_future().get()){
            BadRequest();
            return;
        }
        HttpResHeader res(H303, sizeof(H303));
        res.set("Location", req->get("Referer"));
        Response(res);
        Finish();
    }
    void DELETE(const CGI_Header* header)override{
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
        if(params.count("site") == 0){
            BadRequest();
            return;
        }
        SproxyClient c(getenv("ADMIN_SOCK"));
        if(!c.DelStrategy(params["site"]).get_future().get()){
            BadRequest();
            return;
        }
        HttpResHeader res(H303, sizeof(H303));
        res.set("Location", req->get("Referer"));
        Response(res);
        Finish();
    }
public:
    handler(int fd, const CGI_Header* header):CgiHandler(fd, header){
    }
    ~handler(){
    }
};

CGIMAIN(handler);