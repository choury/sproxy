#include "res/cgi.h"

#include <string.h>
#include <json.h>

class handler: public CgiHandler{
    json_object* sitelist = nullptr;
    void GET(const CGI_Header* header) override{
        if((flag & HTTP_REQ_COMPLETED) == 0){
            return;
        }
        if(sitelist == nullptr){
            Query(CGI_NAME_STRATEGYGET);
            sitelist = json_object_new_array();
            return;
        }
        if(header->type == CGI_VALUE){
            CGI_NameValue *nv = (CGI_NameValue *)(header+1);
            assert(ntohl(nv->name) == CGI_NAME_STRATEGYGET);
            char site[DOMAINLIMIT];
            char strategy[20];
            sscanf((char *)nv->value, "%s %s", site, strategy);
            json_object* jsite = json_object_new_object();
            json_object_object_add(jsite, site, json_object_new_string(strategy));
            json_object_array_add(sitelist, jsite);
            if((header->flag & CGI_FLAG_END) == 0){
                return;
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
            const char* jstring = json_object_get_string(sitelist);
            Send(jstring, strlen(jstring));
            Finish();
            return;
        }
        BadRequest();
    }
    void POST(const CGI_Header* header) override {
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
        if(header->type == CGI_DATA){
            auto param = getparamsmap((char *)(header+1), ntohs(header->contentLength));
            params.insert(param.begin(), param.end());
        }
        if((flag & HTTP_REQ_COMPLETED) == 0){
            return;
        }
        if(header->type == CGI_VALUE){
            HttpResHeader res(H303, sizeof(H303));
            res.set("Location", "/webui/");
            Response(res);
            Finish();
            return;
        }
        if(params.count("site") && params.count("strategy")){
            char strategystring[DOMAINLIMIT+10];
            int len = sprintf(strategystring, "%s %s", params["site"].c_str(), params["strategy"].c_str());
            SetValue(CGI_NAME_STRATEGYADD, strategystring, len+1);
            return;
        }
        BadRequest();
    }
    void DELETE(const CGI_Header* header)override{
        if(header->type == CGI_DATA){
            auto param = getparamsmap((char *)(header+1), ntohs(header->contentLength));
            params.insert(param.begin(), param.end());
        }
        if((flag & HTTP_REQ_COMPLETED) == 0){
            return;
        }
        if(header->type == CGI_VALUE){
            HttpResHeader res(H303, sizeof(H303));
            res.set("Location", "/webui/");
            Response(res);
            Finish();
            return;
        }
        if(params.count("site")){
            SetValue(CGI_NAME_STRATEGYDEL, params["site"].c_str(), params["site"].size()+1);
            return;
        }
        BadRequest();
    }
public:
    handler(int fd, const CGI_Header* header):CgiHandler(fd, header){
    }
    ~handler(){
        json_object_put(sitelist);
    }
};

CGIMAIN(handler);