#include "res/cgi.h"

class handler: public CgiHandler{
    void GET(const CGI_Header* header) override{
        if((flag & HTTP_REQ_COMPLETED) == 0){
            return;
        }
        if(header->type == CGI_VALUE){
            CGI_NameValue *nv = (CGI_NameValue *)(header+1);
            assert(ntohl(nv->name) == CGI_NAME_GETPROXY);
            HttpResHeader res(H200, sizeof(H200));
            res.set("Content-Type", "application/json");
            Response(res);
            char callback[DOMAINLIMIT+sizeof("setproxy(\"\");")];
            Send(callback, sprintf(callback, "setproxy(\"%s\");", (char *)nv->value));
            Finish();
            return;
        }
        Query(CGI_NAME_GETPROXY);
    }
    void POST(const CGI_Header* header) override{
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
        if(params.count("proxy")){
            SetValue(CGI_NAME_SETPROXY, params["proxy"].c_str(), params["proxy"].size()+1);
            return;
        }
        BadRequest();
    }
public:
    handler(int fd, const CGI_Header* header):CgiHandler(fd, header){
    }
};

CGIMAIN(handler);