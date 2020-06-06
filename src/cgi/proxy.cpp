#include "res/cgi.h"
#include "misc/net.h"
#include <unistd.h>
#include <assert.h>

#include <iostream>

int cgi_fd;


class handle{
    uint32_t cgi_id = 0;
    HttpReqHeader* req = nullptr;
    std::map<std::string, std::string> params;
    bool queryed = false;
    bool reqended = false;

    int GET(const CGI_Header* header){
        if(header->flag & CGI_FLAG_END){
            if(queryed == false){
                cgi_query(cgi_fd, cgi_id, CGI_NAME_GETPROXY);
                queryed = true;
                return 0;
            }else if(header->flag & CGI_FLAG_ERROR){
                HttpResHeader res(H403, sizeof(H403));
                cgi_response(cgi_fd, res, cgi_id);
            }
        }
        assert(header->type == CGI_VALUE);
        assert(queryed);
        CGI_NameValue *nv = (CGI_NameValue *)(header+1);
        assert(ntohl(nv->name) == CGI_NAME_GETPROXY);
        HttpResHeader res(H200, sizeof(H200));
        res.set("Content-Type", "application/json");
        cgi_response(cgi_fd, res, cgi_id);
        char callback[DOMAINLIMIT+sizeof("setproxy(\"\");")];
        cgi_write(cgi_fd, cgi_id, callback, sprintf(callback, "setproxy(\"%s\");", (char *)nv->value));
        return 1;
    }
    int POST(const CGI_Header* header){
        if(queryed == false){
            if(params.count("proxy")){
                cgi_setvalue(cgi_fd, cgi_id, CGI_NAME_SETPROXY, params["proxy"].c_str(), params["proxy"].size()+1);
                queryed = true;
                return 0;
            }
            HttpResHeader res(H400, sizeof(H400));
            cgi_response(cgi_fd, res, cgi_id);
        }else if(header->flag & CGI_FLAG_ERROR){
            HttpResHeader res(H303, sizeof(H303));
            res.set("Location", "/webui/");
            cgi_response(cgi_fd, res, cgi_id);
        }else{
            HttpResHeader res(H205, sizeof(H205));
            cgi_response(cgi_fd, res, cgi_id);
        }
        return 1;
    }
public:
    ~handle(){
        delete req;
    }
    int operator()(const CGI_Header* header){
        switch(header->type){
            case CGI_REQUEST:{
                assert(req == nullptr);
                cgi_id = ntohl(header->requestId);
                req = new HttpReqHeader(header);
                auto param = req->getparamsmap();
                params.insert(param.begin(), param.end());
                break;
            }
            case CGI_DATA:{
                assert(req);
                auto param = getparamsmap((char *)(header+1), ntohs(header->contentLength));
                params.insert(param.begin(), param.end());
                break;
            }

            default:
                break;
        }
        assert(cgi_id == ntohl(header->requestId));
        if(header->flag & CGI_FLAG_END){
            reqended = true;
        }
        if(!reqended){
            return 0;
        }
        if(req->ismethod("POST")){
            return POST(header);
        }
        if(req->ismethod("GET")){
            return GET(header);
        }
        HttpResHeader res(H400, sizeof(H400));
        cgi_response(cgi_fd, res, cgi_id);
        return 1;
    }
};


static std::map<uint32_t, handle> cgimap;

int cgimain(int fd){
    ssize_t readlen;
    char buff[CGI_LEN_MAX];
    cgi_fd = fd;
    while((readlen = read(fd, buff, sizeof(CGI_Header)))>0){
        CGI_Header *header = (CGI_Header *)buff;
        int __attribute__((unused)) ret =read(fd, buff + readlen, ntohs(header->contentLength));
        assert(ret == ntohs(header->contentLength));
        uint32_t cgi_id = ntohl(header->requestId);

        if(header->type == CGI_REQUEST){
            assert(cgimap.count(cgi_id) == 0);
            cgimap[cgi_id] =  handle{};
        }
        if(header->type == CGI_RESET){
            cgimap.erase(cgi_id);
            continue;
        }
        if(cgimap.count(cgi_id) && cgimap[cgi_id](header)){
            cgi_write(cgi_fd, cgi_id, "", 0);
            cgimap.erase(cgi_id);
        }
    }
    return 0;
}
