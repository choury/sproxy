#include "res/cgi.h"
#include "misc/net.h"
#include <unistd.h>
#include <assert.h>
#include <json-c/json.h>

#include <iostream>

int cgi_fd;


class handle{
    uint32_t cgi_id = 0;
    HttpReqHeader* req = nullptr;
    std::map<std::string, std::string> params;
    bool queryed = false;
    bool reqended = false;
    json_object* sitelist = nullptr;

    int GET(const CGI_Header* header){
        if(header->flag & CGI_FLAG_END){
            if(queryed == false){
                cgi_query(cgi_fd, cgi_id, CGI_NAME_STRATEGYGET);
                queryed = true;
                sitelist = json_object_new_array();
                return 0;
            }else if(header->flag & CGI_FLAG_ERROR){
                HttpResHeader res(H403);
                cgi_response(cgi_fd, res, cgi_id);
                return 1;
            }else{
                HttpResHeader res(H200);
                res.add("Content-Type", "application/json");
                Cookie cookie;
                cookie.path = "/";
                cookie.domain = req->hostname;
                cookie.maxage = 10;
                for(auto i: params){
                    cookie.set(i.first.c_str(), i.second.c_str());
                    addcookie(res, cookie);
                }
                cgi_response(cgi_fd, res, cgi_id);
                const char* jstring = json_object_get_string(sitelist);
                cgi_write(cgi_fd, cgi_id, jstring, strlen(jstring));
                cgi_write(cgi_fd, cgi_id, "", 0);
                return 1;
            }
        }

        assert(header->type == CGI_VALUE);
        assert(queryed);
        CGI_NameValue *nv = (CGI_NameValue *)(header+1);
        assert(ntohl(nv->name) == CGI_NAME_STRATEGYGET);
        char site[DOMAINLIMIT];
        char strategy[20];
        sscanf((char *)nv->value, "%s %s", site, strategy);
        json_object* jsite = json_object_new_object();
        json_object_object_add(jsite, site, json_object_new_string(strategy));
        json_object_array_add(sitelist, jsite);

        return 0;
    }
    int PUT(const CGI_Header* header){
        if(header->flag & CGI_FLAG_END){
            if(queryed == false){
                if(params.count("site") && params.count("strategy")){
                    char strategystring[DOMAINLIMIT+10];
                    int len = sprintf(strategystring, "%s %s", params["site"].c_str(), params["strategy"].c_str());
                    cgi_set(cgi_fd, cgi_id, CGI_NAME_STRATEGYADD, strategystring, len+1);
                    queryed = true;
                    return 0;
                }
                HttpResHeader res(H400);
                cgi_response(cgi_fd, res, cgi_id);
                return 1;
            }else{
                HttpResHeader res(H303);
                res.add("Location", "/webui/");
                cgi_response(cgi_fd, res, cgi_id);
                return 1;
            }
        }
        return 0;
    }
    int DELETE(const CGI_Header* header){
        if(header->flag & CGI_FLAG_END){
            if(queryed == false){
                if(params.count("site")){
                    cgi_set(cgi_fd, cgi_id, CGI_NAME_STRATEGYDEL, params["site"].c_str(), params["site"].size()+1);
                    queryed = true;
                    return 0;
                }
                HttpResHeader res(H400);
                cgi_response(cgi_fd, res, cgi_id);
                return 1;
            }else{
                HttpResHeader res(H303);
                res.add("Location", "/webui/");
                cgi_response(cgi_fd, res, cgi_id);
                return 1;
            }
        }
        return 0;
    }
public:
    ~handle(){
        json_object_put(sitelist);
        delete req;
    }
    int operator()(const CGI_Header* header){
        switch(header->type){
            case CGI_REQUEST:{
                assert(req == nullptr);
                cgi_id = ntohl(header->requestId);
                req = new HttpReqHeader(header);
                auto param = getparamsmap(req->getparamstring());
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
        if(req->ismethod("post") && params.count("method")){
            if(params["method"] == "delete"){
                return DELETE(header);
            }
            if(params["method"] == "put"){
                return PUT(header);
            }
        }else{
            return GET(header);
        }
        HttpResHeader res(H400);
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

        if(cgimap[cgi_id](header)){
            cgimap.erase(cgi_id);
        }
    }
    return 0;
}
