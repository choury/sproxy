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

    int POST(const CGI_Header* header){
        if(queryed == false){
            if(params.count("key")){
                cgi_set(cgi_fd, cgi_id, CGI_NAME_LOGIN, params["key"].c_str(), params["key"].size()+1);
                queryed = true;
                return 0;
            }
            HttpResHeader res(H400, sizeof(H400));
            cgi_response(cgi_fd, res, cgi_id);
        }else if(header->flag & CGI_FLAG_ERROR){
            HttpResHeader res(H403, sizeof(H403));
            cgi_response(cgi_fd, res, cgi_id);
        }else{
            HttpResHeader res(H204, sizeof(H204));
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
        if(req->ismethod("post")){
            return POST(header);
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

        if(cgimap.count(cgi_id) && cgimap[cgi_id](header)){
            cgi_write(cgi_fd, cgi_id, "", 0);
            cgimap.erase(cgi_id);
        }
    }
    return 0;
}
