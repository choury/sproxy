#include "cgi.h"
#include "net.h"
#include <unistd.h>

#include <iostream>

int cgimain(int fd){
    ssize_t readlen;
    char buff[CGI_LEN_MAX];
    HttpReqHeader *req = nullptr;
    std::map<std::string, std::string> params;
    while((readlen = read(fd, buff, sizeof(CGI_Header)))>0){
        CGI_Header *header = (CGI_Header *)buff;
        readlen += read(fd, buff + readlen, ntohs(header->contentLength));
        uint32_t cgi_id = ntohl(header->requestId);
        if(header->type == CGI_REQUEST){
            req = new HttpReqHeader(header);
        }else if(header->type == CGI_DATA){
            auto param = getparamsmap((char *)(header+1), ntohs(header->contentLength));
            params.insert(param.begin(), param.end());
        }
        if(header->flag & CGI_FLAG_END){
            auto param = getparamsmap(req->getparamstring());
            params.insert(param.begin(), param.end());

            auto cookies = req->getcookies();
            HttpResHeader res(H200);
            res.add("Content-Type", "text/plain; charset=utf-8");
//            res.cgi_id = req->cgi_id;
            Cookie cookie("haha", "haowan");
            addcookie(res, cookie);
            cookie.set("test10s", "test");
            cookie.path = "/";
            cookie.domain = req->hostname;
            cookie.maxage = 10;
            addcookie(res, cookie);
            cgi_response(fd, res, cgi_id);
            for(auto i:params){
                char buff[1024];
                cgi_write(fd, cgi_id, buff, sprintf(buff, "%s =====> %s\n", i.first.c_str(), i.second.c_str()));
            }
            cgi_write(fd, cgi_id, buff, sprintf(buff, "cookies:\n"));
            for(auto i:cookies){
                char buff[1024];
                cgi_write(fd, cgi_id, buff, sprintf(buff, "%s =====> %s\n", i.first.c_str(), i.second.c_str()));
            }
            cgi_write(fd, cgi_id, "", 0);
            params.clear();
            delete req;
        }
    }
    return 0;
}
