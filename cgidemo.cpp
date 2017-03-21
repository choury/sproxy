#include "res/cgi.h"
#include "misc/net.h"
#include <unistd.h>
#include <assert.h>
#include <json-c/json.h>

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
            res.add("Content-Type", "application/json");
            Cookie cookie("test10s", "test");
            cookie.path = "/";
            cookie.domain = req->hostname;
            cookie.maxage = 10;
            addcookie(res, cookie);
            cgi_response(fd, res, cgi_id);
            cgi_query(fd, cgi_id, CGI_NAME_STRATEGY);
            json_object* sitelist = json_object_new_array();
            while(1){
                CGI_Header nv_header;
                read(fd, &nv_header, sizeof(CGI_Header));
                
                if(nv_header.flag & CGI_FLAG_END)
                    break;
                assert(ntohl(nv_header.requestId) == cgi_id);
                assert(nv_header.type == CGI_VALUE);
                uint16_t nvlen = ntohs(nv_header.contentLength);
                CGI_NameValue *nv = (CGI_NameValue *)malloc(nvlen);
                read(fd, nv, nvlen);
                assert(ntohl(nv->name) == CGI_NAME_STRATEGY);
                char site[DOMAINLIMIT];
                char strategy[20];
                sscanf((char *)nv->value, "%s %s", site, strategy);
                json_object* jsite = json_object_new_object();
                json_object_object_add(jsite, site, json_object_new_string(strategy));
                json_object_array_add(sitelist, jsite);
                free(nv);
            }
            const char* jstring = json_object_get_string(sitelist);
            cgi_write(fd, cgi_id, jstring, strlen(jstring));
            cgi_write(fd, cgi_id, "", 0);
            json_object_put(sitelist);
            params.clear();
            delete req;
            req = nullptr;
        }
    }
    return 0;
}
