#include "cgi.h"
#include "net.h"
#include <unistd.h>

#include <iostream>

int cgimain(int fd){
    ssize_t readlen;
    char buff[CGI_LEN_MAX];
    while((readlen = read(fd, buff, sizeof(CGI_Header)))>0){
        CGI_Header *header = (CGI_Header *)buff;
        readlen += read(fd, buff + readlen, ntohs(header->contentLength));
        if(header->type == CGI_REQUEST){
            HttpReqHeader req(header);
            auto &&params = req.getparams();
            HttpResHeader res(H200);
            res.id = req.id;
            write(fd, buff, res.getcgi(buff));
            for(auto i:params){
                char buff[1024];
                cgi_write(fd,res.id, buff, sprintf(buff, "%s =====> %s\n", i.first.c_str(), i.second.c_str()));
            }
            cgi_write(fd,res.id, "", 0);
        }
    }
    return 0;
}
