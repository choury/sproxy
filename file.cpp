#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/stat.h>
#include "common.h"
#include "file.h"

#define H404 "HTTP/1.1 404 Not Found" CRLF CRLF
#define H200 "HTTP/1.1 200 OK" CRLF CRLF


File::File(HttpReqHeader &req,Guest* guest):req(req){
    fd=eventfd(1,O_NONBLOCK);
    char pathname[URLLIMIT];
    sprintf(pathname,".%s",req.path);
repeat:
    struct stat st;
    if(stat(pathname, &st)){
        LOGE("get file info failed: %s\n",strerror(errno));
        HttpResHeader res(H404);
        res.add("Content-Length","0");
        guest->Write(this,wbuff,res.getstring(wbuff));
        clean(this);
        return;
    }
    if (S_ISREG(st.st_mode)) {
        ffd=open(pathname,O_RDONLY);
        if(ffd < 0){
            LOGE("open file failed: %s\n",strerror(errno));
            clean(this);
            return;
        }
        bindex.add(guest,this);
        HttpResHeader res(H200);
        sprintf((char *)wbuff,"%lu",st.st_size);
        res.add("Content-Length",(char *)wbuff);
        guest->Write(this,wbuff,res.getstring(wbuff));
    }else if(S_ISDIR(st.st_mode)){
        strcat(pathname,"/index.html");
        goto repeat;
    }
    handleEvent=(void (Con::*)(uint32_t))&File::defaultHE;
    struct epoll_event event;
    event.data.ptr = this;
    event.events = EPOLLIN;
    epoll_ctl(efd, EPOLL_CTL_ADD, fd, &event);
}


File* File::getfile(HttpReqHeader &req, Guest* guest){
    File* exist=dynamic_cast<File *>(bindex.query(guest));
    if (exist != NULL) {
        exist->clean(guest);
    }
    return new File(req,guest);
}


int File::showerrinfo(int ret, const char* s) {
    if(ret < 0 && errno != EAGAIN) {
        LOGE("%s: %s\n",s,strerror(errno));
        return 1;
    }
    return 0;
}

void File::defaultHE(uint32_t events){
    struct epoll_event event;
    event.data.ptr = this;
    Guest *guest=dynamic_cast<Guest *>(bindex.query(this));
    if( guest == NULL) {
        clean(this);
        return;
    }
    if (events & EPOLLIN){
        int len = guest->bufleft();
        if (len == 0) {
            LOGE( "The guest's write buff is full\n");
            epoll_ctl(efd, EPOLL_CTL_DEL, fd, NULL);
            return;
        }
        len=read(ffd,wbuff,len);
        if (len<=0){
            if(showerrinfo(len,"file read error")){
                clean(this);
            }
            return;
        }
        guest->Write(this,wbuff, len);
    }
    if (events & EPOLLOUT){
        event.events = EPOLLIN;
        epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
    }
    if (events & EPOLLERR || events & EPOLLHUP) {
        LOGE("file unkown error: %s\n",strerror(errno));
        clean(this);
    }
}


void File::closeHE(uint32_t events)
{
    if(ffd > 0){
        close(ffd);
    }
    delete this;
}

ssize_t File::DataProc(const void* buff, size_t size){
    return 0;
}

