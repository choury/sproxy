#include <string.h>
#include <errno.h>
#include <dlfcn.h>
#include <signal.h>
#include <sys/stat.h>

#include "cgi.h"
#include "common.h"

Cgi::Cgi(HttpReqHeader& req, Guest* guest):req(req)
{
    struct stat st;
    if (stat(req.filename, &st)) {
        LOGE("get file info failed: %s\n", strerror(errno));
        HttpResHeader res(H404);
        guest->Write(this, H404, strlen(H404));
        throw 0;
    }
    
    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds)) {  // 创建管道
        LOGE("socketpair failed: %s\n", strerror(errno));
        guest->Write(this, H500, strlen(H500));
        throw 0;
    }
    if (fork() == 0) { // 子进程
        signal(SIGPIPE, SIG_DFL);
        close(fds[0]);   // 关闭管道的父进程端
        void *handle = dlopen(req.filename,RTLD_NOW);
        if(handle == nullptr) {
            LOGE("dlopen failed: %s\n", dlerror());
            write(fds[1], H500, strlen(H500));
            exit(1);
        }
        cgifunc *func=(cgifunc *)dlsym(handle,"cgimain");
        if(func == nullptr) {
            LOGE("dlsym failed: %s\n", dlerror());
            write(fds[1], H500, strlen(H500));
            exit(1);
        }
        HttpResHeader res(H200,fds[1]);
        res.add("Transfer-Encoding","chunked");
        int ret=func(&req, &res);
        write(fds[1],CHUNCKEND, strlen(CHUNCKEND));
        exit(ret);
    } else {    // 父进程
        close(fds[1]);   // 关闭管道的子进程端
        /* 现在可在fd[0]中读写数据 */
        fd=fds[0];
        bindex.add(guest,this);
        handleEvent=(void (Con::*)(uint32_t))&Cgi::defaultHE;
        struct epoll_event event;
        event.data.ptr = this;
        event.events = EPOLLIN;
        epoll_ctl(efd, EPOLL_CTL_ADD, fd, &event);
    }
}


int Cgi::showerrinfo(int ret, const char* s) {
    if(ret < 0) {
        if(errno != EAGAIN) {
            LOGE("%s: %s\n",s,strerror(errno));
        } else {
            return 0;
        }
    }
    return 1;
}

void Cgi::defaultHE(uint32_t events)
{
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

        len=read(fd,wbuff,len);
        if (len<=0){
            if(showerrinfo(len,"cgi read error")){
                clean(this, MISCERRTIP);
            }
            return;
        }
        guest->Write(this, wbuff, len);
    }
    if (events & EPOLLOUT){
        event.events = EPOLLIN;
        epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
    }
    if (events & EPOLLERR || events & EPOLLHUP) {
        LOGE("cgi unkown error: %s\n",strerror(errno));
        clean(this, MISCERRTIP);
    }
}


void Cgi::closeHE(uint32_t events){
    delete this;
}


Cgi* Cgi::getcgi(HttpReqHeader& req, Guest* guest){
    Cgi* exist=dynamic_cast<Cgi *>(bindex.query(guest));
    if (exist != NULL) {
        exist->clean(guest);
    }
    return new Cgi(req,guest);
}
