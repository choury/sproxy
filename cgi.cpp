#include <string.h>
#include <errno.h>

#include "cgi.h"


Cgi::Cgi(HttpReqHeader& req, Guest* guest):req(req)
{
    int fds[2];
    pid_t pid;
    socketpair(AF_UNIX, SOCK_STREAM, 0, fds);  // 创建管道
    if ((pid = fork()) == 0) { // 子进程
        close(fds[0]);   // 关闭管道的父进程端
        dup2(fds[1], STDOUT_FILENO); // 复制管道的子进程端到标准输出
        dup2(fds[1], STDIN_FILENO);  // 复制管道的子进程端到标准输入
        close(fds[1]);   // 关闭已复制的读管道
        /* 使用exec执行命令 */
        execl("./a.out","hello","test",NULL);
        LOGE("execl failed: %s\n",strerror(errno));
        exit(1);
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


ssize_t Cgi::DataProc(const void* buff, size_t size){
    return 0;
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
