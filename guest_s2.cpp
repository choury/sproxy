#include "guest_s2.h"
#include "host.h"
#include "file.h"

Guest_s2::Guest_s2(Guest_s *const copy): Guest_s(copy){
    struct epoll_event event;
    event.data.ptr = this;
    event.events = EPOLLIN | EPOLLOUT;
    epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
    handleEvent = (void (Con::*)(uint32_t))&Guest_s2::defaultHE;

}



ssize_t Guest_s2::Read(void *buff, size_t size) {
    return Guest_s::Read(buff, size);
}


ssize_t Guest_s2::Write(Peer *who, const void *buff, size_t size)
{
    Http2_header header;
    memset(&header, 0, sizeof(header));
    if(idmap.left.count(who)){
        set32(header.id, idmap.left.find(who)->second);
    }else{
        who->clean(this, PEER_LOST_ERR);
        return -1;
    }
    set24(header.length, size);
    if(size == 0) {
        header.flags = END_STREAM_F;
        idmap.left.erase(who);
    }
    header.type = 0;
    Peer::Write(who, &header, sizeof(header));
    return Peer::Write(who, buff, size);
}


ssize_t Guest_s2::Write(const void* buff, size_t size) {
    return Peer::Write(this, buff, size);
}

void Guest_s2::DataProc(Http2_header* header) {
    if(idmap.right.count(get32(header->id))){
        Peer *host = idmap.right.find(get32(header->id))->second;
        host->Write(this, header+1, get24(header->length));
    }else{
        Reset(get32(header->id), ERR_STREAM_CLOSED);
    }
}

void Guest_s2::ReqProc(HttpReqHeader &req)
{
    char hostname[HOST_NAME_MAX];
    gethostname(hostname, sizeof(hostname));
    LOG("([%s]:%d):[%d] %s %s\n", sourceip, sourceport, req.id, req.method, req.url);
        
    if(req.hostname[0] && strcmp(req.hostname, hostname)){
        idmap.insert(decltype(idmap)::value_type(new Host(req, this), req.id));
    }else {
        if(req.parse()){
            LOG("([%s]:%d):[%d] parse url failed\n", sourceip, sourceport, req.id);
            throw 0;
        }
        idmap.insert(decltype(idmap)::value_type(new File(req, this), req.id));
    }
}



void Guest_s2::Response(Peer *who, HttpResHeader &res)
{
    if(idmap.left.count(who)){
        res.id = idmap.left.find(who)->second;
    }else{
        who->clean(this, PEER_LOST_ERR);
        return;
    }
    res.del("Transfer-Encoding");
    res.del("Connection");
    writelen+=res.getframe(wbuff+writelen, &request_table);
    struct epoll_event event;
    event.data.ptr = this;
    event.events = EPOLLIN | EPOLLOUT;
    epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
}


void Guest_s2::defaultHE(uint32_t events)
{
    if (events & EPOLLERR || events & EPOLLHUP) {
        int       error = 0;
        socklen_t errlen = sizeof(error);

        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (void*)&error, &errlen) == 0) {
            LOGE("([%s]:%d): guest_s error:%s\n",
                  sourceip, sourceport, strerror(error));
        }
        clean(this, INTERNAL_ERR);
        return;
    }
    
    if (events & EPOLLIN) {
        (this->*Http2_Proc)();
    }

    if (events & EPOLLOUT) {
        if (writelen) {
            int ret = Guest_s::Write();
            if (ret <= 0) {
                if (showerrinfo(ret, "guest_s write error")) {
                    clean(this, WRITE_ERR);
                }
                return;
            }
        }

        if (writelen == 0) {
            struct epoll_event event;
            event.data.ptr = this;
            event.events = EPOLLIN;
            epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
        }
    }
}


void Guest_s2::RstProc(uint32_t id, uint32_t errcode) {
    if(idmap.right.count(id)){
        if(errcode)
            LOGE("([%s]:%d): reset stream [%d]: %d\n", sourceip, sourceport, id, errcode);
        idmap.right.find(id)->second->clean(this, errcode);
        idmap.right.erase(id);
    }
}

void Guest_s2::GoawayProc(Http2_header* header) {
    clean(this, get32(header+1));
}

void Guest_s2::ErrProc(int errcode) {
    Guest::ErrProc(errcode);
}

void Guest_s2::clean(Peer *who, uint32_t errcode)
{
    if(who == this) {
        Peer::clean(who, errcode);
    }else if(idmap.left.count(who)){
        Reset(idmap.left.find(who)->second, errcode>30?ERR_INTERNAL_ERROR:errcode);
        idmap.left.erase(who);
    }
}
