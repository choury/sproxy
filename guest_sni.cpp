#include "guest_sni.h"

#include <string.h>

void Guest_sni::defaultHE(uint32_t events){
    if (events & EPOLLERR || events & EPOLLHUP) {
        int       error = 0;
        socklen_t errlen = sizeof(error);

        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (void*)&error, &errlen) == 0) {
            LOGE("([%s]:%d): guest error:%s\n",
                  sourceip, sourceport, strerror(error));
        }
        clean(this);
        return;
    }
    

    if (events & EPOLLOUT) {
        if (writelen) {
            int ret = Write();
            if (ret <= 0) {
                if (showerrinfo(ret, "guest_sni write error")) {
                    clean(this);
                }
                return;
            }
            if (Peer *peer = queryconnect(this))
                peer->writedcb();
        }

        if (writelen == 0) {
            struct epoll_event event;
            event.data.ptr = this;
            event.events = EPOLLIN;
            epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
        }
    }
}
