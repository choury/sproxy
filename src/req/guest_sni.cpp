#include "guest_sni.h"
#include "prot/tls.h"
#include "misc/util.h"
#include "misc/net.h"
#include "misc/config.h"

#include <stdlib.h>

Guest_sni::Guest_sni(int fd, const sockaddr_storage* addr, SSL_CTX* ctx):Guest(fd, addr, ctx){
    assert(ctx == nullptr);
    rwer->SetReadCB([this](Buffer& bb){
        char *hostname = nullptr;
        int ret = parse_tls_header((char*)bb.data(), bb.len, &hostname);
        if(ret > 0){
            char buff[HEADLENLIMIT];
            int len = sprintf(buff, "CONNECT %s:%d" CRLF CRLF, hostname, (int)opt.CPORT);
            std::shared_ptr<HttpReqHeader> req = UnpackHttpReq(buff, len);
            ReqProc(req);
            rwer->SetReadCB(std::bind(&Guest_sni::ReadHE, this, _1));
        }else if(ret != -1){
            deleteLater(SNI_HOST_ERR);
        }
        free(hostname);
    });
    Http_Proc = &Guest_sni::AlwaysProc;
}

void Guest_sni::response(void*, std::shared_ptr<HttpRes> res){
    ReqStatus& status = statuslist.front();
    assert(status.res == nullptr);
    status.res = res;
    status.flags |= HTTP_NOEND_F;
    res->attach([this, &status](ChannelMessage& msg){
        assert(!statuslist.empty());
        switch(msg.type){
        case ChannelMessage::CHANNEL_MSG_HEADER: {
            auto header = std::dynamic_pointer_cast<HttpResHeader>(msg.header);
            HttpLog(getsrc(), status.req->header, header);
            rwer->Unblock();
            return 1;
        }
        case ChannelMessage::CHANNEL_MSG_DATA:
            Recv(std::move(msg.data));
            return 1;
        case ChannelMessage::CHANNEL_MSG_SIGNAL:
            Handle(msg.signal);
            return 0;
        }
        return 0;
    }, [this]{ return  rwer->cap(0); });
}
