#include "guest_sni.h"
#include "prot/tls.h"
#include "misc/util.h"
#include "misc/net.h"
#include "misc/config.h"
#include "misc/defer.h"

#include <stdlib.h>
#include <sstream>

Guest_sni::Guest_sni(int fd, const sockaddr_storage* addr, SSL_CTX* ctx):Guest(fd, addr, ctx){
    assert(ctx == nullptr);
    rwer->SetReadCB(std::bind(&Guest_sni::sniffer, this, _1, _2, _3));
    Http_Proc = &Guest_sni::AlwaysProc;
    std::stringstream ss;
    ss << "Sproxy/" << getVersion()
       << " (Build " << getBuildTime() << ") "
       <<"(" << getDeviceInfo() << ")";
    user_agent = ss.str();
}

Guest_sni::Guest_sni(std::shared_ptr<RWer> rwer, const std::string& ua):Guest(rwer), user_agent(ua) {
    rwer->SetReadCB(std::bind(&Guest_sni::sniffer, this, _1, _2, _3));
    Http_Proc = &Guest_sni::AlwaysProc;
}

size_t Guest_sni::sniffer(uint64_t, const void* data, size_t len) {
    char *hostname = nullptr;
    defer(free, hostname);
    int ret = parse_tls_header((char*)data, len, &hostname);
    if(ret > 0){
        char buff[HEADLENLIMIT];
        int slen = snprintf(buff, sizeof(buff), "CONNECT %s:%d" CRLF CRLF, hostname, 443);
        std::shared_ptr<HttpReqHeader> req = UnpackHttpReq(buff, slen);
        req->set("User-Agent", user_agent + " SEQ/" + std::to_string(req->request_id));
        ReqProc(req);
        rwer->SetReadCB(std::bind(&Guest_sni::ReadHE, this, _1, _2, _3));
    }else if(ret != -1){
        deleteLater(SNI_HOST_ERR);
    }
    return len;
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
            HttpLog(rwer->getPeer(), status.req->header, header);
            rwer->Unblock(0);
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
