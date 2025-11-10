#include "rguest3.h"
#include "prot/quic/quicio.h"

Rguest3::Rguest3(const Destination& dest, const std::string& name):
    Guest3(std::make_shared<QuicRWer>(dest, IRWerCallback::create()->onError([](int, int){}))),
    name(name)
{
    auto qrwer = std::dynamic_pointer_cast<QuicRWer>(rwer);
    char alpn[200];
    int len = snprintf(alpn, sizeof(alpn), "%cr3/%s", (char)name.length()+3, name.c_str());
    qrwer->setAlpn((const unsigned char*)alpn, len);
    std::dynamic_pointer_cast<IQuicCallback>(cb)->onConnect([this](const sockaddr_storage&, uint32_t){
        LOG("connected to rproxy3 server: %s\n", dumpDest(rwer->getDst()).c_str());
    });
}

void Rguest3::deleteLater(uint32_t errcode) {
    LOG("rproxy3 exit with code: %d\n", (int)errcode);
    exit(errcode);
}
