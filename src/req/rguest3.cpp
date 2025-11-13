#include "rguest3.h"
#include "prot/quic/quicio.h"
#include "misc/job.h"

size_t Rguest3::next_retry = 1000;

Rguest3::Rguest3(const Destination& dest, const std::string& name):
    Guest3(std::make_shared<QuicRWer>(dest, IRWerCallback::create()->onError([](int, int){}))),
    dest(dest), name(name), starttime(getmtime())
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
    if(!respawned) {
        if(getmtime() - starttime > 1800000) {
            next_retry = 1000;
        } else {
            next_retry = std::min((size_t)32000, next_retry * 2);
        }
        LOG("rguest3 exit with code: %d, retry after %zds\n", (int)errcode, next_retry/1000);
        addjob_with_name([dest = dest, name = name]() {
            new Rguest3(dest, name);
        }, "Rguest3 respawn", next_retry, JOB_FLAGS_AUTORELEASE);
        respawned = true;
    }
    return Guest3::deleteLater(errcode);
}
