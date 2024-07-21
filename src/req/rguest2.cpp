#include "rguest2.h"
#include "prot/sslio.h"

static const unsigned char alpn_protos_rproxy[] =
    "\x02r2";


Rguest2::Rguest2(const Destination* dest):
    Guest2(std::make_shared<SslRWer>(dest->hostname, dest->port, Protocol::TCP,
                                     [this](int ret, int code){Error(ret, code);})) {
    auto srwer = std::dynamic_pointer_cast<SslRWer>(rwer);
    srwer->set_alpn(alpn_protos_rproxy, sizeof(alpn_protos_rproxy)-1);
    srwer->SetConnectCB([this](const sockaddr_storage&){
        LOG("connected to rproxy server: %s\n", rwer->getPeer());
    });
}

void Rguest2::deleteLater(uint32_t errcode) {
    LOG("rproxy exit with code: %d\n", (int)errcode);
    exit(errcode);
}
