#include "host2.h"
#include "http2.h"

Host2::Host2(HttpReqHeader& req, Guest* guest): Host(req, guest, req.ismethod("CONNECT")){

}

void Host2::ResProc(HttpResHeader& res) {
    Guest *guest = dynamic_cast<Guest *>(queryconnect(this));
    if (guest == NULL) {
        clean(this, PEER_LOST_ERR);
        return;
    }
    guest->Response(this, res);
}

