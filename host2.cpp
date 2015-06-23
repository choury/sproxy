#include "host2.h"
#include "http2.h"

Host2::Host2(HttpReqHeader& req, Guest* guest): Host(req, guest, false){

}

void Host2::ResProc(HttpResHeader& res) {
    Guest *guest = dynamic_cast<Guest *>(queryconnect(this));
    if (guest == NULL) {
        clean(this);
        return;
    }
    guest->Response(this, res);
}

