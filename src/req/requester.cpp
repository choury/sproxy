#include "requester.h"
#include "misc/util.h"


Requester::Requester(RWer* rwer) {
    if(rwer){
        init(rwer);
    }
}

void Requester::init(RWer* rwer) {
    this->rwer = rwer;
    strcpy(source, rwer->getPeer());
    *strlchrnul(source, ':') = 0;
}

const char* Requester::getid() {
    return source;
}

const char* Requester::getsrc() {
    return rwer->getPeer();
}
