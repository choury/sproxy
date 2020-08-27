#include "requester.h"
#include "misc/util.h"


Requester::Requester(RWer* rwer) {
    this->rwer = rwer;
    strcpy(sourceip, rwer->getPeer());
    *strchrnul(sourceip, ':') = 0;
}

const char* Requester::getip() {
    return sourceip;
}

const char* Requester::getsrc() {
    return rwer->getPeer();
}
