#include "requester.h"
#include "misc/util.h"


Requester::Requester(std::shared_ptr<RWer> rwer) {
    if(rwer){
        init(rwer);
    }
}

void Requester::init(std::shared_ptr<RWer> rwer) {
    this->rwer = rwer;
    strncpy(source, rwer->getPeer(), sizeof(source));
    *strlchrnul(source, ':') = 0;
}

const char* Requester::getid() {
    return source;
}
