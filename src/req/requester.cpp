#include "requester.h"
#include "misc/util.h"


Requester::Requester(std::shared_ptr<RWer> rwer) {
    if(rwer){
        init(rwer);
    }
}

void Requester::init(std::shared_ptr<RWer> rwer) {
    this->rwer = rwer;
    snprintf(source, sizeof(source), "%s", rwer->getPeer());
    *strlchrnul(source, ':') = 0;
}

const char* Requester::getid() {
    return source;
}
