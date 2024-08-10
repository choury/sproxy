#include "requester.h"

Requester::Requester(std::shared_ptr<RWer> rwer) {
    this->rwer = rwer;
}