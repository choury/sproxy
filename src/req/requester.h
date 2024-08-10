#ifndef REQUESTER_H__
#define REQUESTER_H__

#include "common/base.h"
#include "prot/http/http_def.h"

class Responser;

class Requester: public Server{
protected:
public:
    explicit Requester(std::shared_ptr<RWer> rwer);

    virtual Destination getSrc() const {
        return rwer->getSrc();
    }
    virtual Destination getDst() const {
        return rwer->getDst();
    };
    virtual void response(void* index, std::shared_ptr<HttpRes> res) = 0;
};

#endif
