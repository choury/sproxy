#ifndef REQUESTER_H__
#define REQUESTER_H__

#include "common/base.h"
#include "hook/reflect.h"

class RWer;
struct IMemRWerCallback;

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
    virtual std::shared_ptr<IMemRWerCallback> response(uint64_t id) = 0;

    void reflect(IVisitor& v) override {
        Server::reflect(v);
    }
};

std::string generateUA(const char* ua, const std::string& prog, uint64_t requestid);

#endif
