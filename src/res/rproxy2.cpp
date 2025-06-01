//
// Created by choury on 4/6/24.
//

#include "rproxy2.h"
#include "req/requester.h"
#include "misc/strategy.h"
#include "misc/util.h"
#include "prot/memio.h"

#include <map>
#include <sstream>

std::map<std::string, Rproxy2*> rproxys;

Rproxy2::Rproxy2(std::shared_ptr<RWer> rwer):Proxy2(rwer) {
}

void Rproxy2::init() {
    return Proxy2::init(true, nullptr, nullptr);
}


void Rproxy2::PushProc(uint32_t id, std::shared_ptr<HttpReqHeader> req) {
    LOG("Push frame [%d]: %s\n", (int)id, req->geturl().c_str());
    if(memcmp(req->path, "/rproxy/", 8) != 0) {
        return deleteLater(PROTOCOL_ERR);
    }
    name = req->path + 8;
    if(rproxys.count(name)) {
        return deleteLater(RPROXY_DUP);
    }
    rproxys[name] = this;
}

void Rproxy2::deleteLater(uint32_t errcode) {
    rproxys.erase(name);
    Proxy2::deleteLater(errcode);
}



static std::vector<std::string> split(const std::string& s, char delimiter) {
    std::vector<std::string> tokens;
    std::string token;
    std::istringstream tokenStream(s);
    while (std::getline(tokenStream, token, delimiter)) {
        if (!token.empty()) {
            tokens.push_back(token);
        }
    }
    return tokens;
}

void Rproxy2::distribute(std::shared_ptr<HttpReqHeader> req, std::shared_ptr<MemRWer> rw, Requester* src) {
    uint64_t id = req->request_id;
    if(!checkauth(src->getSrc().hostname, req->get("Authorization"))){
        response(rw, HttpResHeader::create(S401, sizeof(S401), id), "");
        return;
    }
    std::string filename;
    if(req->get("rproxy")) {
        filename = req->get("rproxy");
        req->del("rproxy");
    }else {
        std::string path = req->path;
        auto fragment = split(req->path, '/');
        assert(fragment.size() >= 1 && fragment[0] == "rproxy");
        if(fragment.size() == 1) {
            auto resh = HttpResHeader::create(S200, sizeof(S200), id);
            resh->set("Transfer-Encoding", "chunked");
            resh->set("Content-Type", "text/plain; charset=utf8");
            rw->SendHeader(resh);
            char buff[2048];
            rw->Send(Buffer{buff, (size_t)snprintf(buff, sizeof(buff), "======================================\n")});
            for(auto [name, rproxy]: rproxys) {
                rw->Send(Buffer{buff, (size_t)snprintf(buff, sizeof(buff), "%s [%p]: %s\n",
                                                       name.c_str(), rproxy, dumpDest(rproxy->getPeer()).c_str())});
            }
            rw->Send(Buffer{buff, (size_t)snprintf(buff, sizeof(buff), "======================================\n")});
            rw->Send(nullptr);
            return;
        }
        if(fragment.size() < 3) {
            response(rw, HttpResHeader::create(S400, sizeof(S400), id), "");
            return;
        }
        filename = fragment[1];
        memset(&req->Dest.hostname, 0, sizeof(req->Dest.hostname));
        req->Dest.port = 0;
        if(strcmp(req->Dest.protocol, "websocket")) {
            memset(&req->Dest.protocol, 0, sizeof(req->Dest.protocol));
        }
        strcpy(req->Dest.scheme, "http");
        if(spliturl(path.c_str() + 9 + filename.length(), &req->Dest, req->path)) {
            response(rw, HttpResHeader::create(S400, sizeof(S400), id), "");
            return;
        }
        if(strcmp(req->path, "/") == 0 && path.back() != '/'){
            // /rproxy/example.com => /rproxy/example.com/

            auto resh = HttpResHeader::create(S308, sizeof(S308), id);
            resh->set("Location", path + '/');
            response(rw, resh, "");
            return;
        }
        req->postparse();
        LOGD(DFILE, "rproxy: %s -> %s\n", path.c_str(), req->geturl().c_str());
    }
    req->set(STRATEGY, std::string("rproxy/")+filename);
    if(rproxys.count(filename) == 0) {
        response(rw, HttpResHeader::create(S404, sizeof(S404), id), "");
        return;
    }
    auto rproxy = rproxys[filename];
    rproxy->request(req, rw, src);
}
