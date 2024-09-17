//
// Created by choury on 4/6/24.
//

#include "rproxy2.h"
#include "req/requester.h"
#include "misc/strategy.h"
#include "misc/util.h"

#include <map>
#include <sstream>

std::map<std::string, Rproxy2*> rproxys;

Rproxy2::Rproxy2(std::shared_ptr<RWer> rwer):Proxy2(rwer) {
}

void Rproxy2::init() {
    return Http2Requster::init(true);
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

void Rproxy2::distribute(std::shared_ptr<HttpReq> req, Requester* src) {
    uint64_t id = req->header->request_id;
    if(!checkauth(src->getSrc().hostname, req->header->get("Authorization"))){
        req->response(std::make_shared<HttpRes>(HttpResHeader::create(S401, sizeof(S401), id), ""));
        return;
    }
    std::string filename;
    auto header = req->header;
    if(header->get("rproxy")) {
        filename = header->get("rproxy");
        header->del("rproxy");
    }else {
        std::string path = header->path;
        auto fragment = split(header->path, '/');
        assert(fragment.size() >= 1 && fragment[0] == "rproxy");
        if(fragment.size() == 1) {
            auto resh = HttpResHeader::create(S200, sizeof(S200), id);
            resh->set("Transfer-Encoding", "chunked");
            resh->set("Content-Type", "text/plain; charset=utf8");
            auto res = std::make_shared<HttpRes>(resh);
            req->response(res);
            char buff[2048];
            res->send(buff, snprintf(buff, sizeof(buff), "======================================\n"));
            for(auto [name, rproxy]: rproxys) {
                res->send(buff, snprintf(buff, sizeof(buff), "%s [%p]: %s\n",
                                         name.c_str(), rproxy, dumpDest(rproxy->getPeer()).c_str()));
            }
            res->send(buff, snprintf(buff, sizeof(buff), "======================================\n"));
            res->send(nullptr);
            return;
        }
        if(fragment.size() < 3) {
            req->response(std::make_shared<HttpRes>(HttpResHeader::create(S400, sizeof(S400), id), ""));
            return;
        }
        filename = fragment[1];
        memset(&header->Dest.hostname, 0, sizeof(header->Dest.hostname));
        header->Dest.port = 0;
        if(strcmp(header->Dest.protocol, "websocket")) {
            memset(&header->Dest.protocol, 0, sizeof(header->Dest.protocol));
        }
        strcpy(header->Dest.scheme, "http");
        if(spliturl(path.c_str() + 9 + filename.length(), &header->Dest, header->path)) {
            req->response(std::make_shared<HttpRes>(HttpResHeader::create(S400, sizeof(S400), id), ""));
            return;
        }
        if(strcmp(header->path, "/") == 0 && path.back() != '/'){
            // /rproxy/example.com => /rproxy/example.com/

            auto resh = HttpResHeader::create(S308, sizeof(S308), id);
            resh->set("Location", path + '/');
            req->response(std::make_shared<HttpRes>(resh, ""));
            return;
        }
        header->postparse();
        LOGD(DFILE, "rproxy: %s -> %s\n", path.c_str(), header->geturl().c_str());
    }
    header->set(STRATEGY, std::string("rproxy/")+filename);
    if(rproxys.count(filename) == 0) {
        req->response(std::make_shared<HttpRes>(HttpResHeader::create(S404, sizeof(S404), id), ""));
        return;
    }
    auto rproxy = rproxys[filename];
    rproxy->request(req, src);
}
