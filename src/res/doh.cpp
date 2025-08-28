//
// Created by chouryzhou on 2025/8/25.
//
#include "doh.h"
#include "misc/util.h"
#include "prot/dns/resolver.h"
#include "prot/memio.h"

static Doh* _doh = nullptr;

Doh::Doh() {
    assert(_doh == nullptr);
    _doh = this;
}

Doh::~Doh() {
    assert(_doh == this);
    _doh = nullptr;
}

Doh* Doh::GetInstance() {
    if(_doh == nullptr) {
        _doh = new Doh();
    }
    return _doh;
}

void Doh::DnsCB(std::shared_ptr<void> id_, const char *buff, size_t size) {
    auto id = *((uint64_t*)id_.get());
    if(!_doh->statusmap.count(id)) {
        LOGD(DDNS, "<doh> DNS callback %" PRIu64 " not found in statusmap\n", id);
        _doh->failed_count++;
        return;
    }
    auto status = _doh->statusmap[id];
    _doh->statusmap.erase(id);
    if(buff == nullptr || size == 0) {
        LOGD(DDNS, "<doh> DNS callback %" PRIu64 " failed: buff=%p, size=%zu\n", id, buff, size);
        _doh->failed_count++;
        response(status.rw, HttpResHeader::create(S502, sizeof(S502), id), "[[Bad Gateway]]\n");
        return;
    }
    LOGD(DDNS, "<doh> DNS callback %" PRIu64 " success: size=%zu\n", id, size);
    char gmt[100]; time_t now = time(nullptr);
    strftime(gmt, sizeof(gmt), "%a, %d %b %Y %H:%M:%S GMT", gmtime(&now));
    auto res = HttpResHeader::create(S200, sizeof(S200), id);
    res->set("Content-Type", "application/dns-message")
       ->set("Date", gmt);
    response(status.rw, res, std::string_view(buff, size));
    _doh->succeed_count++;
    _doh->statusmap.erase(id);
}


void Doh::request(std::shared_ptr<HttpReqHeader> req, std::shared_ptr<MemRWer> rw) {
    auto id = req->request_id;
    LOGD(DDNS, "<doh> request %" PRIu64 ": %s %s\n", id, req->method, req->geturl().c_str());
    auto _cb = IRWerCallback::create()->onError([this, id](int ret, int code) {
        LOGD(DDNS, "<doh> error %" PRIu64 ": %d/%d\n", id, ret, code);
        addjob_with_name([this,id]{statusmap.erase(id);}, "doh_clean", 0, JOB_FLAGS_AUTORELEASE);
    })->onClose([id]{
        LOGD(DDNS, "<doh> close %" PRIu64 "\n", id);
        _doh->statusmap.erase(id);
    });
    if(req->ismethod("GET")) {
        std::string query = req->getparamsmap()["dns"];
        if(query.empty()) {
            LOGD(DDNS, "<doh> GET request %" PRIu64 " failed: empty query\n", id);
            failed_count++;
            response(rw, HttpResHeader::create(S400, sizeof(S400), id), "[[empty query]]\n");
            return;
        }
        std::string decoded;
        decoded.resize(query.size());
        size_t dlen = Base64DeUrl(query.c_str(), query.size(), decoded.data());
        if(dlen == 0) {
            LOGD(DDNS, "<doh> GET request %" PRIu64 " failed: base64 decode failed\n", id);
            failed_count++;
            response(rw, HttpResHeader::create(S400, sizeof(S400), id), "[[base64 decode failed]]\n");
            return;
        }
        decoded.resize(dlen);
        LOGD(DDNS, "<doh> GET request %" PRIu64 " decoded DNS query: %zu bytes\n", id, dlen);
        statusmap[id] = DohStatus{
            .req = req,
            .rw = rw,
            .cb = _cb,
            .data = decoded,
        };
        query_raw(decoded.data(), dlen, DnsCB, std::make_shared<decltype(id)>(id));
        rw->SetCallback(_cb);
    } else if (req->ismethod("POST")){ //POST
        _cb->onRead([this, id](Buffer&& bb) -> size_t {
            if (statusmap.count(id) == 0) {
                LOGD(DDNS, "<doh> POST read %" PRIu64 " failed: not in statusmap\n", id);
                failed_count++;
                return bb.len;
            }
            auto& status = statusmap.at(id);
            if (bb.len == 0) {
                LOGD(DDNS, "<doh> POST read %" PRIu64 " EOF, submitting DNS query: %zu bytes\n", id, status.data.size());
                query_raw(status.data.data(), status.data.size(), DnsCB, std::make_shared<decltype(id)>(id));
                return 0;
            }
            LOGD(DDNS, "<doh> POST read %" PRIu64 ": %zu bytes (total: %zu)\n", id, bb.len, status.data.size() + bb.len);
            status.data.append((const char*)bb.data(), bb.len);
            return bb.len;
        });
        statusmap[id] = DohStatus{
            .req = req,
            .rw = rw,
            .cb = _cb,
            .data = "",
        };
        rw->SetCallback(_cb);
    } else {
        LOGD(DDNS, "<doh> request %" PRIu64 " failed: unsupported method %s\n", id, req->method);
        failed_count++;
        response(rw, HttpResHeader::create(S405, sizeof(S405), id), "[[Method Not Allowed]]\n");
        return;
    }
}


void Doh::dump_stat(Dumper dp, void* param) {
    dp(param, "DoH: %p, sessions: %zu, succeed: %zd, failed: %zd\n", this, statusmap.size(), succeed_count, failed_count);
    for(auto& [name, status]: statusmap) {
        dp(param, "  [%" PRIu64 "]: %s\n", name, dumpDest(status.rw->getSrc()).c_str());
    }
}

void Doh::dump_usage(Dumper dp, void *param) {
    size_t usage = 0;
    for(const auto& i : statusmap) {
        usage += sizeof(i.first) + sizeof(i.second) + i.second.rw->mem_usage();
        usage += i.second.data.capacity();
    }
    dp(param, "DoH %p: %zd, reqmap: %zd\n", this, sizeof(*this), usage);
}
