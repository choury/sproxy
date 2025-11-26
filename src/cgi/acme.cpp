#include "res/cgi.h"
#include "misc/config.h"
#include "misc/util.h"
#include "prot/rpc.h"

#include <thread>
#include <future>
#include <cstring>

extern "C" int acme_request_certificate(const char* domain,
                                        const char* contact);
extern "C" bool acme_get_http_challenge(const char* token,
                                        char* buffer,
                                        size_t buffer_len);

class handler: public CgiHandler {
    static SproxyClient* client;
    std::thread worker;

    void process_request() {
        if(!req->has("X-Authorized", "1")) {
            return Unauthorized();
        }
        if(opt.acme_state == nullptr) {
            return respondStatus(S403);
        }
        std::string domain;
        auto it = params.find("domain");
        if(it != params.end() && !it->second.empty()) {
            domain = it->second;
        } else {
            if(req->Dest.hostname[0] == '\0') {
                return respondStatus(S400);
            }
            domain = req->Dest.hostname;
        }
        std::string contact;
        auto contact_it = params.find("contact");
        if(contact_it != params.end() && !contact_it->second.empty()) {
            contact = contact_it->second;
        }

        int result = acme_request_certificate(domain.c_str(),
                                              contact.empty() ? nullptr : contact.c_str());
        bool success = (result == 0);
        if(success) {
            try {
                success = client->FlushCert().get_future().get();
            } catch(...) {
                success = false;
            }
        }

        if(success) {
            respondStatus(S200);
        } else {
            respondStatus(S500);
        }
    }

    void GET(const CGI_Header*) override {
        static const std::string prefix = "/.well-known/acme-challenge/";
        const char* raw_path = req->path;
        if(raw_path == nullptr || !startwith(raw_path, prefix.c_str())) {
            return respondStatus(S404);
        }
        std::string token = std::string(raw_path + prefix.size());
        auto query_pos = token.find('?');
        if(query_pos != std::string::npos) {
            token.resize(query_pos);
        }
        if(token.empty()) {
            return respondStatus(S404);
        }

        char buffer[512] = {0};
        if(!acme_get_http_challenge(token.c_str(), buffer, sizeof(buffer))) {
            return respondStatus(S404);
        }

        std::string body = buffer;
        auto res = HttpResHeader::create(S200, strlen(S200), req->request_id);
        res->set("Content-Length", body.length());
        res->set("Content-Type", "text/plain");
        Response(res);
        Send(body.c_str(), body.size());
        Finish();
    }

    void POST(const CGI_Header* header) override {
        if(header->type == CGI_DATA) {
            auto param = getparamsmap((char *)(header+1), ntohs(header->contentLength));
            params.insert(param.begin(), param.end());
        }
        if((flag & HTTP_REQ_COMPLETED) == 0) {
            return;
        }
        if(worker.joinable()) {
            worker.join();
        }
        worker = std::thread([this] {
            process_request();
        });
    }

public:
    handler(int sfd, int cfd, const char* name, const CGI_Header* header): CgiHandler(sfd, cfd, name, header) {
        if(client == nullptr) {
            client = new SproxyClient(cfd);
        }
    }

    ~handler() override {
        if(worker.joinable()) {
            worker.join();
        }
    }
};

SproxyClient* handler::client = nullptr;

CGIMAIN(handler);
