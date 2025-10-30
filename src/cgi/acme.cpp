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

    void respond_with_status(const char* status, const std::string& body = "", const char* content_type = "text/plain") {
        auto res = HttpResHeader::create(status, strlen(status), req->request_id);
        res->set("Content-Length", body.length());
        if(!body.empty()) {
            res->set("Content-Type", content_type);
        }
        Response(res);
        if(!body.empty() && !req->ismethod("HEAD")) {
            Send(body.c_str(), body.size());
        }
        Finish();
    }

    void process_request() {
        if(!req->has("X-Authorized", "1") || opt.acme_state == nullptr) {
            respond_with_status(S403);
            return;
        }
        std::string domain;
        auto it = params.find("domain");
        if(it != params.end() && !it->second.empty()) {
            domain = it->second;
        } else {
            if(req->Dest.hostname[0] == '\0') {
                respond_with_status(S400);
                return;
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
            respond_with_status(S200);
        } else {
            respond_with_status(S500);
        }
    }

    void GET(const CGI_Header*) override {
        if((flag & HTTP_REQ_COMPLETED) == 0) {
            return;
        }
        static const std::string prefix = "/.well-known/acme-challenge/";
        const char* raw_path = req->path;
        if(raw_path == nullptr || !startwith(raw_path, prefix.c_str())) {
            respond_with_status(S404);
            return;
        }
        std::string token = std::string(raw_path + prefix.size());
        auto query_pos = token.find('?');
        if(query_pos != std::string::npos) {
            token.resize(query_pos);
        }
        if(token.empty()) {
            respond_with_status(S404);
            return;
        }

        char buffer[512] = {0};
        if(!acme_get_http_challenge(token.c_str(), buffer, sizeof(buffer))) {
            respond_with_status(S404);
            return;
        }

        respond_with_status(S200, buffer);
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
