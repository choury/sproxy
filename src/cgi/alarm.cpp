//
// Created by choury on 4/16/24.
//

#include "res/cgi.h"
#include <thread>

extern "C" int sendFcm(const char* title, const char* body, const char* token);

class handler: public CgiHandler {
    std::thread th;
    void POST(const CGI_Header* header) override{
        if(header->type == CGI_DATA){
            auto param = getparamsmap((char *)(header+1), ntohs(header->contentLength));
            params.insert(param.begin(), param.end());
        }
        if((flag & HTTP_REQ_COMPLETED) == 0){
            return;
        }
        if(params.count("title") == 0 || params.count("body") == 0 || params.count("token") == 0){
            std::shared_ptr<HttpResHeader> res = HttpResHeader::create(S400, sizeof(S400), req->request_id);
            Response(res);
            Finish();
            return;
        }
        th = std::thread([this] {
            if(sendFcm(params["title"].c_str(), params["body"].c_str(), params["token"].c_str()) == 0) {
                std::shared_ptr<HttpResHeader> res = HttpResHeader::create(S200, sizeof(S200), req->request_id);
                Response(res);
            } else {
                std::shared_ptr<HttpResHeader> res = HttpResHeader::create(S500, sizeof(S500), req->request_id);
                Response(res);
            }
            Finish();
        });
    }
public:
    handler(int sfd, int cfd, const char* name, const CGI_Header* header):CgiHandler(sfd, -1, name, header){
        close(cfd);
    }
    ~handler(){
        if(th.joinable()){
            th.join();
        }
    }
};

CGIMAIN(handler);
