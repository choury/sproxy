//
// Created by choury on 4/16/24.
//

#include "res/cgi.h"
#include <thread>

extern "C" int sendFcm(const char* title, const char* body, const char* token);

class handler: public CgiHandler {
    std::thread th;
    void POST(const CGI_Header*) override{
        if((flag & HTTP_REQ_COMPLETED) == 0){
            return;
        }
        if(params.count("title") == 0 || params.count("body") == 0 || params.count("token") == 0){
            std::shared_ptr<HttpResHeader> res = UnpackHttpRes(H400, sizeof(H400));
            Response(res);
            Finish();
            return;
        }
        th = std::thread([this] {
            if(sendFcm(params["title"].c_str(), params["body"].c_str(), params["token"].c_str()) == 0) {
                std::shared_ptr<HttpResHeader> res = UnpackHttpRes(H200, sizeof(H200));
                Response(res);
            } else {
                std::shared_ptr<HttpResHeader> res = UnpackHttpRes(H500, sizeof(H500));
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
