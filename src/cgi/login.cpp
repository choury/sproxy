#include "res/cgi.h"

class handler: public CgiHandler{
    void POST(const CGI_Header* header) override{
        if(header->type == CGI_DATA){
            auto param = getparamsmap((char *)(header+1), ntohs(header->contentLength));
            params.insert(param.begin(), param.end());
        }
        if((flag & HTTP_REQ_COMPLETED) == 0){
            return;
        }
        if(header->type == CGI_VALUE){
            HttpResHeader res(H204, sizeof(H204));
            Response(res);
            Finish();
            return;
        }
        if(params.count("key")){
            SetValue(CGI_NAME_LOGIN, params["key"].c_str(), params["key"].size()+1);
            return;
        }
        BadRequest();
    }
public:
    handler(int fd, const CGI_Header* header):CgiHandler(fd, header){
    }
};

CGIMAIN(handler);