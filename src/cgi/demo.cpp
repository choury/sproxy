#include "res/cgi.h"


class handler: public CgiHandler {
public:
    handler(int fd, const char* name, const CGI_Header* header):CgiHandler(fd, name, header){
    }
};

CGIMAIN(handler);
