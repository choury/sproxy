#include "res/cgi.h"


class handler: public CgiHandler {
public:
    handler(int fd, const CGI_Header* header):CgiHandler(fd, header){
    }
};

CGIMAIN(handler);