#ifndef PARSE_H__
#define PARSE_H__

#include <stddef.h>
#include <string>
#include <map>
#include "net.h"
#include "common.h"


using std::string;
using std::map;


struct Cookie{
    string value;
    int    maxage;
    string path;
};

class HttpReqHeader{
    map<string, string> headers;
public:
    map<string, string> params;
    uint32_t id;  // 仅由spdy协议使用
    char method[20];
    char url[URLLIMIT];
    char hostname[DOMAINLIMIT];
    char path[URLLIMIT];
    char filename[URLLIMIT];
    char extname[20];
    uint16_t port;
    explicit HttpReqHeader(const char* header);
    int parse();
    
    bool ismethod(const char* method);
    void add(const char *header, const char *value);
    void del(const char *header);
    const char* get(const char *header);
    
    int getstring(void* outbuff);
};

class HttpResHeader{
    int fd;       // 由cgi使用
    map<string, string> headers;
    map<string, Cookie> Cookies;
public:
    uint32_t id;  // 仅由spdy协议使用
    char version[20];
    char status[100];
    explicit HttpResHeader(const char* header, int fd=0);
    
    void add(const char *header, const char *value);
    void del(const char *header);
    const char* get(const char *header);

    int getstring(void* buff);
    
    int sendheader();                          // 由cgi使用
    int write(const void *buff, size_t size);  // 由cgi使用
};


#ifdef  __cplusplus
extern "C" {
#endif

typedef int (cgifunc)(const HttpReqHeader *req, HttpResHeader *res);
cgifunc cgimain;

void addpsite(const char * host);
void addbsite(const char * host);
int delpsite(const char * host);
int delbsite(const char * host);
int globalproxy();
bool checkproxy(const char *hostname);
bool checkblock(const char *hostname);

#ifdef  __cplusplus
}
#endif

#endif
