#ifndef PARSE_H__
#define PARSE_H__

#include "common.h"
#include "hpack.h"

#include <string>
#include <map>
#include <list>

using std::string;

struct Cookie{
    string value;
    int    maxage;
    string path;
};


class HttpReqHeader{
    std::list<std::pair<string, string>> headers;
public:
    std::map<string, string> params;
    uint32_t id = 0;  // 仅由http2协议使用
    uint8_t flags = 0;
    char method[20];
    char url[URLLIMIT];
    char hostname[DOMAINLIMIT];
    char path[URLLIMIT];
    char filename[URLLIMIT];
    char extname[20];
    uint16_t port;
    explicit HttpReqHeader(const char* header = nullptr);
    explicit HttpReqHeader(std::list<std::pair<string, string>>&& headers);
    int parse();
    
    bool ismethod(const char* method);
    void add(const char *header, const char *value);
    void del(const char *header);
    const char* get(const char *header);
    
    int getstring(void* outbuff);
    int getframe(void* outbuff, Index_table *index_table);
};

class HttpResHeader{
    int fd;       // 由cgi使用
    std::list<std::pair<string, string>> headers;
    std::map<string, Cookie> Cookies;
public:
    uint32_t id = 0;  // 仅由http2协议使用
    uint8_t flags = 0;
    char status[100];
    explicit HttpResHeader(const char* header, int fd=0);
    explicit HttpResHeader(std::list<std::pair<string, string>>&& headers);
    
    void add(const char *header, const char *value);
    void del(const char *header);
    const char* get(const char *header);

    int getstring(void* buff);
    int getframe(void* outbuff, Index_table *index_table);
    
    int sendheader();                          // 由cgi使用
    int write(const void *outbuff, size_t size);  // 由cgi使用
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
