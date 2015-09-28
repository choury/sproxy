#ifndef PARSE_H__
#define PARSE_H__

#include "common.h"

#include <string>
#include <map>
#include <list>

using std::string;

struct Cookie{
    string value;
    int    maxage;
    string path;
};

class Index_table;
class CGI_Header;

class HttpReqHeader{
    std::list<std::pair<string, string>> headers;
public:
    uint32_t id = 0;  // 仅由http2/choury's cgi协议使用
    uint8_t flags = 0;
    char method[20];
    char url[URLLIMIT];
    char hostname[DOMAINLIMIT];
    char path[URLLIMIT];
    char filename[URLLIMIT];
    uint16_t port;
    explicit HttpReqHeader(const char* header = nullptr);
    explicit HttpReqHeader(std::list<std::pair<string, string>>&& headers);
    explicit HttpReqHeader(CGI_Header *headers);
    void getfile();
    std::map<std::string, std::string> getparams();
    
    bool ismethod(const char* method);
    void add(const char *header, const char *value);
    void del(const char *header);
    const char* get(const char *header);
    
    int getstring(void* outbuff);
    int getframe(void* outbuff, Index_table *index_table);
    int getcgi(void *outbuff);
};

class HttpResHeader{
    std::list<std::pair<string, string>> headers;
    std::map<string, Cookie> Cookies;
public:
    uint32_t id = 0;  // 仅由http2/choury's cgi协议使用
    uint8_t flags = 0;
    char status[100];
    explicit HttpResHeader(const char* header);
    explicit HttpResHeader(std::list<std::pair<string, string>>&& headers);
    explicit HttpResHeader(CGI_Header *headers);
    
    void add(const char *header, const char *value);
    void del(const char *header);
    const char* get(const char *header);

    int getstring(void* outbuff);
    int getframe(void* outbuff, Index_table *index_table);
    int getcgi(void* outbuff);
};


#ifdef  __cplusplus
extern "C" {
#endif

typedef int (cgifunc)(int fd);
cgifunc cgimain;

void addpsite(const char * host);
void addbsite(const char * host);
int delpsite(const char * host);
int delbsite(const char * host);
int globalproxy();
bool checkproxy(const char *hostname);
bool checkblock(const char *hostname);
char *cgi_addnv(char *p, const string &name, const string &value);
char *cgi_getnv(char *p, string &name, string &value);

#ifdef  __cplusplus
}
#endif

#endif
