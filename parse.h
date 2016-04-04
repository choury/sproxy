#ifndef PARSE_H__
#define PARSE_H__

#include "common.h"
#include "binmap.h"

#include <string>

using std::string;


class Index_table;
struct CGI_Header;

class HttpReqHeader{
    mulmap<string, string> headers;
public:
    uint32_t http_id = 0;  // 由http2协议使用
    uint32_t cgi_id = 0;   // 由cgi 协议使用
    uint8_t flags = 0;
    char method[20];
    char url[URLLIMIT];
    char hostname[DOMAINLIMIT];
    char path[URLLIMIT];
    char filename[URLLIMIT];
    uint16_t port;
    explicit HttpReqHeader(const char* header = nullptr);
    explicit HttpReqHeader(mulmap<string, string>&& headers);
    explicit HttpReqHeader(CGI_Header *headers);
    void getfile();
    bool ismethod(const char* method);
    void add(const char *header, const char *value);
    void del(const char *header);
    const char* get(const char *header) const;
    std::set<string> getall(const char *header) const;
    
    int getstring(void* outbuff); 
    int getframe(void* outbuff, Index_table *index_table);
    int getcgi(void *outbuff);
};

class HttpResHeader{
    mulmap<string, string> headers;
public:
    uint32_t http_id = 0;  // 由http2协议使用
    uint32_t cgi_id = 0;   // 由cgi 协议使用
    uint8_t flags = 0;
    char status[100];
    explicit HttpResHeader(const char* header);
    explicit HttpResHeader(mulmap<string, string>&& headers);
    explicit HttpResHeader(CGI_Header *headers);
    
    void add(const char *header, const char *value);
    void del(const char *header);
    const char* get(const char *header) const;
    std::set<string> getall(const char *header) const;

    int getstring(void* outbuff);
    int getframe(void* outbuff, Index_table *index_table);
    int getcgi(void* outbuff);
};

// trim from start
static inline string& ltrim(std::string && s) {
    s.erase(0, s.find_first_not_of(" "));
    return s;
}

#ifdef  __cplusplus
extern "C" {
#endif

typedef int (cgifunc)(int fd);
cgifunc cgimain;

void addpsite(const char * host);
void addbsite(const char * host);
void addbip(const char * ip);
int delpsite(const char * host);
int delbsite(const char * host);
int delbip(const char * ip);
int globalproxy();
bool checkproxy(const char *hostname);
bool checkblock(const char *hostname);
bool checklocal(const char *hostname);
bool checkbip(const char *ip);
char *cgi_addnv(char *p, const string &name, const string &value);
char *cgi_getnv(char *p, string &name, string &value);

#ifdef  __cplusplus
}
#endif

#endif
