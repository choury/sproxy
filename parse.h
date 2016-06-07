#ifndef PARSE_H__
#define PARSE_H__

#include "binmap.h"
#include "common.h"
#include "ptr.h"

#include "istring.h"

class Index_table;
struct Http2_header;
struct CGI_Header;

class HttpHeader{
protected:
    std::map<istring, std::string> headers;
    Ptr      src;
public:
    std::set<std::string> cookies;
    uint32_t http_id = 0;  // 由http2协议使用
    uint32_t cgi_id = 0;   // 由cgi 协议使用
    uint8_t flags = 0;
    bool should_proxy  = false;

    explicit HttpHeader(Ptr&& src);
//    explicit HttpHeader(mulmap<string, string> headers, Ptr&& src);

    Ptr getsrc();
    void add(const istring& header, const std::string& value);
    void add(const istring& header, int value);
    void append(const istring& header, const std::string& value);
    void del(const istring& header);
    const char* get(const char *header) const;
//    std::set<string> getall(const char *header) const;

    virtual char *getstring(size_t &len) const = 0;
    virtual Http2_header *getframe(Index_table *index_table) const = 0;
    virtual CGI_Header *getcgi() const = 0;
};

class HttpReqHeader: public HttpHeader{
    void getfile();
public:
    char method[20];
    char url[URLLIMIT];
    char hostname[DOMAINLIMIT];
    char path[URLLIMIT];
    char filename[URLLIMIT];
    uint16_t port;
    explicit HttpReqHeader(const char* header = nullptr,  Ptr &&src = Ptr());
    explicit HttpReqHeader(mulmap<istring, std::string>&& headers, Ptr &&src = Ptr());
    explicit HttpReqHeader(CGI_Header *headers, Ptr &&src = Ptr());
    bool ismethod(const char* method) const;
    
    virtual char *getstring(size_t &len) const override;
    virtual Http2_header *getframe(Index_table *index_table) const override;
    virtual CGI_Header *getcgi() const override;
};

class HttpResHeader: public HttpHeader{
public:
    char status[100];
    explicit HttpResHeader(const char* header, Ptr &&src = Ptr());
    explicit HttpResHeader(mulmap<istring, std::string>&& headers, Ptr &&src = Ptr());
    explicit HttpResHeader(CGI_Header *headers, Ptr &&src = Ptr());
    
    virtual char *getstring(size_t &len) const override;
    virtual Http2_header *getframe(Index_table *index_table) const override;
    virtual CGI_Header *getcgi() const override;
};

// trim from start
static inline std::string& ltrim(std::string && s) {
    s.erase(0, s.find_first_not_of(" "));
    return s;
}

#ifdef  __cplusplus
extern "C" {
#endif


void loadsites();
void addpsite(const char * host);
void addbsite(const char * host);
void addauth(const char * ip);
int delpsite(const char * host);
int delbsite(const char * host);
int globalproxy();
bool checkproxy(const char *hostname);
bool checkblock(const char *hostname);
bool checklocal(const char *hostname);
bool checkauth(const char *ip);

#ifdef  __cplusplus
}
#endif

#endif
