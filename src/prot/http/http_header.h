#ifndef HTTP_HEADER_H__
#define HTTP_HEADER_H__

#include "common/common.h"

#include <map>
#include <set>
#include <vector>
#include <string>
#include <memory>
#include <algorithm>

#define CRLF      "\r\n"

#define H200        "HTTP/1.1 200 OK" CRLF CRLF

#define H204        "HTTP/1.1 204 No Content" CRLF CRLF

#define H205        "HTTP/1.1 205 Reset Content" CRLF CRLF

#define H206        "HTTP/1.1 206 Partial Content" CRLF CRLF

#define H301        "HTTP/1.1 301 Moved Permanently" CRLF CRLF

#define H302        "HTTP/1.1 302 Found" CRLF CRLF

#define H303        "HTTP/1.1 303 See Other" CRLF CRLF

#define H304        "HTTP/1.1 304 Not Modified" CRLF CRLF

#define H400        "HTTP/1.1 400 Bad Request" CRLF CRLF

#define H401        "HTTP/1.1 401 Unauthorized" CRLF CRLF

#define H403        "HTTP/1.1 403 Forbidden" CRLF  CRLF

#define H404        "HTTP/1.1 404 Not Found" CRLF CRLF

#define H405        "HTTP/1.1 405 Method Not Allowed" CRLF CRLF

#define H407        "HTTP/1.1 407 Proxy Authentication Required" CRLF \
                    "Proxy-Authenticate: Basic realm=\"Secure Area\"" CRLF CRLF

#define H408        "HTTP/1.1 408 Request Timeout" CRLF CRLF

#define H416        "HTTP/1.1 416 Requested Range Not Satisfiable" CRLF CRLF

#define H429        "HTTP/1.1 429 Too Many Requests" CRLF CRLF

#define H500        "HTTP/1.1 500 Internal Server Error" CRLF CRLF

#define H502        "HTTP/1.1 502 Bad Gateway" CRLF CRLF

#define H503        "HTTP/1.1 503 Service Unavailable" CRLF CRLF

#define H504        "HTTP/1.1 504 Gateway Timeout" CRLF CRLF

#define H508        "HTTP/1.1 508 Loop Detected" CRLF CRLF

#define HCONNECT    "HTTP/1.1 200 Connection establishe" CRLF CRLF

#define AlterMethod "Alter-Method"


static inline std::string ltrim(std::string s) {
    s.erase(0, s.find_first_not_of(" "));
    return s;
}

class HttpHeader{
protected:
    std::map<std::string, std::string> headers;
public:
    uint32_t request_id = 0;
    uint32_t ctime = 0;
    std::set<std::string> cookies;

    void set(const std::string& header, const std::string& value);
    void set(const std::string& header, uint64_t value);
    void append(const std::string& header, const std::string& value);
    void del(const std::string& header);
    const char* get(const std::string& header) const;
    const std::map<std::string, std::string>& getall() const;

    virtual bool no_body() const = 0;
    virtual bool no_end() const = 0;
    virtual std::multimap<std::string, std::string> Normalize() const = 0;
    HttpHeader();
    virtual ~HttpHeader() = default;
    virtual size_t mem_usage();
};

struct Range{
    ssize_t begin;
    ssize_t end;
};

struct CaseInsensitiveCompare {
    bool operator()(const std::string& a, const std::string& b) const {
        std::string lowerA(a);
        std::string lowerB(b);
        std::transform(a.begin(), a.end(), lowerA.begin(), ::tolower);
        std::transform(b.begin(), b.end(), lowerB.begin(), ::tolower);
        return lowerA < lowerB;
    }
};

typedef std::multimap<std::string, std::string, CaseInsensitiveCompare> HeaderMap;

class HttpReqHeader: public HttpHeader{
    void postparse();
public:
    char method[20];
    struct Destination Dest;
    char path[URLLIMIT];
    std::string filename;
    std::vector<Range> ranges;
    bool chain_proxy  = false;
    explicit HttpReqHeader(HeaderMap&& headers);
    bool ismethod(const char* method) const;
    bool http_method() const;
    bool valid_method() const;
    uint16_t getDport() const;

    virtual std::multimap<std::string, std::string> Normalize() const override;
    virtual bool no_body() const override;
    virtual bool no_end() const override;

    std::map<std::string, std::string> getcookies()const;
    std::map<std::string, std::string> getparamsmap()const;
    const char* getparamstring()const;
    bool getrange();
    std::string geturl() const;
    virtual size_t mem_usage() override;
};


class Cookie{
public:
    const char *name = nullptr;
    const char *value = nullptr;
    const char *path= nullptr;
    const char *domain = nullptr;
    uint32_t maxage = 0;
    Cookie() = default;
    Cookie(const char *name, const char *value):name(name), value(value){}
    void set(const char* name, const char *value){
        this->name = name;
        this->value = value;
    }
};


class HttpResHeader: public HttpHeader{
public:
    char status[100];
    explicit HttpResHeader(HeaderMap&& headers);
    virtual std::multimap<std::string, std::string> Normalize() const override;
    virtual bool no_body() const override;
    virtual bool no_end() const override;
    void addcookie(const Cookie &cookie);
    virtual size_t mem_usage() override {
        return HttpHeader::mem_usage() + sizeof(*this);
    }
};


std::map<std::string, std::string> __attribute__((weak)) getparamsmap(const char *param, size_t len);
std::map<std::string, std::string> __attribute__((weak)) getparamsmap(const char *param);


std::shared_ptr<HttpReqHeader> UnpackHttpReq(const void* header, size_t len = 0);
std::shared_ptr<HttpResHeader> UnpackHttpRes(const void* header, size_t len = 0);
size_t PackHttpReq(std::shared_ptr<const HttpReqHeader> req, void* data, size_t len);
size_t PackHttpRes(std::shared_ptr<const HttpResHeader> res, void* data, size_t len);
#endif
