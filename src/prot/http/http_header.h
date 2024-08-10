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


#define S200        "200 OK"
#define S204        "204 No Content"
#define S205        "205 Reset Content"
#define S206        "206 Partial Content"
#define S301        "301 Moved Permanently"
#define S302        "302 Found"
#define S303        "303 See Other"
#define S304        "304 Not Modified"
#define S307        "307 Temporary Redirect"
#define S308        "308 Permanent Redirect"
#define S400        "400 Bad Request"
#define S401        "401 Unauthorized"
#define S403        "403 Forbidden"
#define S404        "404 Not Found"
#define S405        "405 Method Not Allowed"
#define S407        "407 Proxy Authentication Required"
#define S408        "408 Request Timeout"
#define S416        "416 Requested Range Not Satisfiable"
#define S429        "429 Too Many Requests"
#define S500        "500 Internal Server Error"
#define S502        "502 Bad Gateway"
#define S503        "503 Service Unavailable"
#define S504        "504 Gateway Timeout"
#define S508        "508 Loop Detected"

#define AlterMethod "Alter-Method"


static inline std::string ltrim(std::string s) {
    s.erase(0, s.find_first_not_of(' '));
    return s;
}

class HttpHeader{
protected:
    std::map<std::string, std::string> headers;
public:
    uint64_t request_id = 0;
    uint32_t ctime = 0;
    std::set<std::string> cookies;

    void set(const std::string& header, const std::string& value);
    void set(const std::string& header, uint64_t value);
    void append(const std::string& header, const std::string& value);
    void del(const std::string& header);
    [[nodiscard]] const char* get(const std::string& header) const;
    [[nodiscard]] const std::map<std::string, std::string>& getall() const;

    [[nodiscard]] virtual bool no_body() const = 0;
    [[nodiscard]] virtual bool no_end() const = 0;
    [[nodiscard]] virtual std::multimap<std::string, std::string> Normalize() const = 0;
    HttpHeader();
    HttpHeader(const HttpHeader&) = default;
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
public:
    char method[20];
    struct Destination Dest;
    char path[URLLIMIT];
    std::string filename;
    std::vector<Range> ranges;
    bool chain_proxy  = false;
    explicit HttpReqHeader(HeaderMap&& headers);
    HttpReqHeader(const HttpReqHeader&) = default;
    bool ismethod(const char* method) const;
    [[nodiscard]] bool http_method() const;
    [[nodiscard]] bool valid_method() const;
    [[nodiscard]] uint16_t getDport() const;

    [[nodiscard]] virtual std::multimap<std::string, std::string> Normalize() const override;
    [[nodiscard]] virtual bool no_body() const override;
    [[nodiscard]] virtual bool no_end() const override;

    void postparse();
    [[nodiscard]] std::map<std::string, std::string> getcookies()const;
    [[nodiscard]] std::map<std::string, std::string> getparamsmap()const;
    [[nodiscard]] const char* getparamstring()const;
    bool getrange();
    [[nodiscard]] std::string geturl() const;
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
    HttpResHeader(const char* status, size_t len);
    explicit HttpResHeader(HeaderMap&& headers);
    HttpResHeader(const HttpResHeader&) = default;
    [[nodiscard]] virtual std::multimap<std::string, std::string> Normalize() const override;
    [[nodiscard]] virtual bool no_body() const override;
    [[nodiscard]] virtual bool no_end() const override;
    void addcookie(const Cookie &cookie);
    virtual size_t mem_usage() override {
        return HttpHeader::mem_usage() + sizeof(*this);
    }
    static std::shared_ptr<HttpResHeader> create(const char* status, size_t len, uint64_t id);
};


std::map<std::string, std::string> __attribute__((weak)) getparamsmap(const char *param, size_t len);
std::map<std::string, std::string> __attribute__((weak)) getparamsmap(const char *param);


std::shared_ptr<HttpReqHeader> UnpackHttpReq(const void* header, size_t len = 0);
std::shared_ptr<HttpResHeader> UnpackHttpRes(const void* header, size_t len = 0);
size_t PackHttpReq(std::shared_ptr<const HttpReqHeader> req, void* data, size_t len);
size_t PackHttpRes(std::shared_ptr<const HttpResHeader> res, void* data, size_t len);

#endif
