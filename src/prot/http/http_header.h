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


#define HTTP_STATUS_MAP(X) \
    X(101, "Switching Protocols") \
    X(200, "OK") \
    X(201, "Created") \
    X(204, "No Content") \
    X(205, "Reset Content") \
    X(206, "Partial Content") \
    X(207, "Multi-Status") \
    X(301, "Moved Permanently") \
    X(302, "Found") \
    X(303, "See Other") \
    X(304, "Not Modified") \
    X(307, "Temporary Redirect") \
    X(308, "Permanent Redirect") \
    X(400, "Bad Request") \
    X(401, "Unauthorized") \
    X(403, "Forbidden") \
    X(404, "Not Found") \
    X(405, "Method Not Allowed") \
    X(407, "Proxy Authentication Required") \
    X(408, "Request Timeout") \
    X(409, "Conflict") \
    X(412, "Precondition Failed") \
    X(416, "Requested Range Not Satisfiable") \
    X(423, "Locked") \
    X(424, "Failed Dependency") \
    X(429, "Too Many Requests") \
    X(500, "Internal Server Error") \
    X(502, "Bad Gateway") \
    X(503, "Service Unavailable") \
    X(504, "Gateway Timeout") \
    X(508, "Loop Detected")

#define DEFINE_HTTP_STATUS(code, reason) inline constexpr const char S##code[] = #code " " reason;
HTTP_STATUS_MAP(DEFINE_HTTP_STATUS)
#undef DEFINE_HTTP_STATUS


#define AlterMethod "Alter-Method"


//These flags just defined for user, it will NOT be set by this class
#define HTTP_CLOSED_F       (1u<<1u)   //cls
#define HTTP_CHUNK_F        (1u<<2u)   //http1 only
#define HTTP_NOEND_F        (1u<<3u)   //http1 only
#define HTTP_REQ_COMPLETED  (1u<<4u)   //qc
#define HTTP_RES_COMPLETED  (1u<<5u)   //sc
#define HTTP_RESPOENSED     (1u<<6u)   //res has generated
#define HTTP_RST            (1u<<7u)   //got reset
#define HTTP_RECV_1ST_BYTE  (1u<<8u)   //got first byte

static inline std::string ltrim(std::string s) {
    s.erase(0, s.find_first_not_of(' '));
    return s;
}

class HttpHeader{
protected:
    std::map<std::string, std::string> headers;
public:
    uint64_t request_id = 0;
    std::set<std::string> cookies;

    HttpHeader* set(const std::string& header, const std::string& value);
    HttpHeader* set(const std::string& header, uint64_t value);
    HttpHeader* append(const std::string& header, const std::string& value);
    HttpHeader* del(const std::string& header);
    [[nodiscard]] const char* get(const std::string& header) const;
    [[nodiscard]] bool has(const std::string& header, const std::string& value = "") const;
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
    std::vector<std::tuple<std::string, uint32_t>> tracker;
    explicit HttpReqHeader(HeaderMap&& headers);
    HttpReqHeader(const HttpReqHeader&) = default;
    bool ismethod(const char* method) const;
    [[nodiscard]] bool http_method() const;
    [[nodiscard]] bool webdav_method() const;
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
    std::string name;
    std::string value;
    std::string path;
    std::string domain;
    uint32_t maxage = 0;
    bool secure = false;
    bool httponly = false;
    std::string samesite;

    Cookie() = default;
    Cookie(const std::string& name, const std::string& value):name(name), value(value){}
    explicit Cookie(const std::string& set_cookie);
    void set(const std::string& name, const std::string& value){
        this->name = name;
        this->value = value;
    }
    [[nodiscard]] std::string toString() const;
};


class HttpResHeader: public HttpHeader{
public:
    char status[100];
    bool isWebsocket = false;
    bool isTunnel = false;
    std::string websocketKey;
    HttpResHeader(const char* status, size_t len);
    explicit HttpResHeader(HeaderMap&& headers);
    HttpResHeader(const HttpResHeader&) = default;
    [[nodiscard]] virtual std::multimap<std::string, std::string> Normalize() const override;
    [[nodiscard]] virtual bool no_body() const override;
    [[nodiscard]] virtual bool no_end() const override;
    void addcookie(const Cookie &cookie);
    void markWebsocket(const char* key);
    void markTunnel();
    virtual size_t mem_usage() override {
        return HttpHeader::mem_usage() + sizeof(*this);
    }
    static std::shared_ptr<HttpResHeader> create(const char* status, size_t len, uint64_t id);
};


std::string toLower(const std::string &s);
std::map<std::string, std::string> __attribute__((weak)) getparamsmap(const char *param, size_t len);
std::map<std::string, std::string> __attribute__((weak)) getparamsmap(const char *param);


std::shared_ptr<HttpReqHeader> UnpackHttpReq(const void* header, size_t len = 0);
std::shared_ptr<HttpResHeader> UnpackHttpRes(const void* header, size_t len = 0);
size_t PackHttpReq(std::shared_ptr<const HttpReqHeader> req, void* data, size_t len);
size_t PackHttpRes(std::shared_ptr<const HttpResHeader> res, void* data, size_t len);

void HttpLog(const std::string& src, std::shared_ptr<const HttpReqHeader> req, std::shared_ptr<const HttpResHeader> res);
#endif
