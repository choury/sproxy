#include "res/cgi.h"
#include "res/file.h"
#include "misc/config.h"
#include "misc/util.h"
#include "prot/http/http_header.h"
#include "common/common.h"

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <libxml/parser.h>
#include <libxml/tree.h>

#include <filesystem>
#include <functional>
#include <memory>
#include <cstdio>

using std::string;
using std::vector;
namespace fs = std::filesystem;
struct XmlDocDeleter {
    void operator()(xmlDoc* doc) const {
        xmlFreeDoc(doc);
    }
};
struct XmlCharDeleter {
    void operator()(xmlChar* ptr) const {
        xmlFree(ptr);
    }
};
using XmlDocPtr = std::unique_ptr<xmlDoc, XmlDocDeleter>;
using XmlCharPtr = std::unique_ptr<xmlChar, XmlCharDeleter>;

static int parse_depth(const HttpReqHeader* req) {
    const char* depth = req->get("Depth");
    if (depth == nullptr) {
        return 1;
    }
    if (strcmp(depth, "0") == 0) {
        return 0;
    }
    if (strcmp(depth, "1") == 0) {
        return 1;
    }
    if (strcasecmp(depth, "infinity") == 0) {
        return -1;
    }
    return 1;
}

static string format_http_time(time_t t, const char* fmt) {
    char buff[100];
    strftime(buff, sizeof(buff), fmt, gmtime(&t));
    return buff;
}

static bool uri_need_escape(unsigned char ch) {
    // Keep unreserved characters and '/' intact for path-style URIs
    return !(
        (ch >= 'A' && ch <= 'Z') ||
        (ch >= 'a' && ch <= 'z') ||
        (ch >= '0' && ch <= '9') ||
        ch == '-' || ch == '_' || ch == '.' || ch == '~' || ch == '/'
    );
}

static string uri_path_encode(const string& path) {
    string out;
    out.reserve(path.size());
    char buf[4];
    for (unsigned char ch : path) {
        if (uri_need_escape(ch)) {
            snprintf(buf, sizeof(buf), "%%%02X", ch);
            out.append(buf);
        } else {
            out.push_back(static_cast<char>(ch));
        }
    }
    return out;
}

class WebdavHandler : public CgiHandler {
    string fs_path;
    string href_path;
    int put_fd = -1;
    bool put_existed = false;

    bool statOrRespond(struct stat& st) {
        if (lstat(fs_path.c_str(), &st) < 0) {
            respondStatus(errno == ENOENT ? S404 : S500);
            return false;
        }
        return true;
    }

    XmlDocPtr createDavDoc(const char* root_name, xmlNsPtr& ns) {
        xmlDocPtr doc = xmlNewDoc(BAD_CAST "1.0");
        if (doc == nullptr) {
            return XmlDocPtr();
        }
        xmlNodePtr root = xmlNewNode(nullptr, BAD_CAST root_name);
        ns = xmlNewNs(root, BAD_CAST "DAV:", BAD_CAST "D");
        xmlDocSetRootElement(doc, root);
        return XmlDocPtr(doc);
    }

    bool sendXmlResponse(const char* status, XmlDocPtr doc, std::function<void(HttpResHeader*)> extra = {}) {
        if (!doc) {
            respondStatus(S500);
            return false;
        }
        xmlChar* raw = nullptr;
        int len = 0;
        xmlDocDumpFormatMemoryEnc(doc.get(), &raw, &len, "UTF-8", 1);
        doc.reset();
        XmlCharPtr out(raw);
        if (!out) {
            respondStatus(S500);
            return false;
        }
        auto res = HttpResHeader::create(status, strlen(status), req->request_id);
        res->set("Content-Type", "application/xml; charset=utf-8");
        res->set("Content-Length", len);
        if (extra) {
            extra(res.get());
        }
        Response(res);
        Send((char*)out.get(), len);
        Finish();
        return true;
    }

    void addPropResponse(xmlNodePtr root, xmlNsPtr ns, const string& href, const struct stat& st) {
        string out_href = '/' + href;
        if (S_ISDIR(st.st_mode) && !endwith(out_href.c_str(), "/")) {
            out_href.push_back('/');
        }
        out_href = uri_path_encode(out_href);
        xmlNodePtr resp = xmlNewChild(root, ns, BAD_CAST "response", nullptr);
        xmlNewChild(resp, ns, BAD_CAST "href", BAD_CAST out_href.c_str());
        xmlNodePtr propstat = xmlNewChild(resp, ns, BAD_CAST "propstat", nullptr);
        xmlNodePtr prop = xmlNewChild(propstat, ns, BAD_CAST "prop", nullptr);

        xmlNewChild(prop, ns, BAD_CAST "displayname", BAD_CAST basename(href.c_str()));
        xmlNodePtr resourcetype = xmlNewChild(prop, ns, BAD_CAST "resourcetype", nullptr);
        if (S_ISDIR(st.st_mode)) {
            xmlNewChild(resourcetype, ns, BAD_CAST "collection", nullptr);
            xmlNewChild(prop, ns, BAD_CAST "getcontenttype", BAD_CAST "httpd/unix-directory");
        } else {
            xmlNewChild(prop, ns, BAD_CAST "getcontentlength", BAD_CAST std::to_string(st.st_size).c_str());
            xmlNewChild(prop, ns, BAD_CAST "getcontenttype", BAD_CAST "application/octet-stream");
        }

        xmlNewChild(prop, ns, BAD_CAST "creationdate", BAD_CAST format_http_time(st.st_ctime, "%Y-%m-%dT%H:%M:%SZ").c_str());
        xmlNewChild(prop, ns, BAD_CAST "getlastmodified", BAD_CAST format_http_time(st.st_mtime, "%a, %d %b %Y %H:%M:%S GMT").c_str());
        xmlNewChild(prop, ns, BAD_CAST "getetag", BAD_CAST make_etag(st).c_str());
        xmlNewChild(prop, ns, BAD_CAST "supportedlock", nullptr);

        xmlNewChild(propstat, ns, BAD_CAST "status", BAD_CAST "HTTP/1.1 200 OK");
    }

    void handleCopyMove(bool move) {
        if (fs_path.empty()) {
            return respondStatus(S403);
        }
        const char* dest_header = req->get("Destination");
        if (dest_header == nullptr) {
            return respondStatus(S400);
        }
        char dest_path[URLLIMIT] = {0};
        char decoded_dest[URLLIMIT] = {0};
        struct Destination dest = {};
        spliturl(dest_header, &dest, dest_path);
        URLDecode(decoded_dest, dest_path, 0);
        string dest_rel = resolve(decoded_dest);
        if (!startwith(dest_rel.c_str(), "webdav/")) {
            return respondStatus(S403);
        }
        string dest_fs = pathjoin(opt.webdav_root, dest_rel.substr(7));
        fs::path src(fs_path);
        fs::path dst(dest_fs);
        if (dst == src) {
            return respondStatus(S403);
        }
        string src_str = src.lexically_normal().string();
        string dst_str = dst.lexically_normal().string();
        string src_prefix = src_str;
        if (!src_prefix.empty() && src_prefix.back() != '/') {
            src_prefix.push_back('/');
        }
        if (startwith(dst_str.c_str(), src_prefix.c_str())) {
            return respondStatus(S508);
        }
        struct stat st{};
        if (!statOrRespond(st)) {
            return;
        }
        bool overwrite = true;
        if (const char* o = req->get("Overwrite")) {
            overwrite = !(o[0] == 'F' || o[0] == 'f' || o[0] == '0');
        }
        bool dst_exists = fs::exists(dst);
        if (dst_exists && !overwrite) {
            return respondStatus(S412);
        }
        fs::path dst_parent = dst.parent_path();
        if (!dst_parent.empty() && !fs::exists(dst_parent)) {
            return respondStatus(S409);
        }
        if (dst_exists && overwrite) {
            std::error_code ec;
            fs::remove_all(dst, ec);
            if (ec) {
                LOGE("[webdav] remove destination %s failed: %s\n", dst_str.c_str(), ec.message().c_str());
                return respondStatus(S500);
            }
        }

        std::error_code ec;
        bool created = !dst_exists;
        if (move) {
            fs::rename(src, dst, ec);
            if (ec) {
                fs::copy_options opts = fs::copy_options::recursive | fs::copy_options::overwrite_existing;
                if (S_ISDIR(st.st_mode) && parse_depth(req.get()) == 0) {
                    opts = fs::copy_options::directories_only | fs::copy_options::overwrite_existing;
                }
                fs::copy(src, dst, opts, ec);
                if (ec) {
                    LOGE("[webdav] move(copy) %s -> %s failed: %s\n", src_str.c_str(), dst_str.c_str(), ec.message().c_str());
                    return respondStatus(S500);
                }
                fs::remove_all(src, ec);
                if (ec) {
                    LOGE("[webdav] cleanup %s failed: %s\n", src_str.c_str(), ec.message().c_str());
                    return respondStatus(S500);
                }
            }
        } else {
            fs::copy_options opts = fs::copy_options::overwrite_existing;
            if (S_ISDIR(st.st_mode)) {
                int depth = parse_depth(req.get());
                if (depth == 0) {
                    opts |= fs::copy_options::directories_only;
                } else {
                    opts |= fs::copy_options::recursive;
                }
            }
            if (S_ISREG(st.st_mode)) {
                fs::copy_file(src, dst, opts, ec);
            } else {
                fs::copy(src, dst, opts, ec);
            }
            if (ec) {
                LOGE("[webdav] copy %s -> %s failed: %s\n", src_str.c_str(), dst_str.c_str(), ec.message().c_str());
                return respondStatus(S500);
            }
        }
        respondStatus(created ? S201 : S204);
    }
public:
    WebdavHandler(int sfd, int cfd, const char* name, const CGI_Header* header)
        : CgiHandler(sfd, -1, name, header) {
        close(cfd);
        href_path = resolve(req->filename);
        if(href_path == "webdav") {
            fs_path = opt.webdav_root;
        }else if(startwith(href_path.c_str(), "webdav/" )){
            fs_path = pathjoin(opt.webdav_root, href_path.substr(7));
        }else{
            // wrong path
            return;
        }
    }

    ~WebdavHandler() override {
        if(put_fd >= 0) {
            close(put_fd);
        }
    }

    void PUT(const CGI_Header* header) override {
        if(!req->has("X-Authorized", "1")) {
            return Unauthorized();
        }
        if (fs_path.empty()) {
            return respondStatus(S403);
        }
        if(put_fd < 0) {
            fs::path target(fs_path);
            fs::path parent = target.parent_path();
            if (!fs::exists(parent)) {
                return respondStatus(S409);
            }
            put_existed = fs::exists(target);
            put_fd = ::open(fs_path.c_str(), O_CREAT | O_WRONLY | O_TRUNC, 0644);
            if (put_fd < 0) {
                LOGE("[webdav] open %s failed: %s\n", fs_path.c_str(), strerror(errno));
                return respondStatus(S500);
            }
        }
        if (header->type == CGI_DATA) {
            size_t len = ntohs(header->contentLength);
            const char* data = (const char*)(header + 1);
            ssize_t ret = write(put_fd, data, len);
            if (ret < 0 || (size_t)ret != len) {
                LOGE("[webdav] write %s failed: %s\n", fs_path.c_str(), strerror(errno));
                return respondStatus(S500);
            }
        }
        if ((flag & HTTP_REQ_COMPLETED) == 0) {
            return;
        }
        close(put_fd);
        respondStatus(put_existed ? S204 : S201);
    }

    void DELETE(const CGI_Header*) override {
        if(!req->has("X-Authorized", "1")) {
            return Unauthorized();
        }
        if (fs_path.empty()) {
            return respondStatus(S403);
        }
        std::error_code ec;
        if (!fs::exists(fs_path)) {
            return respondStatus(S404);
        }
        fs::remove_all(fs_path, ec);
        if (ec) {
            LOGE("[webdav] delete %s failed: %s\n", fs_path.c_str(), ec.message().c_str());
            return respondStatus(S500);
        }
        respondStatus(S204);
    }

    void PROPFIND() {
        if (fs_path.empty()) {
            return respondStatus(S403);
        }
        if((flag & HTTP_REQ_COMPLETED) == 0){
            //discard all body
            return;
        }
        struct stat st{};
        if (!statOrRespond(st)) {
            return;
        }
        int depth = parse_depth(req.get());
        if (depth < 0) {
            depth = 1;
        }

        xmlNsPtr ns = nullptr;
        auto doc = createDavDoc("D:multistatus", ns);
        xmlNodePtr root = doc ? xmlDocGetRootElement(doc.get()) : nullptr;
        if (root == nullptr) {
            return respondStatus(S500);
        }
        addPropResponse(root, ns, href_path, st);

        if (S_ISDIR(st.st_mode) && depth != 0) {
            DIR* dir = opendir(fs_path.c_str());
            if (dir == nullptr) {
                return respondStatus(S500);
            }
            struct dirent* ent = nullptr;
            while ((ent = readdir(dir)) != nullptr) {
                if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) {
                    continue;
                }
                string child_name = ent->d_name;
                string child_fs = pathjoin(fs_path, child_name);
                struct stat child_st{};
                if (lstat(child_fs.c_str(), &child_st) < 0) {
                    continue;
                }
                addPropResponse(root, ns, pathjoin(href_path, child_name), child_st);
            }
            closedir(dir);
        }
        sendXmlResponse(S207, std::move(doc));
    }

    void PROPPATCH() {
        if (fs_path.empty()) {
            return respondStatus(S403);
        }
        struct stat st{};
        if (!statOrRespond(st)) {
            return;
        }
        xmlNsPtr ns = nullptr;
        auto doc = createDavDoc("D:multistatus", ns);
        xmlNodePtr root = doc ? xmlDocGetRootElement(doc.get()) : nullptr;
        if (root == nullptr) {
            return respondStatus(S500);
        }
        addPropResponse(root, ns, href_path, st);
        sendXmlResponse(S207, std::move(doc));
    }

    void MKCOL(const CGI_Header*) {
        if (fs_path.empty()) {
            return respondStatus(S403);
        }
        fs::path target(fs_path);
        fs::path parent = target.parent_path();
        if (!parent.empty() && !fs::exists(parent)) {
            return respondStatus(S409);
        }
        if (fs::exists(target)) {
            return respondStatus(S405);
        }
        std::error_code ec;
        fs::create_directory(target, ec);
        if (ec) {
            return respondStatus(S500);
        }
        respondStatus(S201);
    }

    void COPY(const CGI_Header*) {
        handleCopyMove(false);
    }

    void MOVE(const CGI_Header*) {
        handleCopyMove(true);
    }

    void LOCK() {
        if (fs_path.empty()) {
            return respondStatus(S403);
        }
        static const char token[] = "opaquelocktoken:dummy-token";
        xmlNsPtr ns = nullptr;
        auto doc = createDavDoc("D:prop", ns);
        xmlNodePtr prop = doc ? xmlDocGetRootElement(doc.get()) : nullptr;
        if (prop == nullptr) {
            return respondStatus(S500);
        }
        xmlNodePtr lockdiscovery = xmlNewChild(prop, ns, BAD_CAST "lockdiscovery", nullptr);
        xmlNodePtr activelock = xmlNewChild(lockdiscovery, ns, BAD_CAST "activelock", nullptr);
        xmlNodePtr locktype = xmlNewChild(activelock, ns, BAD_CAST "locktype", nullptr);
        xmlNewChild(locktype, ns, BAD_CAST "write", nullptr);
        xmlNodePtr lockscope = xmlNewChild(activelock, ns, BAD_CAST "lockscope", nullptr);
        xmlNewChild(lockscope, ns, BAD_CAST "exclusive", nullptr);
        xmlNewChild(activelock, ns, BAD_CAST "depth", BAD_CAST "infinity");
        xmlNodePtr owner = xmlNewChild(activelock, ns, BAD_CAST "owner", nullptr);
        const char* owner_hdr = req->get("Owner");
        const char* ua = req->get("User-Agent");
        const char* owner_val = owner_hdr ? owner_hdr : (ua ? ua : "anonymous");
        xmlNewChild(owner, ns, BAD_CAST "href", BAD_CAST owner_val);
        xmlNewChild(activelock, ns, BAD_CAST "timeout", BAD_CAST "Second-1800");
        xmlNodePtr locktoken = xmlNewChild(activelock, ns, BAD_CAST "locktoken", nullptr);
        xmlNewChild(locktoken, ns, BAD_CAST "href", BAD_CAST token);

        const char* lock_token = token;
        sendXmlResponse(S200, std::move(doc), [lock_token](HttpResHeader* res) { res->set("Lock-Token", lock_token); });
    }

    void UNLOCK() {
        respondStatus(S204);
    }

    void OPTIONS() {
        auto res = HttpResHeader::create(S200, sizeof(S200), req->request_id);
        res->set("Allow", "OPTIONS, GET, HEAD, PUT, DELETE, MKCOL, COPY, MOVE, PROPFIND, PROPPATCH, LOCK, UNLOCK");
        res->set("DAV", "1, 2");
        Response(res);
        Finish();
    }

    void CustomMethod(const std::string& method, const CGI_Header* header) override {
        if(!req->has("X-Authorized", "1")) {
            return Unauthorized();
        }
        if (method == "OPTIONS") {
            return OPTIONS();
        }
        if (method == "PROPFIND") {
            return PROPFIND();
        }
        if (method == "PROPPATCH") {
            return PROPPATCH();
        }
        if (method == "MKCOL") {
            return MKCOL(header);
        }
        if (method == "COPY") {
            return COPY(header);
        }
        if (method == "MOVE") {
            return MOVE(header);
        }
        if (method == "LOCK") {
            return LOCK();
        }
        if (method == "UNLOCK") {
            return UNLOCK();
        }
        NotImplemented();
    }
};

CGIMAIN(WebdavHandler);
