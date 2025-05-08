#include "cli.h"
#include "prot/netio.h"
#include "misc/util.h"

#include "misc/strategy.h"
#include "misc/config.h"
#include "misc/hook.h"
#include "prot/dns/resolver.h"
#include "res/cgi.h"

Cli::Cli(int fd, const sockaddr_storage* addr):
        Requester(std::make_shared<StreamRWer>(fd, addr, [this](int ret, int code){Error(ret, code);}))
{
    id = nextId();
    rwer->SetReadCB([this](Buffer&& bb){return ReadHE(bb);});
}

Cli::~Cli(){
}

bool Cli::send(const char *data, size_t len) {
    rwer->Send(Buffer{data, len, id});
    return true;
}

size_t Cli::ReadHE(const Buffer& bb) {
    if(bb.len == 0){
        //eof
        deleteLater(NOERROR);
        return 0;
    }
    ssize_t ret = 0;
    size_t left = bb.len;
    const char* data = (const char*)bb.data();
    while(left > 0){
        ret = DefaultProc(data, left);
        if(ret > 0){
            left -= ret;
            data += ret;
            continue;
        }
        if(ret == 0){
            break;
        }
        LOGE("(%s) <cli> rpc error: %s\n", dumpDest(rwer->getSrc()).c_str(), strerror(-ret));
        deleteLater(PROTOCOL_ERR);
        break;
    }
    return bb.len - left;
}

void Cli::Error(int ret, int code) {
    LOGE("(%s) <cli> socket error: %d/%d\n", dumpDest(rwer->getSrc()).c_str(), ret, code);
    deleteLater(ret);
}


bool Cli::AddStrategy(const std::string &host, const std::string &strategy, const std::string &ext) {
    LOG("%s [%s] %s %s %s\n", dumpDest(rwer->getSrc()).c_str(), __func__, host.c_str(), strategy.c_str(), ext.c_str());
    return addstrategy(host.c_str(), strategy.c_str(), ext.c_str());
}

bool Cli::DelStrategy(const std::string &host) {
    LOG("%s [%s] %s\n", dumpDest(rwer->getSrc()).c_str(), __func__, host.c_str());
    return delstrategy(host.c_str());
}

std::string Cli::TestStrategy(const std::string &host) {
    LOG("%s [%s] %s\n", dumpDest(rwer->getSrc()).c_str(), __func__, host.c_str());
    Destination dest;
    char path[URLLIMIT];
    spliturl(host.c_str(), &dest, path);
    auto stra = getstrategy(dest.hostname, path);
    if(stra.ext.empty()){
        return getstrategystring(stra.s);
    }
    return std::string(getstrategystring(stra.s)) + " " + stra.ext;
}

std::vector<std::string> Cli::DumpStrategy() {
    LOG("%s [%s]\n", dumpDest(rwer->getSrc()).c_str(), __func__);
    std::vector<std::string> lists;
    auto slist = getallstrategy();
    for (const auto &i: slist) {
        auto host = i.first;
        if (host.empty()) {
            host = "_";
        }
        lists.push_back(host + " " + getstrategystring(i.second.s) + " " + i.second.ext);
    }
    return lists;
}

void Cli::FlushCgi() {
    LOG("%s [%s]\n", dumpDest(rwer->getSrc()).c_str(), __func__);
    flushcgi();
}

void Cli::FlushDns() {
    LOG("%s [%s]\n", dumpDest(rwer->getSrc()).c_str(), __func__);
    flushdns();
}

void Cli::FlushStrategy() {
    LOG("%s [%s]\n", dumpDest(rwer->getSrc()).c_str(), __func__);
    reloadstrategy();
}

bool Cli::SetServer(const std::string &server) {
    LOG("%s [%s] %s\n", dumpDest(rwer->getSrc()).c_str(), __func__, server.c_str());
    Destination proxy;
    if(parseDest(server.c_str(), &proxy) == 0){
        memcpy(&opt.Server, &proxy, sizeof(proxy));
        return true;
    }
    return false;
}

std::string Cli::GetServer() {
    LOG("%s [%s]\n", dumpDest(rwer->getSrc()).c_str(), __func__);
    return dumpDest(opt.Server);
}

bool Cli::Login(const std::string &token, const std::string &source) {
    LOG("%s [%s] %s\n", dumpDest(rwer->getSrc()).c_str(), __func__, source.c_str());
    return checkauth(source.c_str(), token.c_str());
}

static void sstream_dumper(void* param, const char* fmt, ...) {
    std::string* ss = (std::string*)param;
    va_list ap;
    va_start(ap, fmt);

    int size = vsnprintf(nullptr, 0, fmt, ap) + 1; // Extra space for '\0'
    va_end(ap);

    auto buf = (char*)malloc(size);
    va_start(ap, fmt);
    vsnprintf(buf, size, fmt, ap);
    ss->append(std::string(buf, buf+size-1)); // We don't want the '\0' inside
    free(buf);
    va_end(ap);
}

std::string Cli::DumpStatus() {
    LOG("%s [%s]\n", dumpDest(rwer->getSrc()).c_str(), __func__);
    std::string ss;
    ::dump_stat(sstream_dumper, &ss);
    return ss;
}

std::string Cli::DumpDns() {
    LOG("%s [%s]\n", dumpDest(rwer->getSrc()).c_str(), __func__);
    std::string ss;
    ::dump_dns(sstream_dumper, &ss);
    return ss;
}

std::string Cli::DumpMemUsage() {
    LOG("%s [%s]\n", dumpDest(rwer->getSrc()).c_str(), __func__);
    std::string ss;
    ::dump_usage(sstream_dumper, &ss);
    return ss;
}

std::string Cli::DumpHooker() {
    LOG("%s [%s]\n", dumpDest(rwer->getSrc()).c_str(), __func__);
    std::string ss;
    hookManager.dump(sstream_dumper, &ss);
    return ss;
}

bool Cli::Debug(const std::string& module, bool enable) {
    LOG("%s [%s] %s %s\n", dumpDest(rwer->getSrc()).c_str(), __func__, enable?"enable":"disable", module.c_str());
    return debugon(module.c_str(), enable);
}

bool Cli::killCon(const std::string &address) {
    LOG("%s [%s] %s\n", dumpDest(rwer->getSrc()).c_str(), __func__, address.c_str());
    char *endptr;
    uint64_t num = strtoull(address.c_str(), &endptr, 16);
    if (*endptr != '\0') {
        return false;
    }
    return kill_server(reinterpret_cast<Server*>(num), CLI_KILLED);
}

bool Cli::HookerAdd(const std::string &hooker, const std::string &lib) {
    LOG("%s [%s] %s %s\n", dumpDest(rwer->getSrc()).c_str(), __func__, hooker.c_str(), lib.c_str());
    std::string msg;
    auto cb = std::make_shared<LibCallback>(lib, msg);
    if(!msg.empty()){
        LOGE("HookerAdd failed: %s\n", msg.c_str());
        return false;
    }
    hookManager.Register((const void*)std::stoull(hooker, nullptr, 16), cb);
    return true;
}

bool Cli::HookerDel(const std::string &hooker) {
    LOG("%s [%s] %s\n", dumpDest(rwer->getSrc()).c_str(), __func__, hooker.c_str());
    return hookManager.Unregister((const void*)std::stoull(hooker, nullptr, 16));
}

void Cli::dump_stat(Dumper dp, void* param) {
    dp(param, "Cli %p\n", this);
    rwer->dump_status(dp, param);
}

void Cli::dump_usage(Dumper dp, void *param) {
    dp(param, "Cli %p: %zd, rwer: %zd\n", this, sizeof(*this), rwer->mem_usage());
}
