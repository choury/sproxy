#include "cli.h"
#include "prot/netio.h"
#include "misc/util.h"

#include "misc/strategy.h"
#include "misc/config.h"
#include "res/proxy2.h"
#ifdef WITH_QUIC
#include "res/proxy3.h"
#endif
#include "res/cgi.h"

Cli::Cli(int fd, const sockaddr_storage* addr):
        Requester(std::make_shared<StreamRWer>(fd, addr, std::bind(&Cli::Error, this, _1, _2)))
{
    rwer->SetReadCB(std::bind(&Cli::ReadHE, this, _1));
}

Cli::~Cli(){
}

void Cli::send(const char *data, size_t len) {
    rwer->buffer_insert(rwer->buffer_end(), Buffer{data, len});
}

void Cli::ReadHE(Buffer& bb){
    if(bb.len == 0){
        //eof
        deleteLater(NOERROR);
        return;
    }
    ssize_t ret = 0;
    while(bb.len > 0){
        ret = DefaultProc((const char*) bb.data(), bb.len);
        if(ret > 0){
            bb.trunc(ret);
            continue;
        }
        if(ret == 0){
            break;
        }
        LOGE("<cli> rpc error: %s\n", strerror(-ret));
        return deleteLater(PROTOCOL_ERR);
    }
}

void Cli::Error(int ret, int code) {
    LOGE("<cli> socket error: %d/%d\n", ret, code);
    deleteLater(ret);
}

void Cli::dump_stat(Dumper dp, void* param) {
    dp(param, "Cli %p, (%s)\n", this, getsrc());
    dp(param, "  rwer: rlength:%zu, wlength:%zu, stats:%d, event:%s\n",
       rwer->rlength(), rwer->wlength(),
       (int)rwer->getStats(), events_string[(int)rwer->getEvents()]);
}

bool Cli::AddStrategy(const std::string &host, const std::string &strategy, const std::string &ext) {
    LOG("%s [%s] %s %s %s\n", rwer->getPeer(), __func__, host.c_str(), strategy.c_str(), ext.c_str());
    return addstrategy(host.c_str(), strategy.c_str(), ext.c_str());
}

bool Cli::DelStrategy(const std::string &host) {
    LOG("%s [%s] %s\n", rwer->getPeer(), __func__, host.c_str());
    return delstrategy(host.c_str());
}

std::string Cli::TestStrategy(const std::string &host) {
    LOG("%s [%s] %s\n", rwer->getPeer(), __func__, host.c_str());
    auto stra = getstrategy(host.c_str());
    if(stra.ext.empty()){
        return getstrategystring(stra.s);
    }
    return std::string(getstrategystring(stra.s)) + " " + stra.ext;
}

std::vector<std::string> Cli::ListStrategy() {
    LOG("%s [%s]\n", rwer->getPeer(), __func__);
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
    LOG("%s [%s]\n", rwer->getPeer(), __func__);
    flushcgi();
}

void Cli::FlushDns() {
    LOG("%s [%s]\n", rwer->getPeer(), __func__);
    flushdns();
}

void Cli::FlushStrategy() {
    LOG("%s [%s]\n", rwer->getPeer(), __func__);
    reloadstrategy();
}

bool Cli::SetServer(const std::string &server) {
    LOG("%s [%s] %s\n", rwer->getPeer(), __func__, server.c_str());
    Destination proxy;
    if(loadproxy(server.c_str(), &proxy) == 0){
        memcpy(&opt.Server, &proxy, sizeof(proxy));
        proxy2 = nullptr;
#ifdef WITH_QUIC
        proxy3 = nullptr;
#endif
        return true;
    }
    return false;
}

std::string Cli::GetServer() {
    LOG("%s [%s]\n", rwer->getPeer(), __func__);
    return dumpDest(&opt.Server);
}

bool Cli::Login(const std::string &token, const std::string &source) {
    LOG("%s [%s] %s\n", rwer->getPeer(), __func__, source.c_str());
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

std::string Cli::GetStatus() {
    std::string ss;
    ::dump_stat(sstream_dumper, &ss);
    return ss;
}
