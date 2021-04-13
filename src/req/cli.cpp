#include "cli.h"
#include "prot/netio.h"
#include "misc/util.h"

#include "misc/strategy.h"
#include "misc/config.h"
#include "res/cgi.h"

Cli::Cli(int fd, const sockaddr_storage* addr): Requester(new StreamRWer(fd, addr, std::bind(&Cli::Error, this, _1, _2))) {
    rwer->SetReadCB(std::bind(&Cli::ReadHE, this, _1));
}

Cli::~Cli(){
}

void Cli::send(const char *data, size_t len) {
    rwer->buffer_insert(rwer->buffer_end(), write_block{p_memdup(data, len), len, 0});
}

void Cli::ReadHE(size_t len){
    const char *data = rwer->rdata();
    size_t consumed = 0;
    ssize_t ret = 0;
    while(true){
        ret = DefaultProc(data+consumed, len-consumed);
        if(ret > 0){
            consumed += ret;
            continue;
        }
        if(ret == 0){
            break;
        }
        LOGE("<cli> rpc error: %s\n", strerror(-ret));
        return deleteLater(PROTOCOL_ERR);
    }
    rwer->consume(data, consumed);
}

void Cli::Error(int ret, int code) {
    if(ret == SOCKET_ERR && code == 0){
        //eof
        deleteLater(ret);
        return;
    }
    LOGE("<cli> socket error: %d/%d\n", ret, code);
    deleteLater(ret);
}

void Cli::deleteLater(uint32_t errcode) {
    Requester::deleteLater(errcode);
}

void Cli::dump_stat(Dumper dp, void* param) {
    dp(param, "Cli %p, (%s)\n", this, getsrc());
    dp(param, "  rwer: rlength:%zu, rleft:%zu, wlength:%zu, stats:%d, event:%s\n",
       rwer->rlength(), rwer->rleft(), rwer->wlength(),
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
    }else{
        return std::string(getstrategystring(stra.s)) + " " + stra.ext;
    }
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
    if(checkauth(source.c_str())){
        return true;
    }
    if (strcmp(opt.auth_string, token.c_str()) != 0) {
        return false;
    }
    addauth(source.c_str());
    return true;
}