#include "base.h"
#include "misc/config.h"
#include "misc/strategy.h"

#include <set>
#include <stdarg.h>
#include <unistd.h>
#include <cxxabi.h>

static std::set<Server*> servers;

Server::Server(){
    servers.emplace(this);
}

Server::~Server() {
    servers.erase(this);
}

void Server::deleteLater(uint32_t) {
    if(rwer){
        cb->onClose([this](){
            assert(servers.count(this));
            this->df(this);
            delete this;
        });
        rwer->Close();
    }else{
        assert(servers.count(this));
        delete this;
    }
}

void releaseall() {
    auto serversCopy = servers;
    for(auto i: serversCopy){
        delete i;
    }
    servers.clear();
}

bool isalive(Server* s) {
    return servers.count(s);
}


bool kill_server(Server* s, uint32_t errcode) {
    if(isalive(s)){
        LOGE("kill server: %p\n", s);
        s->deleteLater(errcode);
        return true;
    }
    LOGE("failed to find server: %p to kill\n", s);
    return false;
}

extern void dump_job(Dumper dp, void* param);

void dump_stat(Dumper dp, void* param){
    dp(param, "======================================\n");
    dp(param, "Proxy server: %s, ipv6: %s\n", dumpDest(opt.Server).c_str(), opt.ipv6_enabled ? "enabled" : "disabled");
    dp(param, "--------------------------------------\n");
    for(auto i: servers){
        i->dump_stat(dp, param);
        dp(param, "--------------------------------------\n");
    }
    dump_job(dp, param);
    dp(param, "======================================\n");
}

void dump_usage(Dumper dp, void* param){
    dp(param, "======================================\n");
    for(auto i: servers){
        i->dump_usage(dp, param);
        dp(param, "--------------------------------------\n");
    }
    size_t strag_usage = 0;
    for(const auto& i : getallstrategy() ) {
        strag_usage += i.first.length() + sizeof(i.second);
    }
    dp(param, "strategy: %zd\n", strag_usage);
    dp(param, "======================================\n");
}


static void LogDump(void*, const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    VLOG(LOG_INFO, fmt, ap);
    va_end(ap);
}

void dump_stat(){
    dump_stat(LogDump, nullptr);
}

extern "C" void demangle_func(char* stack, int depth) {
#ifdef __linux__
    /*
     * ./src/sproxy(_ZN6Status7requestEP7HttpReqP9Requester+0xa92) [0x5574eb16f4b2]
     * 通过'('找到函数名，然后通过'+'定位结束位置
     */
    char* offset = nullptr;
    char* offset_pos = nullptr;
    for(char* p = stack; *p; p++){
        if(*p == '(') {
            offset = p;
        }
        if(*p == '+' && offset) {
            offset_pos = p;
        }
    }
    if(!offset || !offset_pos){
        LOGE(" [%d] %s \n", depth, stack);
        return;
    }
    // 临时从'+'处截断，得到一个\0结束的字符串
    *offset_pos = 0;
    size_t size;
    int status;
    char* demangled = abi::__cxa_demangle(offset+1, nullptr, &size, &status);
    // 恢复原状
    *offset_pos = '+';
    if(status){
        LOGE("[%d] %s \n", depth, stack);
        return;
    }
    //从开始位置，即'('，截断，用demangled的函数替换掉
    *offset = 0;
    LOGE("[%d] %s(%s%s\n", depth, stack, demangled, offset_pos);
    free(demangled);
#elif __APPLE__
    (void)depth;
    /*
     * 4   sproxy   0x000000010d6b5e77 _ZN6Status7requestEP7HttpReqP9Requester + 823
     * 查找第4个字段的开始和结束位置，作为函数名
     */
    char* begin_pos = nullptr;
    char* end_pos = nullptr;
    int field = 0;
    for(char* p = stack; *p; field++){
        if(field == 3){
            begin_pos = p;
        }
        while(*p != ' ' && *p){
            p++;
        }
        if(begin_pos){
            end_pos = p;
            break;
        }
        while(*p == ' '){
            p++;
        }
    }

    // 临时从后面的空格处截断，得到一个\0结束的字符串
    *end_pos = 0;
    size_t size;
    int status;
    char* demangled = abi::__cxa_demangle(begin_pos, nullptr, &size, &status);
    // 恢复原状
    *end_pos = ' ';
    if(status){
        LOGE("%s \n", stack);
        return;
    }
    //从开始位置截断，用demangled的函数替换掉
    *begin_pos = 0;
    LOGE("%s%s%s\n", stack, demangled, end_pos);
    free(demangled);
#else
    LOGE("[%d] %s \n", depth, stack);
#endif
}

