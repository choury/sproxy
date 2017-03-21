#ifndef STRATEGY_H__
#define STRATEGY_H__

#include <map>

enum class Strategy{
    direct,
    proxy,
    local,
    block,
};

#ifdef  __cplusplus
extern "C" {
#endif


void loadsites();
bool addstrategy(const char *host, const char *strategy);
bool delstrategy(const char *host);
Strategy getstrategy(const char *host);
const char* getstrategystring(Strategy s);

void addauth(const char * ip);
bool checkauth(const char *ip);

#ifdef  __cplusplus
}
#endif

std::map<std::string, std::string> getallstrategy();

#endif
