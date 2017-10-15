#ifndef STRATEGY_H__
#define STRATEGY_H__

#include <tuple>
#include <list>

enum class Strategy{
    direct,
    forward,
    proxy,
    local,
    block,
    none,
};

#ifdef  __cplusplus
extern "C" {
#endif


void reloadstrategy();
bool addstrategy(const char *host, const char *strategy, std::string ext);
bool delstrategy(const char *host);
Strategy getstrategy(const char *host, std::string& ext);
const char* getstrategystring(Strategy s);

void addauth(const char * ip);
bool checkauth(const char *ip);

#ifdef  __cplusplus
}
#endif

std::list<std::tuple<std::string, std::string, std::string>> getallstrategy();

#endif
