#ifndef STRATEGY_H__
#define STRATEGY_H__

#include <string>
#include <list>

enum class Strategy{
    none,
    direct,
    forward,
    rewrite,
    proxy,
    local,
    block,
};

struct strategy{
    Strategy s;
    std::string ext;
};

void reloadstrategy();
bool addstrategy(const char *host, const char* s, const char* ext);
bool delstrategy(const char *host);
struct strategy getstrategy(const char *host);
const char* getstrategystring(Strategy s);

void addauth(const char * ip);
bool checkauth(const char *ip);

std::list<std::pair<std::string, strategy>> getallstrategy();

#endif
