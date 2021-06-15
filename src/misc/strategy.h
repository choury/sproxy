#ifndef STRATEGY_H__
#define STRATEGY_H__

#ifdef  __cplusplus
extern "C" {
#endif
void addsecret(const char* secret);
bool checkauth(const char* ip, const char* token);
void reloadstrategy();
bool addstrategy(const char *host, const char* s, const char* ext);
bool delstrategy(const char *host);

#ifdef  __cplusplus
}
#endif

#ifdef __cplusplus
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

struct strategy getstrategy(const char *host);
const char* getstrategystring(Strategy s);


std::list<std::pair<std::string, strategy>> getallstrategy();
#endif //__cplusplus
#endif
