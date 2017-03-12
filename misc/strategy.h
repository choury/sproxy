#ifndef STRATEGY_H__
#define STRATEGY_H__

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
const char* getstrategystring(const char *host);

void addauth(const char * ip);
bool checkauth(const char *ip);

#ifdef  __cplusplus
}
#endif

#endif
