#ifndef STRATEGY_H__
#define STRATEGY_H__

#define GEN_TIP  "GENERATED"
#define NO_MITM  "NOMITM"

#ifdef  __cplusplus
extern "C" {
#endif
void addsecret(const char* secret);
bool decodeauth(const char* auth, struct Credit* credit);
bool checksecret(const char* auth, const struct Credit* credit);
bool checktoken(const char* token);
void reloadstrategy();
bool addstrategy(const char *host, const char* s, const char* ext);
bool delstrategy(const char *host);

#ifdef  __cplusplus
}
#endif

#ifdef __cplusplus
#include <string>
#include <list>
#include <memory>
enum class Strategy{
    none,
    direct,
    forward,
    rewrite,
    proxy,
    local,
    block,
    alias,
};

struct strategy{
    Strategy s;
    std::string ext;
};

class HttpReqHeader;
struct strategy getstrategy(const char* host, const char* path = "");
bool mayBeBlocked(const char* host);
const char* getstrategystring(Strategy s);
std::string gen_token();
bool checkauth(const char* ip, std::shared_ptr<const HttpReqHeader> req);
bool getalias(const std::string& name, std::string& target);


std::list<std::pair<std::string, strategy>> getallstrategy();
#endif //__cplusplus
#endif
