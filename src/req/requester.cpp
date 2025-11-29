#include "requester.h"
#include "common/version.h"
#include "misc/config.h"

#include <sstream>

Requester::Requester(std::shared_ptr<RWer> rwer) {
    this->rwer = rwer;
}

std::string generateUA(const char* ua, const std::string& prog, uint64_t requestid) {
    std::stringstream UA;
    if(ua && ua[0]){
        UA << ua;
    } else if(!prog.empty()){
        UA << prog
           <<" (" << getDeviceInfo() << ")"
           <<" Sproxy/" << getVersion()
           <<" (Build " << getBuildTime() << ")";
#ifdef ANDROID_APP
        UA <<" App/" << appVersion;
#endif
    } else {
        UA <<"Sproxy/" << getVersion()
           <<" (" << getDeviceInfo() << ")"
           <<" (Build " << getBuildTime() << ")";
#ifdef ANDROID_APP
        UA <<" App/" << appVersion;
#endif
    }

    if (requestid != 0 && ua && strstr(ua, " SEQ/") == nullptr) {
        UA << " SEQ/" << requestid;
    }
    return UA.str();
}
